from __future__ import annotations

from collections import defaultdict, deque
import csv
from dataclasses import dataclass
from pathlib import Path
import random
import re
from typing import Any, Iterable

from spkg_workflow.config import WorkflowSettings
from spkg_workflow.contracts import ParsedLogRecord, RawLogRecord
from spkg_workflow.providers import OpenAICompatibleClient

from .client_adapter import LibreLogProviderAdapter
from .vendor.grouping import LogParser as DrainLogParser
from .vendor.llama_parser import LogParser as LibreLogParser
from .vendor.regex_manager import RegexTemplateManager


MONTH_PATTERN = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
WEEKDAY_PATTERN = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"

LEADING_TIMESTAMP_PATTERNS = (
    re.compile(
        rf"^(?P<timestamp>\[{WEEKDAY_PATTERN}\s+{MONTH_PATTERN}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?\s+\d{{4}}\])\s*"
    ),
    re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z| ?[+-]\d{2}:?\d{2})?)\s*"
    ),
    re.compile(
        rf"^(?P<timestamp>{MONTH_PATTERN}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}})\s+"
    ),
)

INLINE_TIMESTAMP_PATTERNS: tuple[dict[str, Any], ...] = (
    {
        "pattern": re.compile(
            rf"\s*(?P<timestamp>\[\d{{1,2}}/{MONTH_PATTERN}/\d{{4}}:\d{{2}}:\d{{2}}:\d{{2}}\s+[+-]\d{{4}}\])\s*"
        ),
        "replacement": " ",
    },
    {
        "pattern": re.compile(
            r"(?P<prefix>\bmsg=)audit\((?P<timestamp>\d+(?:\.\d+)?:\d+)\)(?P<suffix>:)"
        ),
        "replacement": r"\g<prefix>audit\g<suffix>",
        "extract_wrapper": ("audit(", ")"),
    },
)


class LibreLogError(RuntimeError):
    """Raised when the pinned LibreLog core cannot produce traceable output."""


@dataclass(frozen=True, slots=True)
class LibreLogOptions:
    regex_sample: int = 3
    similarity: str = "jaccard"
    self_reflection: bool = True
    max_tokens: int = 1024
    depth: int = 4
    similarity_threshold: float = 0.5
    masks: tuple[str, ...] = ()
    random_seed: int = 42

    @classmethod
    def from_settings(cls, settings: WorkflowSettings) -> "LibreLogOptions":
        raw = settings.raw.get("librelog") or {}
        grouping = raw.get("grouping") or {}
        project = settings.raw.get("project") or {}
        return cls(
            regex_sample=int(project.get("sample_size", 3)),
            similarity=str(raw.get("similarity", "jaccard")),
            self_reflection=bool(raw.get("self_reflection", True)),
            max_tokens=int(raw.get("max_tokens", 1024)),
            depth=int(grouping.get("depth", 4)),
            similarity_threshold=float(grouping.get("similarity_threshold", 0.5)),
            masks=tuple(str(item) for item in grouping.get("masks", [])),
            random_seed=int(project.get("sample_seed", 42)),
        )


@dataclass(frozen=True, slots=True)
class LibreLogRun:
    raw_records: tuple[RawLogRecord, ...]
    parsed_records: tuple[ParsedLogRecord, ...]


@dataclass(frozen=True, slots=True)
class _PreprocessedRow:
    raw: RawLogRecord
    timestamp: str
    content: str


def normalize_preprocessed_content(content: str) -> str:
    return re.sub(r"\s{2,}", " ", content).strip()


def extract_timestamp_and_content(log_line: str) -> tuple[str, str]:
    """Apply the timestamp rules from the selected original evaluator."""
    content = log_line.strip()
    for pattern in LEADING_TIMESTAMP_PATTERNS:
        match = pattern.match(content)
        if match:
            timestamp = match.group("timestamp")
            stripped = normalize_preprocessed_content(content[match.end() :])
            return timestamp, stripped or content

    for item in INLINE_TIMESTAMP_PATTERNS:
        match = item["pattern"].search(content)
        if not match:
            continue
        timestamp = match.group("timestamp")
        wrapper = item.get("extract_wrapper")
        if wrapper:
            timestamp = f"{wrapper[0]}{timestamp}{wrapper[1]}"
        stripped = item["pattern"].sub(item["replacement"], content, count=1)
        stripped = normalize_preprocessed_content(stripped)
        return timestamp, stripped or content
    return "", content


def read_raw_log(path: str | Path, dataset_id: str) -> tuple[RawLogRecord, ...]:
    source = Path(path).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"Raw log file does not exist: {source}")

    records: list[RawLogRecord] = []
    with source.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            content = line.rstrip("\r\n")
            if not content.strip():
                continue
            records.append(
                RawLogRecord(
                    dataset_id=dataset_id,
                    line_id=len(records) + 1,
                    original_content=content,
                    source_path=str(source),
                )
            )
    if not records:
        raise LibreLogError(f"Raw log file contains no non-empty lines: {source}")
    return tuple(records)


def _preprocess(records: Iterable[RawLogRecord]) -> tuple[_PreprocessedRow, ...]:
    rows: list[_PreprocessedRow] = []
    for record in records:
        timestamp, content = extract_timestamp_and_content(record.original_content)
        rows.append(_PreprocessedRow(raw=record, timestamp=timestamp, content=content))
    return tuple(rows)


def _group_logs(grouped_logs: Iterable[Iterable[Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for content, event_id, event_template in grouped_logs:
        groups[str(event_id)].append(
            {
                "Content": str(content),
                "EventId": str(event_id),
                "EventTemplate": str(event_template),
            }
        )
    return dict(
        sorted(
            groups.items(),
            key=lambda item: len(item[1][0]["Content"].split()),
        )
    )


def regex_pattern_to_template(regex_pattern: str) -> str:
    """Convert LibreLog's executable pattern to its human-readable template."""
    text = str(regex_pattern or "").strip()
    if not text:
        return ""
    if text.startswith("^"):
        text = text[1:]
    if text.endswith("$"):
        text = text[:-1]

    chars: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            if index + 1 < len(text):
                next_char = text[index + 1]
                chars.append(" " if next_char == " " else next_char)
                index += 2
                continue
            chars.append(char)
            index += 1
            continue
        if char == "(":
            depth = 1
            index += 1
            escaped = False
            while index < len(text) and depth > 0:
                current = text[index]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == "(":
                    depth += 1
                elif current == ")":
                    depth -= 1
                index += 1
            chars.append("<*>")
            continue
        chars.append(char)
        index += 1

    cleaned = "".join(chars)
    cleaned = re.sub(r"<\*>\?", "<*>", cleaned)
    cleaned = re.sub(r"\.\*\??", "<*>", cleaned)
    return re.sub(r"\s{2,}", " ", cleaned).strip()


def parse_log_file(
    path: str | Path,
    *,
    dataset_id: str,
    settings: WorkflowSettings,
    options: LibreLogOptions | None = None,
    client: OpenAICompatibleClient | None = None,
) -> LibreLogRun:
    """Run the pinned original LibreLog core for one raw log file."""
    selected_options = options or LibreLogOptions.from_settings(settings)
    random.seed(selected_options.random_seed)
    raw_records = read_raw_log(path, dataset_id)
    rows = _preprocess(raw_records)
    contents = [row.content for row in rows]

    drain = DrainLogParser(
        rex=list(selected_options.masks),
        depth=selected_options.depth,
        st=selected_options.similarity_threshold,
    )
    grouped_logs = drain.parse(contents)
    groups = _group_logs(grouped_logs)

    provider = LibreLogProviderAdapter(client or OpenAICompatibleClient(settings.provider))
    manager = RegexTemplateManager()
    parser = LibreLogParser(
        pipeline=provider,
        regex_manager1=manager,
        model=settings.provider.models["librelog"],
        regex_sample=selected_options.regex_sample,
        similarity=selected_options.similarity,
        do_self_reflection="True" if selected_options.self_reflection else "False",
        max_new_tokens=selected_options.max_tokens,
    )

    parsed_results: list[tuple[Any, Any, Any]] = []
    for group in groups.values():
        group_contents = [item["Content"] for item in group]
        parsed_results.extend(parser.parse(group, group_contents))

    source_queues: dict[str, deque[_PreprocessedRow]] = defaultdict(deque)
    for row in rows:
        source_queues[row.content].append(row)

    parsed_records: list[ParsedLogRecord] = []
    for content, event_id, regex_pattern in parsed_results:
        normalized_content = str(content)
        if not source_queues[normalized_content]:
            raise LibreLogError(
                "LibreLog emitted a row that cannot be traced to its input content"
            )
        row = source_queues[normalized_content].popleft()
        parsed_records.append(
            ParsedLogRecord(
                dataset_id=dataset_id,
                line_id=row.raw.line_id,
                timestamp=row.timestamp,
                content=row.content,
                original_content=row.raw.original_content,
                event_id=str(event_id),
                regex_template=regex_pattern_to_template(str(regex_pattern)),
                regex_pattern=str(regex_pattern),
                source_path=row.raw.source_path,
            )
        )

    missing_line_ids = [
        row.raw.line_id for queue in source_queues.values() for row in queue
    ]
    if missing_line_ids:
        preview = ", ".join(str(item) for item in missing_line_ids[:10])
        raise LibreLogError(
            f"LibreLog did not return {len(missing_line_ids)} input rows; first IDs: {preview}"
        )
    return LibreLogRun(raw_records=raw_records, parsed_records=tuple(parsed_records))


def write_compatibility_csv(
    path: str | Path, records: Iterable[ParsedLogRecord]
) -> int:
    """Write the seven-column CSV used by the current project's downstream data."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "LineId",
                "Timestamp",
                "Content",
                "OriginalContent",
                "EventId",
                "RegexTemplate",
                "RegexPattern",
            ]
        )
        for record in records:
            writer.writerow(
                [
                    record.line_id,
                    record.timestamp,
                    record.content,
                    record.original_content,
                    record.event_id,
                    record.regex_template,
                    record.regex_pattern,
                ]
            )
            count += 1
    return count


def read_compatibility_csv(
    path: str | Path, *, dataset_id: str, source_path: str = ""
) -> tuple[ParsedLogRecord, ...]:
    source = Path(path)
    records: list[ParsedLogRecord] = []
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "LineId",
            "Timestamp",
            "Content",
            "OriginalContent",
            "EventId",
            "RegexTemplate",
            "RegexPattern",
        }
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise LibreLogError(
                f"LibreLog CSV is missing columns: {', '.join(sorted(missing))}"
            )
        for row in reader:
            records.append(
                ParsedLogRecord(
                    dataset_id=dataset_id,
                    line_id=int(row["LineId"]),
                    timestamp=row["Timestamp"],
                    content=row["Content"],
                    original_content=row["OriginalContent"],
                    event_id=row["EventId"],
                    regex_template=row["RegexTemplate"],
                    regex_pattern=row["RegexPattern"],
                    source_path=source_path or str(source.resolve()),
                )
            )
    return tuple(records)
