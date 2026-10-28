from __future__ import annotations

from collections import defaultdict
import hashlib
import random
from typing import Iterable

from spkg_workflow.contracts import ContractError, ParsedLogRecord, TemplateRecord


def template_id_for(dataset_id: str, regex_pattern: str) -> str:
    identity = "\x00".join((dataset_id, regex_pattern))
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"tpl_{digest}"


def template_id_for_record(record: ParsedLogRecord) -> str:
    return template_id_for(record.dataset_id, record.regex_pattern)


def _sample_indices(
    count: int, sample_size: int, *, seed_material: str
) -> tuple[int, ...]:
    if sample_size <= 0:
        raise ContractError("sample_size must be greater than zero")
    if count <= sample_size:
        return tuple(range(count))

    seed = int.from_bytes(
        hashlib.sha256(seed_material.encode("utf-8")).digest()[:8], "big"
    )
    generator = random.Random(seed)
    # Preserve the first occurrence for easy source inspection and sample the rest.
    selected = {0}
    selected.update(generator.sample(range(1, count), sample_size - 1))
    return tuple(sorted(selected))


def build_template_catalog(
    records: Iterable[ParsedLogRecord],
    *,
    sample_size: int = 3,
    sample_seed: int = 42,
) -> tuple[TemplateRecord, ...]:
    grouped: dict[tuple[str, str], list[ParsedLogRecord]] = defaultdict(list)
    for record in records:
        if not record.regex_pattern.strip():
            raise ContractError(
                f"Parsed log {record.dataset_id}:{record.line_id} has no regex pattern"
            )
        grouped[(record.dataset_id, record.regex_pattern)].append(record)

    templates: list[TemplateRecord] = []
    for (dataset_id, regex_pattern), group in grouped.items():
        ordered = sorted(group, key=lambda record: record.line_id)
        template_id = template_id_for(dataset_id, regex_pattern)
        indices = _sample_indices(
            len(ordered),
            sample_size,
            seed_material=f"{sample_seed}\x00{template_id}",
        )
        templates.append(
            TemplateRecord(
                dataset_id=dataset_id,
                template_id=template_id,
                event_id=ordered[0].event_id,
                regex_template=ordered[0].regex_template,
                regex_pattern=regex_pattern,
                occurrence_count=len(ordered),
                event_ids=tuple(sorted({record.event_id for record in ordered})),
                sample_line_ids=tuple(ordered[index].line_id for index in indices),
                samples=tuple(ordered[index].content for index in indices),
            )
        )

    return tuple(
        sorted(
            templates,
            key=lambda item: (item.dataset_id, item.template_id),
        )
    )
