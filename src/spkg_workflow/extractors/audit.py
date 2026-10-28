from __future__ import annotations

import re

from spkg_workflow.contracts import ParsedLogRecord

from .base import ExtractorContext, FamilyExtraction
from .common import extract_key_values, normalize_outcome, set_aliases


AUDIT_TYPE = re.compile(r"(?:^|\s)type=(?P<type>[^:\s]+):?")
AUDIT_TIMESTAMP = re.compile(r"^audit\((?P<event>[^)]+)\)$")


class AuditExtractor:
    family = "audit"

    def extract(
        self, record: ParsedLogRecord, context: ExtractorContext
    ) -> FamilyExtraction:
        result = FamilyExtraction()
        values = extract_key_values(record.content)
        event_match = AUDIT_TYPE.search(record.content)
        event_type = event_match.group("type") if event_match else values.get("type", "")
        values["type"] = event_type.rstrip(":")

        # Preserve common spelling variants emitted by field-semantic discovery.
        if "old_auid" in values:
            values.setdefault("old_auid", values["old_auid"])
        if "old_ses" in values:
            values.setdefault("old_ses", values["old_ses"])
        set_aliases(values, values.get("acct", ""), ("user", "username"))
        set_aliases(values, values.get("addr", ""), ("src_ip", "source_ip"))
        set_aliases(values, values.get("hostname", ""), ("src_hostname",))
        set_aliases(values, values.get("ses", ""), ("session_id",))
        set_aliases(values, values.get("exe", ""), ("process_exe",))
        set_aliases(values, values.get("comm", ""), ("process_name",))
        set_aliases(values, values.get("proctitle", ""), ("process_title",))
        set_aliases(values, values.get("cmd", ""), ("command",))
        result.source_values.update(values)

        outcome_source = values.get("res") or values.get("success") or ""
        canonical = result.canonical_values
        canonical.update(
            {
                "event_type": event_type,
                "user": values.get("acct") or values.get("id") or "",
                "auid": values.get("auid", ""),
                "uid": values.get("uid", ""),
                "session_id": values.get("ses", ""),
                "tty": values.get("tty", ""),
                "terminal": values.get("terminal", ""),
                "src_ip": values.get("addr", ""),
                "src_hostname": values.get("hostname", ""),
                "pid": values.get("pid", ""),
                "ppid": values.get("ppid", ""),
                "process_exe": values.get("exe") or values.get("name") or "",
                "process_name": values.get("comm", ""),
                "process_title": values.get("proctitle", ""),
                "command": values.get("cmd", ""),
                "cwd": values.get("cwd", ""),
                "syscall": values.get("syscall", ""),
                "outcome": normalize_outcome(outcome_source),
            }
        )
        timestamp_match = AUDIT_TIMESTAMP.match(record.timestamp.strip())
        if timestamp_match:
            canonical["event_id"] = timestamp_match.group("event")
        if context.default_host:
            canonical["host"] = context.default_host
        if not event_type:
            result.warnings.append("audit_type_not_found")
        return result
