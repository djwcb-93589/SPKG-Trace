from __future__ import annotations

import re

from spkg_workflow.contracts import ParsedLogRecord

from .base import ExtractorContext, FamilyExtraction
from .common import set_aliases


DNS_PREFIX = re.compile(r"^dnsmasq\[(?P<pid>\d+)\]:\s*(?P<body>.*)$")
DNS_FAILURES = {"NXDOMAIN", "REFUSED", "SERVFAIL", "FORMERR", "NOTIMP"}


class DnsExtractor:
    family = "dns"

    def extract(
        self, record: ParsedLogRecord, context: ExtractorContext
    ) -> FamilyExtraction:
        result = FamilyExtraction()
        match = DNS_PREFIX.match(record.content.strip())
        if not match:
            result.warnings.append("dns_prefix_not_recognized")
            return result

        pid = match.group("pid")
        body = match.group("body")
        values = result.source_values
        canonical = result.canonical_values
        set_aliases(values, pid, ("pid", "dnsmasq_pid", "process_id"))
        canonical.update({"program": context.default_program or "dnsmasq", "pid": pid})
        if context.default_host:
            canonical["host"] = context.default_host

        reply = re.match(r"^reply\s+(?P<qname>\S+)\s+is\s+(?P<answer>.+)$", body)
        forwarded = re.match(
            r"^forwarded\s+(?P<qname>\S+)\s+to\s+(?P<dst>\S+)$", body
        )
        query = re.match(
            r"^query\[(?P<qtype>[^\]]+)\]\s+(?P<qname>\S+)\s+from\s+(?P<src>\S+)$",
            body,
        )
        cached = re.match(r"^cached\s+(?P<qname>\S+)\s+is\s+(?P<answer>.+)$", body)
        refused = re.match(
            r"^nameserver\s+(?P<dst>\S+)\s+refused to do a recursive query$", body
        )
        file_error = re.match(
            r"^failed to access\s+(?P<path>\S+):\s*(?P<error>.+)$", body
        )

        if reply:
            qname, answer = reply.group("qname", "answer")
            set_aliases(values, qname, ("qname", "domain", "query_domain"))
            set_aliases(values, answer, ("reply_ip", "answer_kind"))
            canonical.update(
                {"event_type": "reply", "qname": qname, "answer_kind": answer}
            )
            status = answer.upper()
            if status in DNS_FAILURES or status.startswith("NODATA"):
                canonical.update({"status_code": answer, "outcome": "failure"})
            else:
                canonical["outcome"] = "success"
        elif forwarded:
            qname, dst = forwarded.group("qname", "dst")
            set_aliases(values, qname, ("qname", "domain", "forwarded_query"))
            set_aliases(
                values,
                dst,
                ("dst_ip", "destination_server", "forward_server", "nameserver_ip"),
            )
            canonical.update(
                {
                    "event_type": "forwarded",
                    "qname": qname,
                    "dst_ip": dst,
                    "response_source": "upstream",
                }
            )
        elif query:
            qtype, qname, src = query.group("qtype", "qname", "src")
            set_aliases(values, qtype, ("qtype", "query_type", "record_type"))
            set_aliases(values, qname, ("qname", "domain", "query_domain"))
            set_aliases(values, src, ("src_ip", "source_ip", "client_ip"))
            canonical.update(
                {
                    "event_type": "query",
                    "qtype": qtype,
                    "qname": qname,
                    "src_ip": src,
                }
            )
        elif cached:
            qname, answer = cached.group("qname", "answer")
            set_aliases(values, qname, ("qname", "domain", "query_domain"))
            set_aliases(values, answer, ("record_type", "qtype", "cached_value"))
            canonical.update(
                {
                    "event_type": "cached",
                    "qname": qname,
                    "qtype": answer,
                    "response_source": "cache",
                }
            )
            status = answer.upper()
            if status in DNS_FAILURES or status.startswith("NODATA"):
                canonical.update({"status_code": answer, "outcome": "failure"})
            else:
                canonical["outcome"] = "success"
        elif refused:
            dst = refused.group("dst")
            set_aliases(values, dst, ("dst_ip", "nameserver_ip", "destination_server"))
            canonical.update(
                {
                    "event_type": "nameserver_error",
                    "dst_ip": dst,
                    "status_code": "REFUSED",
                    "response_source": "upstream",
                    "outcome": "failure",
                }
            )
        elif file_error:
            path, error = file_error.group("path", "error")
            set_aliases(values, path, ("file_path",))
            set_aliases(values, error, ("error_message",))
            canonical.update(
                {
                    "event_type": "file_access_error",
                    "status_code": "FILE_ACCESS_ERROR",
                    "outcome": "failure",
                }
            )
        else:
            result.warnings.append("dns_event_not_recognized")
        return result
