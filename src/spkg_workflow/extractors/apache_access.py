from __future__ import annotations

import re

from spkg_workflow.contracts import ParsedLogRecord

from .base import ExtractorContext, FamilyExtraction
from .common import set_aliases


ACCESS_LINE = re.compile(
    r'^(?P<src_ip>\S+)\s+(?P<ident>\S+)\s+(?P<authuser>\S+)\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\S+)\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"$'
)
REQUEST_LINE = re.compile(r"^(?P<method>\S+)\s+(?P<target>\S+)\s+(?P<protocol>\S+)$")


def _split_target(target: str) -> tuple[str, str, str]:
    if not target or target == "-":
        return "", "", ""
    if "?" in target:
        path, query = target.split("?", 1)
        return target, path, query
    return target, target, ""


def _outcome(status: str) -> str:
    try:
        code = int(status)
    except ValueError:
        return "unknown" if status else ""
    if 200 <= code < 400:
        return "success"
    if 400 <= code < 600:
        return "failure"
    return "unknown"


class ApacheAccessExtractor:
    family = "apache_access"

    def extract(
        self, record: ParsedLogRecord, context: ExtractorContext
    ) -> FamilyExtraction:
        result = FamilyExtraction()
        match = ACCESS_LINE.match(record.content.strip())
        if not match:
            result.warnings.append("apache_access_line_not_recognized")
            return result
        data = match.groupdict()
        user = "" if data["authuser"] == "-" else data["authuser"]
        referer = "" if data["referer"] == "-" else data["referer"]
        user_agent = "" if data["user_agent"] == "-" else data["user_agent"]
        method = request_uri = request_path = query = version = ""
        if data["request"] != "-":
            request = REQUEST_LINE.match(data["request"])
            if request:
                method = request.group("method")
                request_uri, request_path, query = _split_target(request.group("target"))
                version = request.group("protocol")
                if version and not version.startswith("HTTP/"):
                    version = f"HTTP/{version}"

        values = result.source_values
        set_aliases(values, data["src_ip"], ("src_ip", "client_ip"))
        set_aliases(values, method, ("http_method", "request_method"))
        set_aliases(values, request_uri, ("request_uri",))
        set_aliases(values, request_path, ("request_path", "http_path"))
        set_aliases(values, query, ("query_string", "request_query", "http_query"))
        set_aliases(values, version, ("http_version",))
        set_aliases(values, data["status"], ("status_code",))
        set_aliases(values, data["size"], ("response_size", "bytes_sent"))
        set_aliases(values, referer, ("referer",))
        set_aliases(values, user_agent, ("user_agent",))
        set_aliases(values, user, ("user",))

        event_type = (
            "request_timeout"
            if data["request"] == "-" and data["status"] == "408"
            else "http_request"
        )
        result.canonical_values.update(
            {
                "host": context.default_host,
                "program": context.default_program or "apache",
                "event_type": event_type,
                "event_action": method,
                "user": user,
                "src_ip": data["src_ip"],
                "object_name": request_path or request_uri,
                "status_code": data["status"],
                "outcome": _outcome(data["status"]),
                "referer": referer,
                "user_agent": user_agent,
                "http_version": version,
                "bytes_sent": data["size"],
            }
        )
        return result
