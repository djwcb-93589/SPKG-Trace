from __future__ import annotations

import re

from spkg_workflow.contracts import ParsedLogRecord

from .base import ExtractorContext, FamilyExtraction
from .common import set_aliases, split_endpoint


BASE_LINE = re.compile(
    r"^\[(?P<module>[^:\]]+):(?P<severity>[^\]]+)\]\s+"
    r"\[pid (?P<pid>\d+)\]\s+\[client (?P<client>[^\]]+)\]\s+(?P<message>.*)$"
)
AUTHZ = re.compile(r"^AH01630: client denied by server configuration: (?P<path>.+)$")
SCRIPT_NOT_FOUND = re.compile(r"^script (?P<script>.+?) not found or unable to stat$")
NEGOTIATION = re.compile(
    r"^AH00687: Negotiation: discovered file\(s\) matching request: (?P<path>.+?) "
    r"\(None could be negotiated\)\.?$"
)
AUTOINDEX = re.compile(
    r"^AH01276: Cannot serve directory (?P<directory>.+?): No matching DirectoryIndex "
    r"\((?P<index_list>.+?)\) found,? and server-generated directory index forbidden "
    r"by Options directive$"
)
PHP_REQUIRE = re.compile(
    r"^PHP Fatal error: require\(\): Failed opening required (?P<required>.+?) "
    r"\(include_path='(?P<include_path>.+?)'\) in (?P<source_file>.+?) on line (?P<line>\d+)$"
)
PHP_UNDEFINED_FUNCTION = re.compile(
    r"^PHP Fatal error: Uncaught Error: Call to undefined function (?P<func>[^()]+)\(\) "
    r"in (?P<error_file>.+?):(?P<error_line>\d+)\\nStack trace:\\n"
    r"(?P<stack_trace>#\d+ \{main\})\\n thrown in (?P<thrown_file>.+?) on line (?P<thrown_line>\d+)$"
)
PHP_UNDEFINED_CONSTANT = re.compile(
    r"^PHP Warning: Use of undefined constant (?P<constant>.+?) - assumed (?P<assumed>.+?) "
    r"\(this will throw an Error in a future version of PHP\) in "
    r"(?P<error_file>.+?) on line (?P<error_line>\d+)$"
)
PHP_SCANDIR = re.compile(
    r"^PHP Warning: scandir\(\): \(errno (?P<errno>\d+)\): No such file or directory "
    r"in (?P<file_path>.+?) on line (?P<line>\d+)$"
)
PHP_WARNING = re.compile(
    r"^PHP Warning: (?P<warning_message>.+?) in (?P<file_path>.+?) on line (?P<line>\d+)$"
)


def _unquote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text


def _split_referer(message: str) -> tuple[str, str]:
    for delimiter in (", referer: ", " referer: "):
        if delimiter in message:
            body, referer = message.rsplit(delimiter, 1)
            return body, referer.strip()
    return message, ""


class ApacheErrorExtractor:
    family = "apache_error"

    def extract(
        self, record: ParsedLogRecord, context: ExtractorContext
    ) -> FamilyExtraction:
        result = FamilyExtraction()
        base = BASE_LINE.match(record.content.strip())
        if not base:
            result.warnings.append("apache_error_line_not_recognized")
            return result

        module = base.group("module")
        severity = base.group("severity")
        pid = base.group("pid")
        client = base.group("client")
        src_ip, src_port = split_endpoint(client)
        message, referer = _split_referer(base.group("message"))
        values: dict[str, str] = {
            "module": module,
            "component": module,
            "program": module,
            "severity": severity,
            "log_level": severity,
            "pid": pid,
            "client": client,
            "src_ip": src_ip,
            "src_port": src_port,
            "referer": referer,
            "message": message,
            "log_component": f"{module}:{severity}",
        }
        if module == "php7":
            values["php7_error"] = f"{module}:{severity}"
            values["error_type"] = (
                "Fatal error" if message.startswith("PHP Fatal error:") else "Warning"
            )
        elif module == "negotiation":
            values["negotiation_error"] = severity
        elif module == "autoindex":
            values["autoindex_error"] = severity

        canonical: dict[str, str] = {
            "host": context.default_host,
            "program": module or context.default_program,
            "pid": pid,
            "src_ip": src_ip,
            "src_port": src_port,
            "referer": referer,
            "severity": severity,
            "outcome": "failure",
        }
        error_code_match = re.match(r"^(AH\d+):", message)
        if error_code_match:
            values["error_code"] = error_code_match.group(1)
            canonical["error_code"] = error_code_match.group(1)

        authz = AUTHZ.match(message)
        script = SCRIPT_NOT_FOUND.match(message)
        negotiation = NEGOTIATION.match(message)
        autoindex = AUTOINDEX.match(message)
        php_require = PHP_REQUIRE.match(message)
        php_function = PHP_UNDEFINED_FUNCTION.match(message)
        php_constant = PHP_UNDEFINED_CONSTANT.match(message)
        php_scandir = PHP_SCANDIR.match(message)
        php_warning = PHP_WARNING.match(message)

        if authz:
            path = authz.group("path").strip()
            set_aliases(values, path, ("requested_resource", "denied_path"))
            canonical.update(
                {
                    "event_type": "access_denied",
                    "event_action": "denied",
                    "object_name": path,
                    "status_code": "403",
                }
            )
        elif script:
            path = _unquote(script.group("script"))
            set_aliases(values, path, ("script", "requested_file"))
            canonical.update(
                {
                    "event_type": "script_not_found",
                    "event_action": "not_found",
                    "object_name": path,
                    "status_code": "404",
                }
            )
        elif negotiation:
            path = negotiation.group("path").strip()
            set_aliases(values, path, ("requested_file", "requested_resource"))
            canonical.update(
                {
                    "event_type": "negotiation_error",
                    "event_action": "failed",
                    "object_name": path,
                    "status_code": "406",
                }
            )
        elif autoindex:
            directory = autoindex.group("directory").strip()
            index_list = autoindex.group("index_list").strip()
            set_aliases(values, directory, ("directory",))
            set_aliases(values, index_list, ("directory_index", "directory_index_list"))
            canonical.update(
                {
                    "event_type": "directory_index_forbidden",
                    "event_action": "denied",
                    "object_name": directory,
                    "status_code": "403",
                }
            )
        elif php_require:
            data = php_require.groupdict()
            required = _unquote(data["required"])
            set_aliases(values, required, ("required_file",))
            set_aliases(values, data["include_path"], ("include_path",))
            set_aliases(values, data["source_file"], ("source_file", "error_file"))
            set_aliases(values, data["line"], ("line_number", "error_line"))
            set_aliases(values, "require()", ("error_function",))
            set_aliases(values, message, ("error_message",))
            canonical.update(
                {
                    "event_type": "php_error",
                    "event_action": "failed",
                    "object_name": required,
                    "status_code": "500",
                }
            )
        elif php_function:
            data = php_function.groupdict()
            set_aliases(values, data["func"], ("undefined_function",))
            set_aliases(values, data["error_file"], ("error_file",))
            set_aliases(values, data["error_line"], ("error_line",))
            set_aliases(values, data["stack_trace"], ("stack_trace",))
            set_aliases(values, data["thrown_file"], ("thrown_file",))
            set_aliases(values, data["thrown_line"], ("thrown_line",))
            set_aliases(values, message, ("error_message",))
            canonical.update(
                {
                    "event_type": "php_error",
                    "event_action": "failed",
                    "object_name": data["error_file"],
                    "status_code": "500",
                }
            )
        elif php_constant:
            data = php_constant.groupdict()
            set_aliases(values, data["constant"], ("undefined_constant",))
            set_aliases(values, data["assumed"], ("assumed_constant",))
            set_aliases(values, data["error_file"], ("error_file",))
            set_aliases(values, data["error_line"], ("error_line", "line_number"))
            canonical.update(
                {
                    "event_type": "php_error",
                    "event_action": "failed",
                    "object_name": data["error_file"],
                }
            )
        elif php_scandir:
            data = php_scandir.groupdict()
            set_aliases(values, data["errno"], ("errno", "error_code"))
            set_aliases(values, data["file_path"], ("file_path",))
            set_aliases(values, data["line"], ("line_number",))
            canonical.update(
                {
                    "event_type": "php_error",
                    "event_action": "failed",
                    "object_name": data["file_path"],
                    "error_code": data["errno"],
                }
            )
        elif php_warning:
            data = php_warning.groupdict()
            set_aliases(values, data["warning_message"], ("warning_message",))
            set_aliases(values, data["file_path"], ("file_path",))
            set_aliases(values, data["line"], ("line_number",))
            canonical.update(
                {
                    "event_type": "php_error",
                    "event_action": "failed",
                    "object_name": data["file_path"],
                }
            )
        else:
            result.warnings.append("apache_error_message_not_classified")

        result.source_values.update(values)
        result.canonical_values.update(canonical)
        return result
