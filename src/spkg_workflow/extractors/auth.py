from __future__ import annotations

import re

from spkg_workflow.contracts import ParsedLogRecord

from .base import ExtractorContext, FamilyExtraction
from .common import extract_key_values, set_aliases


AUTH_PREFIX = re.compile(
    r"^(?P<host>\S+)\s+(?P<program>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<body>.*)$"
)


class AuthExtractor:
    family = "auth"

    def extract(
        self, record: ParsedLogRecord, context: ExtractorContext
    ) -> FamilyExtraction:
        result = FamilyExtraction()
        prefix = AUTH_PREFIX.match(record.content.strip())
        if not prefix:
            result.warnings.append("auth_prefix_not_recognized")
            return result

        host = prefix.group("host")
        program = prefix.group("program").strip()
        pid = prefix.group("pid") or ""
        body = prefix.group("body")
        values = extract_key_values(body)
        set_aliases(values, host, ("host", "hostname"))
        set_aliases(values, program, ("program", "process", "process_name"))
        set_aliases(values, pid, ("pid",))

        canonical = result.canonical_values
        canonical.update(
            {
                "host": host or context.default_host,
                "program": program or context.default_program,
                "pid": pid,
            }
        )

        accepted = re.match(
            r"^(?P<action>Accepted|Failed)\s+(?P<method>\S+)\s+for(?: invalid user)?\s+"
            r"(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)\s+"
            r"(?P<ssh_version>\S+)(?::\s+(?P<key_type>\S+)\s+(?P<fingerprint>\S+))?$",
            body,
            re.IGNORECASE,
        )
        no_ident = re.match(
            r"^Did not receive identification string from (?P<src_ip>\S+) port (?P<src_port>\d+)$",
            body,
        )
        sudo = re.match(
            r"^(?P<invoker>\S+)\s*:\s*TTY=(?P<tty>.*?)\s*;\s*PWD=(?P<pwd>.*?)\s*;\s*"
            r"USER=(?P<target>.*?)\s*;\s*COMMAND=(?P<command>.*)$",
            body,
        )
        su_success = re.match(
            r"^Successful su for (?P<target>\S+) by (?P<actor>\S+)$", body
        )
        su_terminal = re.match(
            r"^\+\s+(?P<tty>\S+)\s+(?P<actor>[^:\s]+):(?P<target>\S+)$", body
        )
        new_session = re.match(
            r"^New session (?P<session>\S+) of user (?P<user>\S+)\.?$", body
        )
        removed_session = re.match(r"^Removed session (?P<session>\S+)\.?$", body)
        pam_session = re.match(
            r"^pam_unix\((?P<service>[^)]+)\): session (?P<state>opened|closed) "
            r"for user (?P<user>\S+)(?: by \(uid=(?P<uid>\d+)\))?$",
            body,
        )

        if accepted:
            data = accepted.groupdict(default="")
            outcome = "success" if data["action"].lower() == "accepted" else "failure"
            set_aliases(values, data["method"], ("auth_method",))
            set_aliases(values, data["user"], ("user",))
            set_aliases(values, data["src_ip"], ("src_ip", "source_ip"))
            set_aliases(values, data["src_port"], ("src_port", "source_port"))
            set_aliases(values, data["ssh_version"], ("ssh_version",))
            set_aliases(values, data["key_type"], ("key_type",))
            set_aliases(values, data["fingerprint"], ("key_fingerprint",))
            canonical.update(
                {
                    "event_type": "ssh_login",
                    "event_action": data["action"].lower(),
                    "user": data["user"],
                    "src_ip": data["src_ip"],
                    "src_port": data["src_port"],
                    "outcome": outcome,
                }
            )
        elif no_ident:
            data = no_ident.groupdict()
            set_aliases(values, data["src_ip"], ("src_ip", "source_ip"))
            set_aliases(values, data["src_port"], ("src_port", "source_port"))
            canonical.update(
                {
                    "event_type": "ssh_identification",
                    "event_action": "rejected",
                    "src_ip": data["src_ip"],
                    "src_port": data["src_port"],
                    "outcome": "failure",
                }
            )
        elif sudo:
            data = {key: value.strip() for key, value in sudo.groupdict().items()}
            set_aliases(values, data["invoker"], ("user", "invoker_user"))
            set_aliases(values, data["target"], ("sudo_user", "target_user"))
            set_aliases(values, data["tty"], ("tty",))
            set_aliases(values, data["pwd"], ("pwd", "cwd"))
            set_aliases(values, data["command"], ("command",))
            canonical.update(
                {
                    "event_type": "sudo_cmd",
                    "event_action": "execute",
                    "user": data["invoker"],
                    "invoker_user": data["invoker"],
                    "target_user": data["target"],
                    "tty": data["tty"],
                    "cwd": data["pwd"],
                    "command": data["command"],
                    "outcome": "success",
                }
            )
        elif su_success or su_terminal:
            match = su_success or su_terminal
            assert match is not None
            data = match.groupdict(default="")
            set_aliases(values, data["actor"], ("by_user", "user", "actor_user"))
            set_aliases(values, data["target"], ("target_user",))
            if data.get("tty"):
                set_aliases(values, data["tty"], ("tty",))
            canonical.update(
                {
                    "event_type": "su",
                    "event_action": "assume_identity",
                    "actor_user": data["actor"],
                    "target_user": data["target"],
                    "tty": data.get("tty", ""),
                    "outcome": "success",
                }
            )
        elif new_session:
            data = new_session.groupdict()
            set_aliases(values, data["session"].rstrip("."), ("session_id",))
            set_aliases(values, data["user"].rstrip("."), ("user",))
            canonical.update(
                {
                    "event_type": "session",
                    "event_action": "opened",
                    "session_id": data["session"].rstrip("."),
                    "user": data["user"].rstrip("."),
                    "outcome": "success",
                }
            )
        elif removed_session:
            session = removed_session.group("session").rstrip(".")
            set_aliases(values, session, ("session_id",))
            canonical.update(
                {
                    "event_type": "session",
                    "event_action": "closed",
                    "session_id": session,
                    "outcome": "success",
                }
            )
        elif pam_session:
            data = pam_session.groupdict(default="")
            service = data["service"].split(":", 1)[0]
            set_aliases(values, service, ("service", "subsystem", "pam_service"))
            set_aliases(
                values, data["state"], ("session_operation", "session_state", "pam_action")
            )
            set_aliases(values, data["user"], ("user", "target_user"))
            set_aliases(values, data["uid"], ("uid", "actor_user"))
            canonical.update(
                {
                    "event_type": "pam_session",
                    "event_action": data["state"],
                    "user": data["user"],
                    "actor_user": data["uid"],
                    "pam_service": service,
                    "pam_action": data["state"],
                    "outcome": "success",
                }
            )
        else:
            result.warnings.append("auth_event_not_recognized")

        result.source_values.update(values)
        return result
