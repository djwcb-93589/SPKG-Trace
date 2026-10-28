from __future__ import annotations

import re

from spkg_workflow.contracts import ParsedLogRecord

from .base import ExtractorContext, FamilyExtraction
from .common import extract_key_values, set_aliases, split_endpoint


PEER_PREFIX = re.compile(
    r"^(?P<peer>(?:(?P<user>[^/\s]+)/)?(?P<endpoint>(?:\[[^\]]+\]|[^\s:]+):\d+))\s+(?P<body>.*)$"
)


def _traffic_pair(value: str) -> tuple[str, str]:
    text = value.strip()
    if "/" in text:
        return tuple(text.split("/", 1))  # type: ignore[return-value]
    return text, ""


class VpnExtractor:
    family = "vpn"

    def extract(
        self, record: ParsedLogRecord, context: ExtractorContext
    ) -> FamilyExtraction:
        result = FamilyExtraction()
        content = record.content.strip()
        peer_match = PEER_PREFIX.match(content)
        if peer_match:
            peer = peer_match.group("peer")
            user = peer_match.group("user") or ""
            endpoint = peer_match.group("endpoint")
            body = peer_match.group("body")
            src_ip, src_port = split_endpoint(endpoint)
        else:
            peer = user = endpoint = src_ip = src_port = ""
            body = content

        values = extract_key_values(body)
        set_aliases(values, peer, ("peer_id", "peer_ip_port", "client_endpoint"))
        set_aliases(values, user, ("user", "username", "user_name", "source_user"))
        set_aliases(
            values,
            src_ip,
            ("src_ip", "source_ip", "client_ip", "src_host", "dmorgan_host"),
        )
        set_aliases(values, src_port, ("src_port", "source_port", "client_port", "port"))
        canonical: dict[str, str] = {
            "host": context.default_host,
            "program": context.default_program or "openvpn",
            "user": user,
            "session_id": peer or endpoint,
            "src_ip": src_ip,
            "src_port": src_port,
        }

        eku = re.search(
            r"Certificate has EKU \(str\) (?P<actual>.+?) expects (?P<expected>.+)$", body
        )
        control = re.search(
            r"Control Channel:\s*(?P<tls>TLSv\S+),?\s+cipher\s+TLSv\S+\s+"
            r"(?P<cipher>\S+),?\s+peer certificate:\s*(?P<bits>\d+) bit "
            r"(?P<key_type>\S+),?\s+signature:\s*(?P<signature>\S+)",
            body,
        )
        initial = re.search(
            r"TLS: Initial packet from \[(?P<family>[^\]]+)\](?P<endpoint>\S+) "
            r"sid=(?P<sid>\S+)(?:\s+(?P<detail>.*))?$",
            body,
        )
        verify_short = re.search(r"\bVERIFY (?P<verify_type>\S+) OK$", body)
        verify_detail = re.search(r"\bVERIFY OK:\s*depth=(?P<depth>\d+)\s*(?P<attrs>.*)$", body)
        inactivity = re.search(
            r"(?:\[(?P<client>[^\]]+)\]\s+)?Inactivity timeout \(--ping-restart\) restarting$",
            body,
        )
        initiated = re.search(
            r"\[(?P<client>[^\]]+)\] Peer Connection Initiated with "
            r"\[(?P<family>[^\]]+)\](?P<endpoint>\S+)$",
            body,
        )
        peer_info = re.search(r"peer info:\s*(?P<key>[^=\s]+)=(?P<value>.*)$", body)
        data_cipher = re.search(
            r"(?:(?P<direction>\S+)\s+)?Data Channel: Cipher '(?P<cipher>[^']+)' "
            r"initialized with (?P<bits>\d+) bit key$",
            body,
        )
        data_hmac = re.search(
            r"(?:(?P<direction>\S+)\s+)?Data Channel: Using (?P<bits>\d+) bit "
            r"message hash '(?P<hash>[^']+)' for HMAC authentication$",
            body,
        )
        learn = re.search(r"MULTI: Learn:\s*(?P<virtual>\S+)\s*->\s*(?P<client>\S+)$", body)
        primary_ip = re.search(r"MULTI: primary virtual IP for \S+:\s*(?P<virtual>\S+)$", body)
        pool_ip = re.search(
            r"MULTI_sva: pool returned IPv4=(?P<virtual>\S+)\s+IPv6=\((?P<ipv6>[^)]+)\)",
            body,
        )
        push_received = re.search(r"PUSH: Received control message:\s*'(?P<message>.*)'$", body)
        push_sent = re.search(
            r"SENT CONTROL \[(?P<client>[^\]]+)\]:\s*'(?P<message>.*)'\s*"
            r"\(status=(?P<status>\d+)\)$",
            body,
        )
        signal = re.search(
            r"(?P<signal>SIG\S+)\[(?P<detail>[^\]]+)\] received (?P<reason>.*)$",
            body,
        )
        soft_reset = re.search(
            r"TLS: soft reset sec=(?P<sec>\S+) bytes=(?P<bytes>\S+) pkts=(?P<pkts>\S+)$",
            body,
        )
        negotiation_error = re.search(
            r"TLS Error: TLS key negotiation failed to occur within (?P<seconds>\d+) seconds",
            body,
        )
        handshake_error = "TLS Error: TLS handshake failed" in body
        move_session = re.search(
            r"TLS: move_session: dest=(?P<dest>\S+) src=(?P<src>\S+) reinit_src=(?P<reinit>\S+)$",
            body,
        )

        if eku:
            data = eku.groupdict()
            set_aliases(values, data["actual"], ("actual_eku", "eku_actual", "eku_value", "certificate_eku"))
            set_aliases(values, data["expected"], ("expected_eku", "eku_expected"))
            canonical.update(
                {"event_type": "cert_verify", "event_action": "verified", "outcome": "success"}
            )
        elif control:
            data = control.groupdict()
            set_aliases(values, data["tls"], ("tls_version",))
            set_aliases(values, data["cipher"], ("cipher", "cipher_suite"))
            set_aliases(values, data["bits"], ("certificate_key_size", "key_size", "key_bits"))
            set_aliases(values, data["key_type"], ("certificate_key_type",))
            set_aliases(
                values,
                data["signature"],
                ("certificate_signature_algorithm", "signature_algorithm"),
            )
            canonical.update(
                {
                    "event_type": "control_channel",
                    "event_action": "negotiated",
                    "tls_version": data["tls"],
                    "cipher_suite": data["cipher"],
                    "outcome": "success",
                }
            )
        elif initial:
            data = initial.groupdict(default="")
            packet_ip, packet_port = split_endpoint(data["endpoint"])
            set_aliases(values, data["family"], ("address_family", "af_inet_family"))
            set_aliases(values, packet_ip, ("source_ip", "src_ip"))
            set_aliases(values, packet_port, ("source_port", "src_port"))
            set_aliases(values, data["sid"], ("sid", "session_id"))
            canonical.update(
                {
                    "event_type": "vpn_initial_packet",
                    "event_action": "received",
                    "session_id": data["sid"],
                    "src_ip": packet_ip,
                    "src_port": packet_port,
                }
            )
        elif verify_short:
            verify_type = verify_short.group("verify_type")
            set_aliases(values, verify_type, ("verify_type",))
            canonical.update(
                {"event_type": "cert_verify", "event_action": "verified", "outcome": "success"}
            )
        elif verify_detail:
            data = verify_detail.groupdict()
            set_aliases(values, data["depth"], ("depth",))
            attrs = extract_key_values(data["attrs"])
            values.update({key: value for key, value in attrs.items() if key not in values})
            common_name = attrs.get("cn", "")
            set_aliases(values, common_name, ("common_name", "client_common_name"))
            if not user and common_name and common_name.lower() not in {"openvpn ca", "openvpn"}:
                canonical["user"] = common_name
            canonical.update(
                {"event_type": "cert_verify", "event_action": "verified", "outcome": "success"}
            )
        elif "Validating certificate extended key usage" in body:
            canonical.update({"event_type": "cert_verify", "event_action": "validating"})
        elif inactivity:
            client = inactivity.group("client") or ""
            set_aliases(values, client, ("client_identifier", "client_id"))
            canonical.update(
                {
                    "event_type": "inactivity_timeout",
                    "event_action": "timed_out",
                    "outcome": "timeout",
                }
            )
        elif initiated:
            data = initiated.groupdict()
            remote_ip, remote_port = split_endpoint(data["endpoint"])
            set_aliases(values, data["client"], ("client_identifier", "client_id"))
            set_aliases(values, data["family"], ("address_family", "af_inet_family"))
            set_aliases(values, remote_ip, ("client_ip", "src_ip"))
            set_aliases(values, remote_port, ("client_port", "src_port"))
            canonical.update(
                {
                    "event_type": "peer_connection_initiated",
                    "event_action": "initiated",
                    "src_ip": remote_ip,
                    "src_port": remote_port,
                    "outcome": "success",
                }
            )
        elif peer_info:
            data = peer_info.groupdict()
            set_aliases(values, data["key"], ("info_key", "peer_info_key"))
            set_aliases(values, data["value"], ("info_value", "peer_info_value"))
            canonical.update(
                {
                    "event_type": "peer_info",
                    "event_action": "reported",
                    "peer_info_key": data["key"],
                    "peer_info_value": data["value"],
                }
            )
        elif data_cipher:
            data = data_cipher.groupdict(default="")
            set_aliases(values, data["direction"], ("direction", "channel_direction"))
            set_aliases(values, data["cipher"], ("cipher", "cipher_suite"))
            set_aliases(values, data["bits"], ("key_bits", "key_size"))
            canonical.update(
                {
                    "event_type": "data_channel",
                    "event_action": "initialized",
                    "cipher_suite": data["cipher"],
                    "outcome": "success",
                }
            )
        elif data_hmac:
            data = data_hmac.groupdict(default="")
            set_aliases(values, data["direction"], ("direction", "channel_direction"))
            set_aliases(values, data["bits"], ("hash_bit_length",))
            set_aliases(values, data["hash"], ("hash_algorithm", "hmac_alg"))
            canonical.update(
                {
                    "event_type": "data_channel",
                    "event_action": "authenticated",
                    "hmac_alg": data["hash"],
                    "outcome": "success",
                }
            )
        elif learn or primary_ip or pool_ip:
            match = learn or primary_ip or pool_ip
            assert match is not None
            virtual_ip = match.group("virtual")
            set_aliases(
                values,
                virtual_ip,
                ("virtual_ip", "learned_ip", "assigned_ipv4", "ipv4_assigned"),
            )
            if pool_ip:
                ipv6 = pool_ip.group("ipv6")
                set_aliases(values, ipv6, ("ipv6_enabled", "ipv6_status"))
            canonical.update(
                {
                    "event_type": "virtual_ip_assigned",
                    "event_action": "assigned",
                    "virtual_ip": virtual_ip,
                    "outcome": "success",
                }
            )
        elif push_received or push_sent:
            match = push_received or push_sent
            assert match is not None
            message = match.group("message")
            status = match.groupdict().get("status", "")
            set_aliases(
                values,
                message,
                ("control_message", "control_message_type", "command", "push_reply"),
            )
            set_aliases(values, status, ("status", "status_code"))
            canonical.update(
                {
                    "event_type": "control_message",
                    "event_action": "sent" if push_sent else "received",
                    "control_message": message,
                    "status_code": status,
                    "outcome": "success",
                }
            )
        elif signal:
            data = signal.groupdict()
            set_aliases(values, data["signal"], ("signal",))
            set_aliases(values, data["detail"], ("signal_detail",))
            set_aliases(values, data["reason"], ("event_reason", "event_detail"))
            canonical.update(
                {
                    "event_type": "tls_reset",
                    "event_action": "restarted",
                    "control_message": data["signal"],
                    "outcome": "restart",
                }
            )
        elif soft_reset:
            data = soft_reset.groupdict()
            bytes_in, bytes_out = _traffic_pair(data["bytes"])
            pkts_in, pkts_out = _traffic_pair(data["pkts"])
            set_aliases(values, data["sec"], ("sec", "duration_sec"))
            set_aliases(values, data["bytes"], ("bytes", "bytes_transferred"))
            set_aliases(values, data["pkts"], ("pkts", "packets_transferred"))
            set_aliases(values, bytes_in, ("bytes_received", "bytes_in"))
            set_aliases(values, bytes_out, ("bytes_sent", "bytes_out"))
            set_aliases(values, pkts_in, ("pkts_received", "pkts_in"))
            set_aliases(values, pkts_out, ("pkts_sent", "pkts_out"))
            canonical.update(
                {
                    "event_type": "tls_reset",
                    "event_action": "reset",
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "pkts_in": pkts_in,
                    "pkts_out": pkts_out,
                    "outcome": "restart",
                }
            )
        elif negotiation_error or handshake_error:
            if negotiation_error:
                seconds = negotiation_error.group("seconds")
                set_aliases(values, seconds, ("timeout_seconds", "duration_sec"))
            canonical.update(
                {
                    "event_type": "tls_error",
                    "event_action": "failed",
                    "outcome": "failure",
                }
            )
        elif move_session:
            data = move_session.groupdict()
            set_aliases(values, data["dest"], ("dest",))
            set_aliases(values, data["src"], ("src",))
            set_aliases(values, data["reinit"], ("reinit_src",))
            canonical.update({"event_type": "tls_session_move", "event_action": "moved"})
        else:
            result.warnings.append("vpn_event_not_recognized")

        result.source_values.update(values)
        result.canonical_values.update(canonical)
        return result
