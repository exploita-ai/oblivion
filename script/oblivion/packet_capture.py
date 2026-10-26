"""Inspect complete Ethernet PCAPs recorded outside the laboratory guests."""
import hashlib
import socket
import struct


def capture(path):
    data = path.read_bytes()
    assert data[:4] in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"]
    order = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    assert struct.unpack(order + "I", data[20:24])[0] == 1
    result = {"packets": 0, "ipv4": 0, "ipv6": 0, "udp": 0, "tcp": 0, "tcp_ports": [], "udp_ports": [], "tcp_flows": [], "ipv4_fragments": 0}
    offset = 24
    while offset < len(data):
        _, _, length, original = struct.unpack_from(order + "IIII", data, offset)
        assert length == original and offset + 16 + length <= len(data)
        packet = data[offset + 16:offset + 16 + length]
        offset += 16 + length
        result["packets"] += 1
        protocol = packet[12:14]
        if protocol == b"\x86\xdd":
            result["ipv6"] += 1
        if protocol != b"\x08\x00":
            continue
        result["ipv4"] += 1
        ip = packet[14:]
        assert len(ip) >= 20 and ip[0] >> 4 == 4
        if struct.unpack_from("!H", ip, 6)[0] & 0x3fff:
            result["ipv4_fragments"] += 1
            continue
        if ip[9] not in [6, 17]:
            continue
        kind = "tcp" if ip[9] == 6 else "udp"
        result[kind] += 1
        transport = ip[(ip[0] & 15) * 4:]
        source, destination = struct.unpack_from("!HH", transport)
        result[kind + "_ports"].extend([source, destination])
        if kind == "tcp":
            result["tcp_flows"].append((socket.inet_ntoa(ip[12:16]), source, socket.inet_ntoa(ip[16:20]), destination))
    for kind in ["tcp", "udp"]:
        result[kind + "_ports"] = sorted(set(result[kind + "_ports"]))
    result["tcp_flows"] = sorted(set(result["tcp_flows"]))
    result["sha256"] = hashlib.sha256(data).hexdigest()
    return result
