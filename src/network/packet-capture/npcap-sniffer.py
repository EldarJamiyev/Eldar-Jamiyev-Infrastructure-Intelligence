#!/usr/bin/env python3
"""
Eldar Jamiyev's Infrastructure Intelligence (EJII)
Enterprise Real-Time Npcap Packet Capture Daemon & Protocol Dissector
Zero-Fiction / Zero-Simulation Standard: 100% Genuine Physical Wire Capture.
"""

import sys
import os
import json
import time
import struct
import socket
import ctypes
import argparse

# ---------------------------------------------------------------------------
# Windows Npcap CTypes Definition (64-bit Pointer Safe)
# ---------------------------------------------------------------------------
class timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_usec', ctypes.c_long)]

class pcap_pkthdr(ctypes.Structure):
    _fields_ = [('ts', timeval), ('caplen', ctypes.c_uint32), ('len', ctypes.c_uint32)]

class bpf_program(ctypes.Structure):
    _fields_ = [('bf_len', ctypes.c_uint), ('bf_insns', ctypes.c_void_p)]

class pcap_stat(ctypes.Structure):
    _fields_ = [
        ('ps_recv', ctypes.c_uint),
        ('ps_drop', ctypes.c_uint),
        ('ps_ifdrop', ctypes.c_uint),
        ('bs_capt', ctypes.c_uint)
    ]

class pcap_if(ctypes.Structure):
    pass
pcap_if._fields_ = [
    ('next', ctypes.POINTER(pcap_if)),
    ('name', ctypes.c_char_p),
    ('description', ctypes.c_char_p),
    ('addresses', ctypes.c_void_p),
    ('flags', ctypes.c_uint)
]

def load_wpcap():
    possible_paths = [
        r'C:\Windows\System32\Npcap\wpcap.dll',
        r'C:\Windows\System32\wpcap.dll',
        'wpcap.dll',
        'libpcap.so',
        'libpcap.dylib'
    ]
    for p in possible_paths:
        try:
            lib = ctypes.cdll.LoadLibrary(p)
            lib.pcap_open_live.restype = ctypes.c_void_p
            lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
            lib.pcap_next_ex.restype = ctypes.c_int
            lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
            lib.pcap_compile.restype = ctypes.c_int
            lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(bpf_program), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
            lib.pcap_setfilter.restype = ctypes.c_int
            lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(bpf_program)]
            lib.pcap_close.argtypes = [ctypes.c_void_p]
            lib.pcap_findalldevs.restype = ctypes.c_int
            lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if)), ctypes.c_char_p]
            lib.pcap_freealldevs.argtypes = [ctypes.POINTER(pcap_if)]
            try:
                lib.pcap_stats.restype = ctypes.c_int
                lib.pcap_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(pcap_stat)]
            except Exception:
                pass
            return lib
        except Exception:
            continue
    return None

def is_physical_candidate(desc_str):
    d = (desc_str or '').lower()
    if 'ndiswan' in d or 'wan miniport' in d or 'bluetooth' in d:
        return False
    if 'virtual' in d or 'hyper-v' in d or 'vmware' in d or 'vbox' in d or 'direct' in d:
        return False
    return True

def find_best_device(wpcap):
    alldevs = ctypes.POINTER(pcap_if)()
    errbuf = ctypes.create_string_buffer(256)
    if wpcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf) != 0:
        return None, errbuf.value.decode('utf-8', 'ignore')

    devices = []
    curr = alldevs
    while curr:
        dev = curr.contents
        name = dev.name.decode('utf-8', 'ignore') if dev.name else ''
        desc = dev.description.decode('utf-8', 'ignore') if dev.description else ''
        devices.append((name, desc))
        curr = dev.next
    wpcap.pcap_freealldevs(alldevs)

    # 1. Prefer true physical NIC (Intel, Realtek, Broadcom, Atheros, Ethernet, Wi-Fi)
    for name, desc in devices:
        d_lower = desc.lower()
        if is_physical_candidate(desc) and ('intel' in d_lower or 'realtek' in d_lower or 'wi-fi' in d_lower or 'ethernet' in d_lower):
            return name, desc

    # 2. Candidate physical without keyword match
    for name, desc in devices:
        if is_physical_candidate(desc):
            return name, desc

    # 3. Fallback: Loopback or any non-wan
    for name, desc in devices:
        if 'ndiswan' not in desc.lower() and 'wan' not in desc.lower():
            return name, desc

    if devices:
        return devices[0][0], devices[0][1]
    return None, "No network devices found"

# ---------------------------------------------------------------------------
# Deep Protocol Dissection Functions
# ---------------------------------------------------------------------------
def format_mac(b):
    return ":".join(f"{x:02x}" for x in b)

def dissect_ethernet(raw):
    if len(raw) < 14:
        return None, raw
    dst_mac = format_mac(raw[0:6])
    src_mac = format_mac(raw[6:12])
    ethertype = struct.unpack("!H", raw[12:14])[0]
    payload = raw[14:]

    # Handle 802.1Q VLAN Tagging
    vlan_id = None
    if ethertype == 0x8100 and len(payload) >= 4:
        vlan_hdr = struct.unpack("!H", payload[0:2])[0]
        vlan_id = vlan_hdr & 0x0FFF
        ethertype = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]

    return {
        'srcMac': src_mac,
        'dstMac': dst_mac,
        'ethertype': hex(ethertype),
        'vlanId': vlan_id
    }, ethertype, payload

def dissect_arp(raw):
    if len(raw) < 28:
        return None
    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("!HHBBH", raw[0:8])
    sender_mac = format_mac(raw[8:14])
    sender_ip = socket.inet_ntoa(raw[14:18])
    target_mac = format_mac(raw[18:24])
    target_ip = socket.inet_ntoa(raw[24:28])
    return {
        'opcode': 'REQUEST' if opcode == 1 else ('REPLY' if opcode == 2 else str(opcode)),
        'senderMac': sender_mac,
        'senderIp': sender_ip,
        'targetMac': target_mac,
        'targetIp': target_ip
    }

def dissect_ipv4(raw):
    if len(raw) < 20:
        return None, 0, raw
    v_ihl = raw[0]
    version = v_ihl >> 4
    ihl = (v_ihl & 0x0F) * 4
    if len(raw) < ihl:
        return None, 0, raw

    dscp_ecn = raw[1]
    dscp = dscp_ecn >> 2
    ecn = dscp_ecn & 0x03
    total_len, ident, flags_frag, ttl, protocol, checksum = struct.unpack("!HHHBBH", raw[2:12])
    flags = {
        'df': bool(flags_frag & 0x4000),
        'mf': bool(flags_frag & 0x2000)
    }
    fragment_offset = (flags_frag & 0x1FFF) * 8
    src_ip = socket.inet_ntoa(raw[12:16])
    dst_ip = socket.inet_ntoa(raw[16:20])
    payload = raw[ihl:total_len] if total_len <= len(raw) else raw[ihl:]

    return {
        'version': version,
        'ihl': ihl,
        'dscp': dscp,
        'ecn': ecn,
        'totalLength': total_len,
        'identification': ident,
        'flags': flags,
        'fragmentOffset': fragment_offset,
        'ttl': ttl,
        'protocol': protocol,
        'checksum': hex(checksum),
        'srcIp': src_ip,
        'dstIp': dst_ip
    }, protocol, payload

def dissect_ipv6(raw):
    if len(raw) < 40:
        return None, 0, raw
    vtc_fl = struct.unpack("!I", raw[0:4])[0]
    version = vtc_fl >> 28
    traffic_class = (vtc_fl >> 20) & 0xFF
    flow_label = vtc_fl & 0xFFFFF
    payload_len, next_header, hop_limit = struct.unpack("!HBB", raw[4:8])
    src_ip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, raw[24:40])
    payload = raw[40:40+payload_len]
    return {
        'version': version,
        'trafficClass': traffic_class,
        'flowLabel': flow_label,
        'payloadLength': payload_len,
        'nextHeader': next_header,
        'hopLimit': hop_limit,
        'srcIp': src_ip,
        'dstIp': dst_ip
    }, next_header, payload

def dissect_icmp(raw):
    if len(raw) < 8:
        return None
    icmp_type, code, checksum = struct.unpack("!BBH", raw[0:4])
    ident, seq = struct.unpack("!HH", raw[4:8])

    type_desc = f"Type {icmp_type}"
    if icmp_type == 8:
        type_desc = "Echo (ping) request"
    elif icmp_type == 0:
        type_desc = "Echo (ping) reply"
    elif icmp_type == 3:
        code_map = {0: "Net Unreachable", 1: "Host Unreachable", 2: "Protocol Unreachable", 3: "Port Unreachable", 4: "Frag Needed (DF set)"}
        type_desc = f"Destination unreachable ({code_map.get(code, f'Code {code}')})"
    elif icmp_type == 11:
        type_desc = "Time-to-live exceeded (traceroute hop)"

    return {
        'type': icmp_type,
        'code': code,
        'typeDesc': type_desc,
        'checksum': hex(checksum),
        'identifier': ident,
        'sequenceNumber': seq,
        'payloadLength': max(0, len(raw) - 8)
    }

def dissect_tcp(raw):
    if len(raw) < 20:
        return None, raw
    src_port, dst_port, seq, ack, offset_reserved, flags_byte, win_size, checksum, urg_ptr = struct.unpack("!HHIIBBHHH", raw[0:20])
    data_offset = (offset_reserved >> 4) * 4
    if len(raw) < data_offset:
        return None, raw

    flags = {
        'fin': bool(flags_byte & 0x01),
        'syn': bool(flags_byte & 0x02),
        'rst': bool(flags_byte & 0x04),
        'psh': bool(flags_byte & 0x08),
        'ack': bool(flags_byte & 0x10),
        'urg': bool(flags_byte & 0x20),
        'ece': bool(flags_byte & 0x40),
        'cwr': bool(flags_byte & 0x80)
    }

    flag_names = [k.upper() for k, v in flags.items() if v]

    # Parse TCP Options
    options = {}
    opt_bytes = raw[20:data_offset]
    idx = 0
    while idx < len(opt_bytes):
        kind = opt_bytes[idx]
        if kind == 0: # End of options
            break
        elif kind == 1: # NOP
            idx += 1
            continue
        if idx + 1 >= len(opt_bytes):
            break
        length = opt_bytes[idx + 1]
        if length < 2 or idx + length > len(opt_bytes):
            break
        data = opt_bytes[idx+2 : idx+length]
        if kind == 2 and len(data) == 2:
            options['mss'] = struct.unpack("!H", data)[0]
        elif kind == 3 and len(data) == 1:
            options['windowScale'] = data[0]
        elif kind == 4:
            options['sackPermitted'] = True
        elif kind == 8 and len(data) == 8:
            options['timestamp'] = struct.unpack("!II", data)
        idx += length

    payload = raw[data_offset:]
    return {
        'srcPort': src_port,
        'dstPort': dst_port,
        'seq': seq,
        'ack': ack,
        'dataOffset': data_offset,
        'flags': flags,
        'flagNames': flag_names,
        'windowSize': win_size,
        'checksum': hex(checksum),
        'urgentPointer': urg_ptr,
        'options': options,
        'payloadLength': len(payload)
    }, payload

def dissect_udp(raw):
    if len(raw) < 8:
        return None, raw
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw[0:8])
    payload = raw[8:length] if length <= len(raw) else raw[8:]
    return {
        'srcPort': src_port,
        'dstPort': dst_port,
        'length': length,
        'checksum': hex(checksum),
        'payloadLength': len(payload)
    }, payload

def parse_dns_name(payload, offset):
    parts = []
    visited = set()
    orig_offset = offset
    stepped = False
    new_offset = offset

    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            offset += 1
            if not stepped:
                new_offset = offset
            break
        elif (length & 0xC0) == 0xC0: # Pointer
            if offset + 1 >= len(payload):
                break
            ptr = struct.unpack("!H", payload[offset:offset+2])[0] & 0x3FFF
            if not stepped:
                new_offset = offset + 2
                stepped = True
            if ptr in visited:
                break
            visited.add(ptr)
            offset = ptr
        else:
            offset += 1
            if offset + length > len(payload):
                break
            parts.append(payload[offset:offset+length].decode('utf-8', 'ignore'))
            offset += length
            if not stepped:
                new_offset = offset

    return ".".join(parts), new_offset

def dissect_dns(payload):
    if len(payload) < 12:
        return None
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[0:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F

    offset = 12
    questions = []
    type_map = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'}

    for _ in range(qdcount):
        if offset >= len(payload):
            break
        name, offset = parse_dns_name(payload, offset)
        if offset + 4 <= len(payload):
            qtype, qclass = struct.unpack("!HH", payload[offset:offset+4])
            offset += 4
            questions.append({'name': name, 'type': type_map.get(qtype, str(qtype))})

    answers = []
    for _ in range(ancount):
        if offset >= len(payload):
            break
        name, offset = parse_dns_name(payload, offset)
        if offset + 10 <= len(payload):
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", payload[offset:offset+10])
            offset += 10
            rdata_bytes = payload[offset:offset+rdlength]
            offset += rdlength
            data_str = ""
            if rtype == 1 and len(rdata_bytes) == 4:
                data_str = socket.inet_ntoa(rdata_bytes)
            elif rtype == 28 and len(rdata_bytes) == 16:
                data_str = socket.inet_ntop(socket.AF_INET6, rdata_bytes)
            elif rtype in (2, 5, 12):
                cname, _ = parse_dns_name(payload, offset - rdlength)
                data_str = cname
            else:
                data_str = f"len={rdlength}"
            answers.append({'name': name, 'type': type_map.get(rtype, str(rtype)), 'ttl': ttl, 'data': data_str})

    return {
        'transactionId': hex(tid),
        'isResponse': bool(qr),
        'opcode': opcode,
        'rcode': rcode,
        'rcodeDesc': "NoError" if rcode == 0 else ("NXDomain" if rcode == 3 else f"RCODE {rcode}"),
        'questions': questions,
        'answers': answers
    }

def dissect_tls(payload):
    if len(payload) < 5:
        return None
    content_type, major, minor, record_len = struct.unpack("!BBBH", payload[0:5])
    content_types = {20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'ApplicationData'}
    if content_type not in content_types:
        return None

    ct_name = content_types[content_type]
    tls_info = {
        'contentType': ct_name,
        'recordVersion': f"{major}.{minor}",
        'recordLength': record_len
    }

    if content_type == 22 and len(payload) >= 9:
        handshake_type = payload[5]
        hs_map = {1: 'ClientHello', 2: 'ServerHello', 11: 'Certificate', 12: 'ServerKeyExchange', 14: 'ServerHelloDone', 16: 'ClientKeyExchange'}
        tls_info['handshakeType'] = hs_map.get(handshake_type, f"Type {handshake_type}")

        # Extract SNI from ClientHello
        if handshake_type == 1 and len(payload) > 43:
            try:
                idx = 9 # Skip record header (5) + handshake hdr (4)
                idx += 2 + 32 # Skip client version (2) + random (32)
                if idx < len(payload):
                    sess_len = payload[idx]
                    idx += 1 + sess_len
                    if idx + 2 <= len(payload):
                        cipher_len = struct.unpack("!H", payload[idx:idx+2])[0]
                        idx += 2 + cipher_len
                        if idx + 1 <= len(payload):
                            comp_len = payload[idx]
                            idx += 1 + comp_len
                            if idx + 2 <= len(payload):
                                ext_total_len = struct.unpack("!H", payload[idx:idx+2])[0]
                                idx += 2
                                ext_end = min(idx + ext_total_len, len(payload))
                                while idx + 4 <= ext_end:
                                    ext_type, ext_len = struct.unpack("!HH", payload[idx:idx+4])
                                    idx += 4
                                    if ext_type == 0: # server_name (SNI)
                                        if idx + 5 <= len(payload):
                                            # list_len (2), name_type (1), name_len (2)
                                            name_len = struct.unpack("!H", payload[idx+3:idx+5])[0]
                                            sni_bytes = payload[idx+5 : idx+5+name_len]
                                            tls_info['sni'] = sni_bytes.decode('utf-8', 'ignore')
                                        break
                                    idx += ext_len
            except Exception:
                pass

    return tls_info

def dissect_http(payload):
    if len(payload) < 10:
        return None
    methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'HTTP/1.0', b'HTTP/1.1']
    if not any(payload.startswith(m) for m in methods):
        return None

    try:
        text = payload[:1024].decode('utf-8', 'ignore')
        lines = text.split('\r\n')
        first_line = lines[0]
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if ': ' in line:
                k, v = line.split(': ', 1)
                headers[k.lower()] = v

        if first_line.startswith('HTTP/'):
            parts = first_line.split(' ', 2)
            return {
                'type': 'RESPONSE',
                'status': int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 200,
                'statusText': parts[2] if len(parts) > 2 else '',
                'contentType': headers.get('content-type', ''),
                'contentLength': headers.get('content-length', '')
            }
        else:
            parts = first_line.split(' ')
            return {
                'type': 'REQUEST',
                'method': parts[0],
                'uri': parts[1] if len(parts) > 1 else '/',
                'host': headers.get('host', ''),
                'userAgent': headers.get('user-agent', '')
            }
    except Exception:
        return None

def dissect_quic(payload):
    if len(payload) < 5:
        return None
    first_byte = payload[0]
    is_long = bool(first_byte & 0x80)
    if is_long and len(payload) >= 6:
        version = struct.unpack("!I", payload[1:5])[0]
        packet_type = (first_byte >> 4) & 0x03
        type_map = {0: 'Initial', 1: '0-RTT', 2: 'Handshake', 3: 'Retry'}
        return {
            'headerType': 'Long',
            'version': hex(version),
            'packetType': type_map.get(packet_type, str(packet_type)),
            'length': len(payload)
        }
    elif not is_long:
        return {
            'headerType': 'Short (1-RTT Protected)',
            'length': len(payload)
        }
    return None

# ---------------------------------------------------------------------------
# Main Sniffer Runtime Loop
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="EJII Real-Time Physical Wire Packet Capture Daemon")
    parser.add_argument("--device", help="Npcap device name to capture on", default=None)
    parser.add_argument("--bpf", help="BPF capture filter expression", default=None)
    parser.add_argument("--snaplen", help="Snapshot length", type=int, default=65535)
    parser.add_argument("--count", help="Exit after N packets (0 = infinite)", type=int, default=0)
    parser.add_argument("--list-interfaces", action="store_true", help="Print available interfaces in JSON and exit")
    args = parser.parse_args()

    wpcap = load_wpcap()
    if not wpcap:
        sys.stderr.write(json.dumps({"error": "Failed to load Npcap library (wpcap.dll)"}) + "\n")
        sys.stderr.flush()
        sys.exit(1)

    if args.list_interfaces:
        alldevs = ctypes.POINTER(pcap_if)()
        errbuf = ctypes.create_string_buffer(256)
        if wpcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf) != 0:
            sys.stdout.write(json.dumps([]) + "\n")
            sys.exit(0)
        devs = []
        curr = alldevs
        best_name, _ = find_best_device(wpcap)
        while curr:
            d = curr.contents
            n = d.name.decode('utf-8', 'ignore') if d.name else ''
            desc = d.description.decode('utf-8', 'ignore') if d.description else ''
            is_phys = is_physical_candidate(desc)
            is_default = (n == best_name)
            devs.append({
                "name": n,
                "description": desc,
                "isPhysical": is_phys,
                "isDefault": is_default
            })
            curr = d.next
        wpcap.pcap_freealldevs(alldevs)
        sys.stdout.write(json.dumps(devs) + "\n")
        sys.exit(0)

    device_name = args.device
    device_desc = ""
    if not device_name:
        device_name, device_desc = find_best_device(wpcap)

    if not device_name:
        sys.stderr.write(json.dumps({"error": "No capture device available", "detail": device_desc}) + "\n")
        sys.stderr.flush()
        sys.exit(1)

    errbuf = ctypes.create_string_buffer(256)
    dev_bytes = device_name.encode('utf-8')
    handle = wpcap.pcap_open_live(dev_bytes, args.snaplen, 1, 50, errbuf)

    if not handle:
        sys.stderr.write(json.dumps({"error": f"Failed to open interface {device_name}", "detail": errbuf.value.decode('utf-8', 'ignore')}) + "\n")
        sys.stderr.flush()
        sys.exit(1)

    # Apply BPF Capture Filter if specified
    bpf_filter_str = args.bpf or ""
    if bpf_filter_str:
        bpf = bpf_program()
        filter_bytes = bpf_filter_str.encode('utf-8')
        if wpcap.pcap_compile(handle, ctypes.byref(bpf), filter_bytes, 1, 0xFFFFFFFF) == 0:
            wpcap.pcap_setfilter(handle, ctypes.byref(bpf))
        else:
            sys.stderr.write(json.dumps({"warning": f"BPF filter compilation failed for: {bpf_filter_str}"}) + "\n")
            sys.stderr.flush()

    # Inform supervisor of capture startup
    sys.stdout.write(json.dumps({
        "event": "CAPTURE_STARTED",
        "device": device_name,
        "description": device_desc,
        "bpf": bpf_filter_str
    }) + "\n")
    sys.stdout.flush()

    import threading

    stop_event = threading.Event()
    def stdin_monitor():
        try:
            for line in sys.stdin:
                if not line:
                    break
                cmd = line.strip().upper()
                if cmd in ('QUIT', 'STOP', 'EXIT'):
                    break
        except Exception:
            pass
        finally:
            stop_event.set()

    monitor_thread = threading.Thread(target=stdin_monitor, daemon=True)
    monitor_thread.start()

    header = ctypes.POINTER(pcap_pkthdr)()
    data = ctypes.POINTER(ctypes.c_ubyte)()

    packet_counter = 0
    accepted_counter = 0
    last_stats_time = time.time()

    try:
        while not stop_event.is_set():
            res = wpcap.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(data))
            now = time.time()
            if now - last_stats_time >= 1.0:
                last_stats_time = now
                try:
                    ps = pcap_stat()
                    if wpcap.pcap_stats(handle, ctypes.byref(ps)) == 0:
                        sys.stdout.write(json.dumps({
                            "event": "STATS",
                            "received": ps.ps_recv,
                            "dropped": ps.ps_drop,
                            "ifdrop": ps.ps_ifdrop,
                            "captured": packet_counter
                        }) + "\n")
                        sys.stdout.flush()
                except Exception:
                    pass
            if res == 1:
                packet_counter += 1
                accepted_counter += 1
                hdr = header.contents
                caplen = hdr.caplen
                wirelen = hdr.len
                raw = bytes([data[i] for i in range(caplen)])

                # ISO 8601 Microsecond Timestamp
                ts_sec = hdr.ts.tv_sec
                ts_usec = hdr.ts.tv_usec
                iso_ts = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts_sec)) + f".{ts_usec:06d}Z"

                # Layer 2: Ethernet
                eth_info, ethertype, l3_payload = dissect_ethernet(raw)
                if not eth_info:
                    continue

                frame_record = {
                    'frameNumber': packet_counter,
                    'timestamp': iso_ts,
                    'wireLength': wirelen,
                    'capturedLength': caplen,
                    'ethernet': eth_info,
                    'protocol': 'ETHERNET',
                    'srcIp': None,
                    'dstIp': None,
                    'srcPort': None,
                    'dstPort': None,
                    'summary': '',
                    'urlIntelligence': {
                        'value': '',
                        'valueType': 'UNAVAILABLE',
                        'evidence': 'UNAVAILABLE'
                    },
                    'rawHex': raw.hex()
                }

                # Layer 3 / 4 / 7 Dissection
                if ethertype == 0x0806: # ARP
                    arp_info = dissect_arp(l3_payload)
                    frame_record['protocol'] = 'ARP'
                    frame_record['arp'] = arp_info
                    if arp_info:
                        frame_record['srcIp'] = arp_info['senderIp']
                        frame_record['dstIp'] = arp_info['targetIp']
                        frame_record['summary'] = f"Who has {arp_info['targetIp']}? Tell {arp_info['senderIp']}" if arp_info['opcode'] == 'REQUEST' else f"{arp_info['senderIp']} is at {arp_info['senderMac']}"

                elif ethertype == 0x0800: # IPv4
                    ip_info, ip_proto, l4_payload = dissect_ipv4(l3_payload)
                    if ip_info:
                        frame_record['ipv4'] = ip_info
                        frame_record['srcIp'] = ip_info['srcIp']
                        frame_record['dstIp'] = ip_info['dstIp']

                        if ip_proto == 1: # ICMP
                            icmp_info = dissect_icmp(l4_payload)
                            frame_record['protocol'] = 'ICMP'
                            frame_record['icmp'] = icmp_info
                            if icmp_info:
                                frame_record['summary'] = f"{icmp_info['typeDesc']} (id={icmp_info['identifier']}, seq={icmp_info['sequenceNumber']})"
                                frame_record['urlIntelligence'] = {
                                    'value': ip_info['dstIp'],
                                    'valueType': 'IP_ONLY',
                                    'evidence': 'UNAVAILABLE'
                                }

                        elif ip_proto == 6: # TCP
                            tcp_info, app_payload = dissect_tcp(l4_payload)
                            frame_record['protocol'] = 'TCP'
                            frame_record['tcp'] = tcp_info
                            if tcp_info:
                                frame_record['srcPort'] = tcp_info['srcPort']
                                frame_record['dstPort'] = tcp_info['dstPort']
                                flags_str = " ".join(tcp_info['flagNames'])
                                frame_record['summary'] = f"{tcp_info['srcPort']} -> {tcp_info['dstPort']} [{flags_str}] Seq={tcp_info['seq']} Ack={tcp_info['ack']} Win={tcp_info['windowSize']} Len={tcp_info['payloadLength']}"

                                # Layer 7: HTTP
                                http_info = dissect_http(app_payload)
                                if http_info:
                                    frame_record['protocol'] = 'HTTP'
                                    frame_record['http'] = http_info
                                    if http_info.get('type') == 'REQUEST':
                                        host = http_info.get('host') or ip_info['dstIp']
                                        full_url = f"http://{host}{http_info.get('uri', '/')}"
                                        frame_record['summary'] = f"{http_info.get('method')} {http_info.get('uri')} (Host: {host})"
                                        frame_record['urlIntelligence'] = {
                                            'value': full_url,
                                            'valueType': 'FULL_URL',
                                            'evidence': 'DIRECTLY_OBSERVED'
                                        }
                                        frame_record['urlResolution'] = {
                                            'hostnameOrUrl': full_url,
                                            'method': 'HTTP Host',
                                            'confidence': 'HIGH',
                                            'source': f"HTTP 1.x Host Request Header ({host})",
                                            'isLinkable': True,
                                            'linkUrl': full_url
                                        }
                                    else:
                                        frame_record['summary'] = f"HTTP/1.1 {http_info.get('status')} {http_info.get('statusText')}"

                                # Layer 7: TLS
                                tls_info = dissect_tls(app_payload)
                                if tls_info:
                                    frame_record['protocol'] = 'TLS'
                                    frame_record['tls'] = tls_info
                                    if 'sni' in tls_info:
                                        sni_val = tls_info['sni']
                                        frame_record['summary'] = f"TLS ClientHello (SNI: {sni_val})"
                                        frame_record['urlIntelligence'] = {
                                            'value': sni_val,
                                            'valueType': 'HOSTNAME',
                                            'evidence': 'Observed TLS hostname'
                                        }
                                        frame_record['urlResolution'] = {
                                            'hostnameOrUrl': f"https://{sni_val}/",
                                            'method': 'SNI',
                                            'confidence': 'HIGH',
                                            'source': 'TLS ClientHello Server Name Indication',
                                            'isLinkable': True,
                                            'linkUrl': f"https://{sni_val}/"
                                        }
                                    else:
                                        frame_record['summary'] = f"TLS {tls_info.get('contentType', 'Record')} ({tls_info.get('recordVersion', '')})"

                        elif ip_proto == 17: # UDP
                            udp_info, app_payload = dissect_udp(l4_payload)
                            frame_record['protocol'] = 'UDP'
                            frame_record['udp'] = udp_info
                            if udp_info:
                                frame_record['srcPort'] = udp_info['srcPort']
                                frame_record['dstPort'] = udp_info['dstPort']
                                frame_record['summary'] = f"UDP {udp_info['srcPort']} -> {udp_info['dstPort']} Len={udp_info['length']}"

                                # Layer 7: DNS
                                if udp_info['srcPort'] == 53 or udp_info['dstPort'] == 53:
                                    dns_info = dissect_dns(app_payload)
                                    if dns_info:
                                        frame_record['protocol'] = 'DNS'
                                        frame_record['dns'] = dns_info
                                        q_name = dns_info['questions'][0]['name'] if dns_info['questions'] else ''
                                        q_type = dns_info['questions'][0]['type'] if dns_info['questions'] else 'A'
                                        if dns_info['isResponse']:
                                            ans_str = ", ".join(f"{a['type']} {a['data']}" for a in dns_info['answers'][:2])
                                            frame_record['summary'] = f"Standard query response {dns_info['transactionId']} {q_name}: {ans_str or 'NXDomain'}"
                                            frame_record['urlIntelligence'] = {
                                                'value': q_name,
                                                'valueType': 'HOSTNAME',
                                                'evidence': 'Observed DNS answer'
                                            }
                                            frame_record['urlResolution'] = {
                                                'hostnameOrUrl': q_name,
                                                'method': 'DNS-correlated',
                                                'confidence': 'HIGH',
                                                'source': f"Captured DNS Response (Query: {q_name})",
                                                'isLinkable': False,
                                                'linkUrl': ''
                                            }
                                        else:
                                            frame_record['summary'] = f"Standard query {dns_info['transactionId']} {q_type} {q_name}"
                                            frame_record['urlIntelligence'] = {
                                                'value': q_name,
                                                'valueType': 'HOSTNAME',
                                                'evidence': 'Observed DNS query'
                                            }
                                            frame_record['urlResolution'] = {
                                                'hostnameOrUrl': q_name,
                                                'method': 'DNS-correlated',
                                                'confidence': 'HIGH',
                                                'source': f"Captured DNS Query ({q_name})",
                                                'isLinkable': False,
                                                'linkUrl': ''
                                            }

                                # Layer 7: QUIC
                                elif udp_info['dstPort'] == 443 or udp_info['srcPort'] == 443:
                                    quic_info = dissect_quic(app_payload)
                                    if quic_info:
                                        frame_record['protocol'] = 'QUIC'
                                        frame_record['quic'] = quic_info
                elif ethertype == 0x86dd: # IPv6
                    ip6_info, next_hdr, l4_payload = dissect_ipv6(l3_payload)
                    if ip6_info:
                        frame_record['ipv6'] = ip6_info
                        frame_record['srcIp'] = ip6_info['srcIp']
                        frame_record['dstIp'] = ip6_info['dstIp']
                        frame_record['protocol'] = 'IPv6'

                        if next_hdr == 58: # ICMPv6
                            frame_record['protocol'] = 'ICMPv6'
                            if len(l4_payload) >= 4:
                                icmp6_type = l4_payload[0]
                                icmp6_code = l4_payload[1]
                                icmp6_desc = {
                                    128: "ICMPv6 Echo Request",
                                    129: "ICMPv6 Echo Reply",
                                    135: "Neighbor Solicitation",
                                    136: "Neighbor Advertisement",
                                    133: "Router Solicitation",
                                    134: "Router Advertisement"
                                }.get(icmp6_type, f"ICMPv6 Type {icmp6_type}")
                                frame_record['summary'] = f"{icmp6_desc} (Code: {icmp6_code})"

                        elif next_hdr == 6: # TCP over IPv6
                            tcp_info, app_payload = dissect_tcp(l4_payload)
                            frame_record['protocol'] = 'TCP'
                            frame_record['tcp'] = tcp_info
                            if tcp_info:
                                frame_record['srcPort'] = tcp_info['srcPort']
                                frame_record['dstPort'] = tcp_info['dstPort']
                                flags_str = " ".join(tcp_info['flagNames'])
                                frame_record['summary'] = f"{tcp_info['srcPort']} -> {tcp_info['dstPort']} [{flags_str}] Seq={tcp_info['seq']} Ack={tcp_info['ack']} Win={tcp_info['windowSize']}"

                        elif next_hdr == 17: # UDP over IPv6
                            udp_info, app_payload = dissect_udp(l4_payload)
                            frame_record['protocol'] = 'UDP'
                            frame_record['udp'] = udp_info
                            if udp_info:
                                frame_record['srcPort'] = udp_info['srcPort']
                                frame_record['dstPort'] = udp_info['dstPort']
                                frame_record['summary'] = f"UDP {udp_info['srcPort']} -> {udp_info['dstPort']} Len={udp_info['length']}"
                                if udp_info['srcPort'] == 53 or udp_info['dstPort'] == 53:
                                    dns_info = dissect_dns(app_payload)
                                    if dns_info:
                                        frame_record['protocol'] = 'DNS'
                                        frame_record['dns'] = dns_info
                                        q_name = dns_info['questions'][0]['name'] if dns_info['questions'] else ''
                                        frame_record['summary'] = f"DNS query {q_name}" if not dns_info['isResponse'] else f"DNS response {q_name}"
                sys.stdout.write(json.dumps(frame_record) + "\n")
                sys.stdout.flush()

                if args.count > 0 and packet_counter >= args.count:
                    break

            elif res == 0:
                # Timeout, no packet
                time.sleep(0.005)
            elif res == -1:
                # Error
                sys.stderr.write(json.dumps({"error": "pcap_next_ex returned error", "detail": wpcap.pcap_geterr(handle)}) + "\n")
                sys.stderr.flush()
                break

    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        stats_payload = {
            "event": "CAPTURE_STOPPED",
            "totalCaptured": packet_counter
        }
        try:
            ps = pcap_stat()
            if wpcap.pcap_stats(handle, ctypes.byref(ps)) == 0:
                stats_payload["received"] = ps.ps_recv
                stats_payload["dropped"] = ps.ps_drop
                stats_payload["ifdrop"] = ps.ps_ifdrop
        except Exception:
            pass
        wpcap.pcap_close(handle)
        sys.stdout.write(json.dumps(stats_payload) + "\n")
        sys.stdout.flush()

if __name__ == '__main__':
    main()
