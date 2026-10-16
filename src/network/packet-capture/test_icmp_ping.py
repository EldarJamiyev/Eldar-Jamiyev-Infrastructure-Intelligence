import ctypes
import time
import subprocess
import threading

def test_icmp_ping():
    wpcap = ctypes.cdll.LoadLibrary(r'C:\Windows\System32\Npcap\wpcap.dll')

    class timeval(ctypes.Structure):
        _fields_ = [('tv_sec', ctypes.c_long), ('tv_usec', ctypes.c_long)]

    class pcap_pkthdr(ctypes.Structure):
        _fields_ = [('ts', timeval), ('caplen', ctypes.c_uint32), ('len', ctypes.c_uint32)]

    class bpf_program(ctypes.Structure):
        _fields_ = [('bf_len', ctypes.c_uint), ('bf_insns', ctypes.c_void_p)]

    wpcap.pcap_open_live.restype = ctypes.c_void_p
    wpcap.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    wpcap.pcap_next_ex.restype = ctypes.c_int
    wpcap.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    wpcap.pcap_compile.restype = ctypes.c_int
    wpcap.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(bpf_program), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
    wpcap.pcap_setfilter.restype = ctypes.c_int
    wpcap.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(bpf_program)]
    wpcap.pcap_close.argtypes = [ctypes.c_void_p]

    device = b'\\Device\\NPF_{92CDF319-BC46-4389-812A-B4C8605EE900}'
    errbuf = ctypes.create_string_buffer(256)
    handle = wpcap.pcap_open_live(device, 65535, 1, 100, errbuf)
    if not handle:
        print("Failed to open Npcap handle:", errbuf.value.decode())
        return

    # Compile BPF filter for ICMP
    bpf = bpf_program()
    filter_expr = b'icmp'
    if wpcap.pcap_compile(handle, ctypes.byref(bpf), filter_expr, 1, 0xFFFFFFFF) == 0:
        wpcap.pcap_setfilter(handle, ctypes.byref(bpf))
        print("BPF Filter 'icmp' successfully applied!")

    captured_icmp = []

    def capture_loop():
        header = ctypes.POINTER(pcap_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        start = time.time()
        while time.time() - start < 4:
            res = wpcap.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(data))
            if res == 1:
                hdr = header.contents
                raw = bytes([data[i] for i in range(hdr.caplen)])
                # Parse IPv4 & ICMP
                if len(raw) >= 34 and raw[12:14] == b'\x08\x00' and raw[23] == 1:
                    src_ip = f"{raw[26]}.{raw[27]}.{raw[28]}.{raw[29]}"
                    dst_ip = f"{raw[30]}.{raw[31]}.{raw[32]}.{raw[33]}"
                    icmp_type = raw[34]
                    icmp_code = raw[35]
                    type_str = "Echo Request" if icmp_type == 8 else ("Echo Reply" if icmp_type == 0 else f"Type {icmp_type}")
                    captured_icmp.append({
                        'src': src_ip,
                        'dst': dst_ip,
                        'type': icmp_type,
                        'code': icmp_code,
                        'type_str': type_str,
                        'len': hdr.len
                    })
                    print(f"Captured ICMP on Wire: {src_ip} -> {dst_ip} [{type_str}] (Code: {icmp_code}, Len: {hdr.len} bytes)")
            elif res == 0:
                time.sleep(0.01)

    t = threading.Thread(target=capture_loop)
    t.start()
    time.sleep(0.5)

    print("Launching ping 8.8.8.8...")
    subprocess.run(["ping", "-n", "1", "8.8.8.8"], capture_output=True, text=True)

    t.join()
    wpcap.pcap_close(handle)
    print(f"Total ICMP frames captured from wire: {len(captured_icmp)}")

if __name__ == '__main__':
    test_icmp_ping()
