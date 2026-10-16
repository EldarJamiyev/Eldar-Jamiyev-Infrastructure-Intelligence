import ctypes
import time

def test_capture():
    wpcap = ctypes.cdll.LoadLibrary(r'C:\Windows\System32\Npcap\wpcap.dll')

    class timeval(ctypes.Structure):
        _fields_ = [
            ('tv_sec', ctypes.c_long),
            ('tv_usec', ctypes.c_long)
        ]

    class pcap_pkthdr(ctypes.Structure):
        _fields_ = [
            ('ts', timeval),
            ('caplen', ctypes.c_uint32),
            ('len', ctypes.c_uint32)
        ]

    # Explicit ctypes signatures for 64-bit pointers
    wpcap.pcap_open_live.restype = ctypes.c_void_p
    wpcap.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]

    wpcap.pcap_next_ex.restype = ctypes.c_int
    wpcap.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))
    ]

    wpcap.pcap_close.argtypes = [ctypes.c_void_p]

    device = b'\\Device\\NPF_{92CDF319-BC46-4389-812A-B4C8605EE900}'
    errbuf = ctypes.create_string_buffer(256)

    handle = wpcap.pcap_open_live(device, 65535, 1, 1000, errbuf)
    if not handle:
        print("Failed to open device:", errbuf.value.decode())
        return

    print("Successfully opened live 64-bit capture on Intel(R) Ethernet Connection (17) I219-LM!")

    header = ctypes.POINTER(pcap_pkthdr)()
    data = ctypes.POINTER(ctypes.c_ubyte)()

    packets_captured = 0
    start = time.time()
    while packets_captured < 5 and (time.time() - start < 5):
        res = wpcap.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(data))
        if res == 1:
            hdr = header.contents
            pkt_len = hdr.caplen
            byte_arr = bytes([data[i] for i in range(min(pkt_len, 34))])
            print(f"Captured Real Frame #{packets_captured + 1}: len={hdr.len}, caplen={hdr.caplen}, hex={byte_arr.hex()[:40]}...")
            packets_captured += 1
        elif res == 0:
            time.sleep(0.01)
        elif res == -1:
            break

    print(f"Total packets captured: {packets_captured}")
    wpcap.pcap_close(handle)

if __name__ == '__main__':
    test_capture()
