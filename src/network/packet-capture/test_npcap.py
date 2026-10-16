import ctypes
import sys

def main():
    try:
        wpcap = ctypes.cdll.LoadLibrary(r'C:\Windows\System32\Npcap\wpcap.dll')
    except Exception as e:
        print("Failed to load wpcap.dll:", e)
        return

    class pcap_if(ctypes.Structure):
        pass

    pcap_if._fields_ = [
        ('next', ctypes.POINTER(pcap_if)),
        ('name', ctypes.c_char_p),
        ('description', ctypes.c_char_p),
        ('addresses', ctypes.c_void_p),
        ('flags', ctypes.c_uint)
    ]

    alldevs = ctypes.POINTER(pcap_if)()
    errbuf = ctypes.create_string_buffer(256)

    res = wpcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf)
    if res != 0:
        print("pcap_findalldevs error:", errbuf.value.decode('utf-8', 'ignore'))
        return

    curr = alldevs
    count = 0
    while curr:
        dev = curr.contents
        name = dev.name.decode('utf-8', 'ignore') if dev.name else ''
        desc = dev.description.decode('utf-8', 'ignore') if dev.description else ''
        print(f"[{count}] {name} => {desc}")
        curr = dev.next
        count += 1

    print(f"Total Npcap devices found: {count}")
    wpcap.pcap_freealldevs(alldevs)

if __name__ == '__main__':
    main()
