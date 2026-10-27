/**
 * EJII Learning Center — Network Academy Curriculum (CCNA & Network Administration)
 * 4 Courses, 12 Modules, 36 Substantive Lessons with Worked Examples, Code/Config Blocks,
 * Original Diagrams, Knowledge Checks, and Lab Integrations.
 */

'use strict';

const NETWORK_COURSES = [
  {
    id: 'network-fundamentals',
    trackId: 'network',
    slug: 'network-fundamentals',
    title: 'Network Fundamentals & Architecture',
    subtitle: 'OSI 7-Layer Model, TCP/IP Protocol Suite, Ethernet & Network Diagnostics',
    description: 'Master foundational computer networking concepts, physical transmission, framing, and systematic diagnostic methodologies.',
    level: 'beginner',
    estimatedMinutes: 240,
    accent: '#0284C7',
    objectives: [
      'Understand the 7 layers of the OSI model and the 4 layers of the TCP/IP suite.',
      'Explain Ethernet frame structure, MAC learning, and broadcast domain boundaries.',
      'Apply structured ICMP and ARP troubleshooting workflows to resolve connectivity issues.'
    ],
    moduleIds: ['net-mod-models', 'net-mod-ethernet', 'net-mod-troubleshooting'],
    prerequisites: []
  },
  {
    id: 'ip-addressing',
    trackId: 'network',
    slug: 'ip-addressing',
    title: 'IP Addressing, Subnetting & IPv6',
    subtitle: 'Binary Math, CIDR, VLSM Design & Modern IPv6 Architecture',
    description: 'Learn step-by-step IPv4 subnet boundary calculations, Variable-Length Subnet Masking (VLSM), and next-generation IPv6 deployment.',
    level: 'beginner',
    estimatedMinutes: 300,
    accent: '#2563EB',
    objectives: [
      'Convert IPv4 addresses between dotted-decimal and binary representation.',
      'Calculate network, broadcast, and host range boundaries using CIDR prefix notation.',
      'Design efficient hierarchical subnets with VLSM and understand IPv6 address types.'
    ],
    moduleIds: ['net-mod-ipv4-binary', 'net-mod-subnet-calc', 'net-mod-ipv6'],
    prerequisites: ['network-fundamentals']
  },
  {
    id: 'switching-routing',
    trackId: 'network',
    slug: 'switching-routing',
    title: 'Switching, VLANs & Dynamic Routing',
    subtitle: '802.1Q Trunking, Spanning Tree (STP), EtherChannel & OSPF Routing',
    description: 'Configure and troubleshoot enterprise campus networks, VLAN segmentation, inter-VLAN routing, and link-state routing protocols.',
    level: 'intermediate',
    estimatedMinutes: 360,
    accent: '#4F46E5',
    objectives: [
      'Segment enterprise traffic using VLANs, 802.1Q trunks, and inter-VLAN routing.',
      'Prevent bridging loops using Spanning Tree Protocol (STP) and bundle links with LACP.',
      'Evaluate routing tables using Longest-Prefix Match and configure single-area OSPFv2.'
    ],
    moduleIds: ['net-mod-vlans', 'net-mod-stp-lacp', 'net-mod-routing'],
    prerequisites: ['ip-addressing']
  },
  {
    id: 'network-services',
    trackId: 'network',
    slug: 'network-services',
    title: 'Network Services, Security & Automation',
    subtitle: 'DHCP, DNS, NAT, Access Control Lists (ACL), WLAN & Programmability',
    description: 'Deploy critical infrastructure IP services, harden access with ACLs and port security, and introduce modern network automation with Python.',
    level: 'intermediate',
    estimatedMinutes: 320,
    accent: '#0D9488',
    objectives: [
      'Configure and troubleshoot essential IP services including DHCP, DNS, NTP, and NAT/PAT.',
      'Implement traffic filtering with standard/extended ACLs and secure physical switchports.',
      'Explain network management telemetry and program network devices with RESTCONF and Python.'
    ],
    moduleIds: ['net-mod-ip-services', 'net-mod-net-security', 'net-mod-net-automation'],
    prerequisites: ['switching-routing']
  }
];

const NETWORK_MODULES = [
  // Course 1 Modules
  {
    id: 'net-mod-models',
    courseId: 'network-fundamentals',
    title: 'Module 1: Network Models & Architecture',
    description: 'Theoretical foundations of layered networking: OSI reference model and TCP/IP encapsulation.',
    lessonIds: ['net-osi-model', 'net-tcp-ip-suite', 'net-l2-l3-boundary']
  },
  {
    id: 'net-mod-ethernet',
    courseId: 'network-fundamentals',
    title: 'Module 2: Ethernet & Switching Basics',
    description: 'Physical layer signaling, framing, MAC address table population, and collision/broadcast boundaries.',
    lessonIds: ['net-ethernet-frames', 'net-mac-learning', 'net-broadcast-domains']
  },
  {
    id: 'net-mod-troubleshooting',
    courseId: 'network-fundamentals',
    title: 'Module 3: Diagnostic Methodology & Probing',
    description: 'Systematic network triage using ICMP ping, traceroute, and ARP inspection.',
    lessonIds: ['net-ping-traceroute', 'net-arp-resolution', 'net-structured-triage']
  },

  // Course 2 Modules
  {
    id: 'net-mod-ipv4-binary',
    courseId: 'ip-addressing',
    title: 'Module 1: IPv4 & Binary Foundations',
    description: 'Anatomy of 32-bit IPv4 addresses, positional binary math, and subnet masks.',
    lessonIds: ['net-ipv4-anatomy', 'net-binary-math', 'net-classless-cidr']
  },
  {
    id: 'net-mod-subnet-calc',
    courseId: 'ip-addressing',
    title: 'Module 2: Subnet Boundaries & Calculations',
    description: 'Fast subnet boundary math, magic number calculation, and Variable-Length Subnet Masking (VLSM).',
    lessonIds: ['net-subnet-step-by-step', 'net-magic-number', 'net-vlsm-design']
  },
  {
    id: 'net-mod-ipv6',
    courseId: 'ip-addressing',
    title: 'Module 3: IPv6 Fundamentals & Addressing',
    description: '128-bit IPv6 architecture, address notation, compression rules, and SLAAC/NDP discovery.',
    lessonIds: ['net-ipv6-structure', 'net-ipv6-unicast-multicast', 'net-ndp-slaac']
  },

  // Course 3 Modules
  {
    id: 'net-mod-vlans',
    courseId: 'switching-routing',
    title: 'Module 1: VLANs, 802.1Q & Inter-VLAN Routing',
    description: 'Traffic isolation using Virtual LANs, 802.1Q frame tagging, and router-on-a-stick topology.',
    lessonIds: ['net-vlan-segmentation', 'net-8021q-trunking', 'net-inter-vlan-routing']
  },
  {
    id: 'net-mod-stp-lacp',
    courseId: 'switching-routing',
    title: 'Module 2: Spanning Tree & Link Aggregation',
    description: 'Loop prevention with Spanning Tree (802.1D/802.1w) and bandwidth bundling with LACP (802.3ad).',
    lessonIds: ['net-stp-fundamentals', 'net-rstp-convergence', 'net-etherchannel-lacp']
  },
  {
    id: 'net-mod-routing',
    courseId: 'switching-routing',
    title: 'Module 3: Routing Tables & Dynamic Protocols',
    description: 'Longest-prefix matching, administrative distance, static routes, and single-area OSPFv2.',
    lessonIds: ['net-routing-table-lookup', 'net-static-default-routing', 'net-ospf-single-area']
  },

  // Course 4 Modules
  {
    id: 'net-mod-ip-services',
    courseId: 'network-services',
    title: 'Module 1: Core Infrastructure IP Services',
    description: 'Deploying and diagnosing DHCP DORA handshakes, recursive DNS, and NAT/PAT translation.',
    lessonIds: ['net-dhcp-operation', 'net-dns-resolution', 'net-nat-pat']
  },
  {
    id: 'net-mod-net-security',
    courseId: 'network-services',
    title: 'Module 2: Security & Access Control',
    description: 'Packet filtering with Standard/Extended ACLs, port security hardening, and WLAN security.',
    lessonIds: ['net-standard-extended-acls', 'net-port-security', 'net-wireless-fundamentals']
  },
  {
    id: 'net-mod-net-automation',
    courseId: 'network-services',
    title: 'Module 3: Automation, Monitoring & APIs',
    description: 'Network management telemetry with SNMP/Syslog, and programmable APIs with RESTCONF and Python.',
    lessonIds: ['net-snmp-syslog-ntp', 'net-restconf-netconf', 'net-python-automation']
  }
];

const NETWORK_LESSONS = [
  // --- Course 1: Network Fundamentals ---
  // Module 1.1: Models
  {
    id: 'net-osi-model',
    courseId: 'network-fundamentals',
    moduleId: 'net-mod-models',
    trackId: 'network',
    slug: 'osi-7-layer-model',
    title: 'The OSI 7-Layer Reference Model',
    difficulty: 'beginner',
    estimatedMinutes: 20,
    objectives: [
      'Identify each layer of the OSI model from Layer 1 Physical to Layer 7 Application.',
      'Explain the distinct responsibility of each layer in end-to-end data communication.',
      'Identify the Protocol Data Unit (PDU) name associated with each OSI layer.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Why Layered Networking Exists',
        content: 'The Open Systems Interconnection (OSI) reference model, developed by the ISO in 1984, provides an abstract architectural framework for computer networking. By decomposing communication into seven independent layers, vendors can build hardware and software that interoperate seamlessly. A physical fiber optic transceiver operating at Layer 1 does not need to know whether the application payload at Layer 7 is an HTTP GET request or an SSH cryptographic exchange.'
      },
      {
        type: 'table',
        heading: 'The 7 OSI Layers & Associated PDUs',
        headers: ['Layer #', 'Layer Name', 'PDU Name', 'Primary Function', 'Key Examples'],
        rows: [
          ['7', 'Application', 'Data', 'Network service interface for applications', 'HTTP, DNS, SSH, SNMP'],
          ['6', 'Presentation', 'Data', 'Data syntax, formatting, encryption & compression', 'TLS, JSON, ASCII, JPEG'],
          ['5', 'Session', 'Data', 'Dialog control, session establishment & teardown', 'RPC, NetBIOS, Sockets'],
          ['4', 'Transport', 'Segment / Datagram', 'End-to-end reliability, multiplexing & ports', 'TCP, UDP, QUIC'],
          ['3', 'Network', 'Packet', 'Logical addressing and path determination (routing)', 'IPv4, IPv6, ICMP, OSPF'],
          ['2', 'Data Link', 'Frame', 'Physical framing, MAC addressing & error detection', 'Ethernet (802.3), Wi-Fi (802.11)'],
          ['1', 'Physical', 'Bit', 'Transmission of raw binary bits over physical media', 'Cat6 copper, Fiber optics, RF']
        ]
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'Mnemonic for Memorization',
        content: 'Bottom-up (L1 to L7): "Please Do Not Throw Sausage Pizza Away" (Physical, Data Link, Network, Transport, Session, Presentation, Application).'
      },
      {
        type: 'diagram',
        diagramType: 'osi-model',
        caption: 'OSI 7-Layer Model stack showing PDU names and bidirectional traversal during communication.'
      },
      {
        type: 'knowledge-check',
        question: 'Which OSI layer is responsible for segment retransmission, sequencing, and flow control?',
        options: ['Layer 2 (Data Link)', 'Layer 3 (Network)', 'Layer 4 (Transport)', 'Layer 5 (Session)'],
        correctIndex: 2,
        explanation: 'Layer 4 (Transport), exemplified by TCP, handles end-to-end reliability, sequence numbering, acknowledgment packets, and sliding-window flow control.'
      }
    ],
    quizId: 'quiz-network-fundamentals',
    labIds: ['net-packet-journey'],
    prevLessonId: null,
    nextLessonId: 'net-tcp-ip-suite'
  },
  {
    id: 'net-tcp-ip-suite',
    courseId: 'network-fundamentals',
    moduleId: 'net-mod-models',
    trackId: 'network',
    slug: 'tcp-ip-protocol-suite',
    title: 'The TCP/IP Suite & Data Encapsulation',
    difficulty: 'beginner',
    estimatedMinutes: 20,
    objectives: [
      'Compare the 4-layer TCP/IP architectural model with the 7-layer OSI model.',
      'Explain the step-by-step encapsulation process from Application data to physical bits.',
      'Distinguish connection-oriented TCP from connectionless UDP.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Pragmatic Standard of the Internet',
        content: 'While OSI remains the premier educational model, the real-world Internet was built on the DARPA TCP/IP model (RFC 1122). TCP/IP collapses the OSI Application, Presentation, and Session layers into a single Application layer, and maps the Data Link and Physical layers to the Network Access (Link) layer.'
      },
      {
        type: 'worked-example',
        heading: 'Step-by-Step Data Encapsulation',
        steps: [
          {
            title: '1. Application Layer (User Data)',
            content: 'The user types a web address. The browser crafts an HTTP GET request payload.'
          },
          {
            title: '2. Transport Layer (Segment Header Added)',
            content: 'TCP attaches a 20-byte header with Source Port (e.g. 52412) and Destination Port (443), along with sequence numbers.'
          },
          {
            title: '3. Network Layer (Packet Header Added)',
            content: 'IP attaches a 20-byte IPv4 header containing Source IP (192.168.1.50) and Destination IP (140.82.121.4).'
          },
          {
            title: '4. Data Link Layer (Frame Header & Trailer Added)',
            content: 'Ethernet prepends a 14-byte header (Dest MAC, Source MAC, EtherType 0x0800) and appends a 4-byte FCS trailer.'
          },
          {
            title: '5. Physical Layer (Bit Encoding)',
            content: 'The completed frame is encoded into electrical pulses, optical blinks, or radio waves onto the wire.'
          }
        ]
      },
      {
        type: 'code',
        language: 'text',
        title: 'TCP vs UDP Header Comparison',
        content: `TCP Header (20 Bytes minimum):
[Source Port: 16b] [Dest Port: 16b]
[Sequence Number: 32b]
[Acknowledgment Number: 32b]
[Data Offset: 4b][Flags: 9b][Window Size: 16b]
[Checksum: 16b][Urgent Pointer: 16b]

UDP Header (8 Bytes total - Lightweight & Low Latency):
[Source Port: 16b] [Dest Port: 16b]
[Length: 16b]      [Checksum: 16b]`
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'Common Mistake',
        content: 'Do not assume TCP is always "better" than UDP because it has acknowledgments. For real-time streaming, voice (VoIP), and online gaming, UDP is essential because retransmitting stale audio packets produces jarring audio glitches rather than smooth playback.'
      }
    ],
    quizId: 'quiz-network-fundamentals',
    labIds: ['net-packet-journey'],
    prevLessonId: 'net-osi-model',
    nextLessonId: 'net-l2-l3-boundary'
  },
  {
    id: 'net-l2-l3-boundary',
    courseId: 'network-fundamentals',
    moduleId: 'net-mod-models',
    trackId: 'network',
    slug: 'l2-l3-boundary',
    title: 'Layer 2 Framing vs Layer 3 Routing Boundaries',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Understand why MAC addresses are local to a single link while IP addresses are end-to-end.',
      'Explain how a default gateway enables communication outside the local broadcast domain.',
      'Trace how frame headers are stripped and rewritten at every router hop.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Local Delivery vs Global Routing',
        content: 'One of the most vital concepts in enterprise networking is the fundamental difference between Layer 2 MAC delivery and Layer 3 IP routing. MAC addresses (e.g. 00:1A:2B:3C:4D:5E) are burned-in physical identifiers used exclusively for delivery inside a single local broadcast domain (LAN or VLAN). They cannot be routed across the Internet. In contrast, IP addresses are hierarchical logical addresses designed for worldwide global path determination.'
      },
      {
        type: 'callout',
        tone: 'info',
        title: 'The Golden Rule of Packet Routing',
        content: 'As a packet travels across multiple routers from client to server: The Source IP and Destination IP remain UNCHANGED end-to-end (absent NAT), but the Source MAC and Destination MAC are STRIPPED and RE-WRITTEN at EVERY router hop!'
      },
      {
        type: 'worked-example',
        heading: 'Hop-by-Hop MAC Rewriting Example',
        steps: [
          {
            title: 'Hop 1: PC1 to Local Router Gateway (R1)',
            content: 'Source IP: 192.168.1.10 | Dest IP: 8.8.8.8\nSource MAC: PC1_MAC | Dest MAC: R1_LAN_MAC'
          },
          {
            title: 'Hop 2: Router R1 to ISP Gateway (R2)',
            content: 'Source IP: 192.168.1.10 | Dest IP: 8.8.8.8 (IPs unchanged!)\nSource MAC: R1_WAN_MAC | Dest MAC: R2_WAN_MAC (MACs completely replaced!)'
          }
        ]
      },
      {
        type: 'knowledge-check',
        question: 'When Host A sends a packet to Host B on a remote subnet across three routers, what happens to the Destination IP address in the packet header?',
        options: [
          'It is changed to the default gateway IP address at each hop.',
          'It remains unchanged as Host B\'s IP address all the way to the destination.',
          'It is replaced by Host B\'s MAC address.',
          'It is decremented by 1 at each router.'
        ],
        correctIndex: 1,
        explanation: 'The Destination IP remains the target destination address end-to-end. Only the Layer 2 Destination MAC address changes at each hop to address the next-hop router interface.'
      }
    ],
    quizId: 'quiz-network-fundamentals',
    labIds: ['net-packet-journey'],
    prevLessonId: 'net-tcp-ip-suite',
    nextLessonId: 'net-ethernet-frames'
  },

  // Module 1.2: Ethernet & Switching
  {
    id: 'net-ethernet-frames',
    courseId: 'network-fundamentals',
    moduleId: 'net-mod-ethernet',
    trackId: 'network',
    slug: 'ethernet-frame-structure',
    title: 'Ethernet Frame Anatomy: Preamble to FCS',
    difficulty: 'beginner',
    estimatedMinutes: 20,
    objectives: [
      'Dissect the fields of an IEEE 802.3 Ethernet frame.',
      'Explain the purpose of the 7-byte Preamble and 1-byte Start Frame Delimiter (SFD).',
      'Understand the EtherType field and common protocol identifiers (0x0800, 0x0806, 0x86DD).'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Structure of Modern Wire Communication',
        content: 'Ethernet II (the framing format standardized in IEEE 802.3) forms the backbone of all modern wired LANs. An Ethernet frame wraps an IP packet with physical delivery headers. Every frame on the wire begins with synchronization bits and ends with a cyclic redundancy check.'
      },
      {
        type: 'table',
        heading: 'Ethernet Frame Field Specification',
        headers: ['Field', 'Length', 'Purpose'],
        rows: [
          ['Preamble', '7 Bytes', 'Alternating 1s and 0s (10101010...) for receiver clock synchronization'],
          ['SFD', '1 Byte', 'Start Frame Delimiter (10101011) indicating data payload begins next'],
          ['Dest MAC', '6 Bytes', '48-bit physical address of the receiving device on this link'],
          ['Source MAC', '6 Bytes', '48-bit physical address of the transmitting network interface (NIC)'],
          ['EtherType', '2 Bytes', 'Identifies upper-layer protocol: 0x0800 (IPv4), 0x0806 (ARP), 0x86DD (IPv6)'],
          ['Payload', '46-1500 Bytes', 'The encapsulated L3 packet. Minimum 46 bytes (padded if necessary)'],
          ['FCS', '4 Bytes', 'Frame Check Sequence: 32-bit CRC calculation to detect bit corruption']
        ]
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'Minimum & Maximum Frame Size',
        content: 'Standard Ethernet frames have a minimum size of 64 bytes (14 header + 46 payload + 4 FCS) to ensure collision detection on legacy half-duplex CSMA/CD. The standard Maximum Transmission Unit (MTU) payload is 1500 bytes, giving a maximum standard frame size of 1518 bytes.'
      }
    ],
    quizId: 'quiz-network-fundamentals',
    labIds: ['net-packet-journey'],
    prevLessonId: 'net-l2-l3-boundary',
    nextLessonId: 'net-mac-learning'
  },
  {
    id: 'net-mac-learning',
    courseId: 'network-fundamentals',
    moduleId: 'net-mod-ethernet',
    trackId: 'network',
    slug: 'mac-address-tables-learning',
    title: 'MAC Address Learning & Transparent Bridging',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Describe how Ethernet switches dynamically populate their Content Addressable Memory (CAM) table.',
      'Explain Forwarding, Filtering, and Flooding operations in a modern switch.',
      'Understand MAC address table aging timers and cache expiration.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'How Switches Make Forwarding Decisions',
        content: 'Unlike ancient network hubs that blindly repeated incoming electrical signals out of every single port, modern Ethernet switches are intelligent Layer 2 bridges. A switch maintains a dynamic Content Addressable Memory (CAM) table mapping MAC addresses to specific physical switchports. Crucially, a switch learns by inspecting the SOURCE MAC address of incoming frames, and forwards by inspecting the DESTINATION MAC address.'
      },
      {
        type: 'worked-example',
        heading: 'The Three Core Switch Operations',
        steps: [
          {
            title: '1. Learning (Inspect Source MAC)',
            content: 'When PC1 (MAC 00:AA) on Port 1 sends a frame, the switch examines the Source MAC and records: "MAC 00:AA is on Port 1" with a 300-second aging timer.'
          },
          {
            title: '2. Forwarding / Filtering (Known Destination)',
            content: 'If the Destination MAC is 00:BB and the switch already knows 00:BB is on Port 3, the switch forwards the frame directly to Port 3 only. All other ports are filtered (silenced).'
          },
          {
            title: '3. Flooding (Unknown Unicast or Broadcast)',
            content: 'If the Destination MAC is not in the table, or is the broadcast address (FF:FF:FF:FF:FF:FF), the switch floods the frame out of all active ports except the ingress port (Port 1).'
          }
        ]
      },
      {
        type: 'terminal-output',
        title: 'Cisco IOS MAC Address Table Inspection',
        content: `Switch# show mac address-table
          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    0014.2201.2345    DYNAMIC     Gi0/1
   1    001b.d4c2.89ab    DYNAMIC     Gi0/2
   1    0050.56a1.1234    DYNAMIC     Gi0/3
Total Mac Addresses for this criterion: 3`
      }
    ],
    quizId: 'quiz-network-fundamentals',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-ethernet-frames',
    nextLessonId: 'net-broadcast-domains'
  },
  {
    id: 'net-broadcast-domains',
    courseId: 'network-fundamentals',
    moduleId: 'net-mod-ethernet',
    trackId: 'network',
    slug: 'broadcast-collision-domains',
    title: 'Collision Domains vs Broadcast Domains',
    difficulty: 'beginner',
    estimatedMinutes: 20,
    objectives: [
      'Define collision domains and explain how full-duplex switches eliminate collisions.',
      'Define broadcast domains and explain why routers break up broadcast domains.',
      'Describe the catastrophic impact of a broadcast storm on network infrastructure.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Containing Electrical and Logical Noise',
        content: 'Two fundamental boundaries govern local network topology: collision domains and broadcast domains. A collision domain is a physical network segment where data packets can collide with one another when sent simultaneously. A broadcast domain is a logical segment where any device broadcasting a frame will be heard by all other devices in that segment.'
      },
      {
        type: 'table',
        heading: 'Domain Comparison Matrix',
        headers: ['Device', 'Collision Domains', 'Broadcast Domains'],
        rows: [
          ['Hub / Repeater', '1 Single Domain for all ports', '1 Single Domain for all ports'],
          ['Switch / Bridge', '1 Separate Domain per port (Full Duplex = 0 collisions)', '1 Single Domain across all ports (unless split by VLANs)'],
          ['Router / Layer 3 Switch', '1 Separate Domain per port', '1 Separate Domain per routed interface (Breaks broadcasts!)']
        ]
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'Broadcast Storms',
        content: 'Because switches flood broadcast frames (FF:FF:FF:FF:FF:FF) out of every port, a physical loop between switches without Spanning Tree Protocol will cause frames to circulate infinitely, multiplying exponentially until switch CPU reaches 100% and network links saturate completely.'
      }
    ],
    quizId: 'quiz-network-fundamentals',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-mac-learning',
    nextLessonId: 'net-ping-traceroute'
  },

  // Module 1.3: Diagnostics
  {
    id: 'net-ping-traceroute',
    courseId: 'network-fundamentals',
    moduleId: 'net-mod-troubleshooting',
    trackId: 'network',
    slug: 'icmp-ping-traceroute-mechanics',
    title: 'ICMP Diagnostics: Ping & Traceroute Deep Dive',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Explain the mechanics of ICMP Echo Request (Type 8) and Echo Reply (Type 0).',
      'Describe how traceroute manipulates the IP Time-To-Live (TTL) field to map network hops.',
      'Interpret common ping failure codes: Request Timed Out vs Destination Host Unreachable.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Network Engineer\'s Primary Instruments',
        content: 'The Internet Control Message Protocol (ICMP / RFC 792) provides operational diagnostic and error reporting mechanisms for the IP protocol. ICMP packets are encapsulated directly inside IP datagrams (Protocol number 1). The two most ubiquitous diagnostic tools—ping and traceroute—rely entirely on ICMP mechanics.'
      },
      {
        type: 'worked-example',
        heading: 'How Traceroute Discovers Every Hop',
        steps: [
          {
            title: '1. Packet with TTL = 1',
            content: 'Traceroute sends an IP packet toward the target with TTL set to 1. The first router decrements TTL to 0, drops the packet, and responds with ICMP Type 11 (Time-to-Live Exceeded). Traceroute records Hop 1\'s IP and RTT.'
          },
          {
            title: '2. Packet with TTL = 2',
            content: 'Traceroute sends the next packet with TTL = 2. Hop 1 decrements TTL to 1 and forwards. Hop 2 decrements TTL to 0, drops the packet, and returns ICMP TTL Exceeded. Hop 2 is discovered!'
          },
          {
            title: '3. Reaching Destination',
            content: 'The TTL increments until the packet reaches the target host, which replies with an ICMP Echo Reply (Windows) or Port Unreachable (Linux/Cisco), concluding the trace.'
          }
        ]
      },
      {
        type: 'code',
        language: 'text',
        title: 'Diagnostic Output Analysis',
        content: `C:\\> ping 192.168.1.100
Pinging 192.168.1.100 with 32 bytes of data:
Reply from 192.168.1.1: Destination host unreachable.
(Root Cause: Gateway 192.168.1.1 sent an ARP request for 192.168.1.100, but received NO ARP reply!)

C:\\> ping 10.0.0.50
Pinging 10.0.0.50 with 32 bytes of data:
Request timed out.
(Root Cause: Packet reached the destination or remote firewall, but return path or firewall dropped ICMP)`
      }
    ],
    quizId: 'quiz-network-fundamentals',
    labIds: ['net-packet-journey'],
    prevLessonId: 'net-broadcast-domains',
    nextLessonId: 'net-arp-resolution'
  },
  {
    id: 'net-arp-resolution',
    courseId: 'network-fundamentals',
    moduleId: 'net-mod-troubleshooting',
    trackId: 'network',
    slug: 'arp-protocol-inspection',
    title: 'Address Resolution Protocol (ARP) & Cache Inspection',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Trace the ARP Request (Broadcast) and ARP Reply (Unicast) exchange.',
      'Inspect and clear the local operating system ARP cache.',
      'Explain Gratuitous ARP and the security risks of ARP Poisoning/Spoofing.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Bridging the Logical-Physical Divide',
        content: 'When an operating system prepares to send an IP packet to another host on the local subnet, it knows the destination IP address, but its network card cannot transmit an Ethernet frame without knowing the destination hardware MAC address. Address Resolution Protocol (ARP / RFC 826) provides this vital mapping.'
      },
      {
        type: 'worked-example',
        heading: 'The ARP Resolution Exchange',
        steps: [
          {
            title: '1. ARP Cache Check',
            content: 'Host A (192.168.1.10) wants to talk to Host B (192.168.1.20). Host A first checks its local RAM ARP table. If an entry exists, it sends immediately.'
          },
          {
            title: '2. ARP Request (Broadcast)',
            content: 'If missing, Host A sends an ARP Request: "Who has 192.168.1.20? Tell 192.168.1.10". Target MAC is FF:FF:FF:FF:FF:FF so every host on the switch receives it.'
          },
          {
            title: '3. ARP Reply (Unicast)',
            content: 'Only Host B matches the IP. Host B caches Host A\'s MAC and replies with a unicast ARP Reply directly to Host A: "192.168.1.20 is at 00:11:22:33:44:55".'
          }
        ]
      },
      {
        type: 'terminal-output',
        title: 'Inspecting Local ARP Cache in Windows & Linux',
        content: `C:\\> arp -a
Interface: 192.168.1.15 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.1           f4-6a-92-0b-11-20     dynamic  (Default Gateway)
  192.168.1.50          00-15-5d-01-a2-3f     dynamic  (Local Server)
  192.168.1.255         ff-ff-ff-ff-ff-ff     static   (Broadcast)`
      }
    ],
    quizId: 'quiz-network-fundamentals',
    labIds: ['net-packet-journey'],
    prevLessonId: 'net-ping-traceroute',
    nextLessonId: 'net-structured-triage'
  },
  {
    id: 'net-structured-triage',
    courseId: 'network-fundamentals',
    moduleId: 'net-mod-troubleshooting',
    trackId: 'network',
    slug: 'structured-network-triage',
    title: 'Structured Network Troubleshooting Methodologies',
    difficulty: 'beginner',
    estimatedMinutes: 20,
    objectives: [
      'Compare Top-Down, Bottom-Up, and Divide-and-Conquer diagnostic approaches.',
      'Apply the 7-step Cisco troubleshooting model to real-world incidents.',
      'Document evidence systematically before implementing remediations.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Eliminating Guesswork in Incident Triage',
        content: 'Junior administrators often waste hours randomly restarting routers, modifying IP settings, and plugging in cables. Professional Network Operations Centers (NOC) use formal structured troubleshooting methodologies based on the OSI model.'
      },
      {
        type: 'table',
        heading: 'OSI Diagnostic Approaches',
        headers: ['Methodology', 'Starting Point', 'Best Used When'],
        rows: [
          ['Bottom-Up', 'Layer 1 (Cables, link LEDs, physical optics)', 'Suspected physical damage, newly installed cabling, complete blackout'],
          ['Top-Down', 'Layer 7 (Application test, web interface, DNS)', 'User reports an application error but basic connectivity appears intact'],
          ['Divide-and-Conquer', 'Layer 3 or 4 (Ping / Traceroute to test IP)', 'Fastest method for experienced engineers to instantly cut the problem scope in half']
        ]
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'The Divide-and-Conquer Rule of Thumb',
        content: 'Start at Layer 3 with a ping to the destination IP. If ping responds: Layers 1, 2, and 3 are 100% verified functional! Focus immediately on Layer 4 ports, firewalls, and Layer 7 services. If ping fails: ping 127.0.0.1 (local stack), then ping the default gateway to isolate whether the failure is local or upstream.'
      }
    ],
    quizId: 'quiz-network-fundamentals',
    labIds: ['net-packet-journey'],
    prevLessonId: 'net-arp-resolution',
    nextLessonId: 'net-ipv4-anatomy'
  },

  // --- Course 2: IP Addressing and Subnetting ---
  // Module 2.1: IPv4 & Binary Foundations
  {
    id: 'net-ipv4-anatomy',
    courseId: 'ip-addressing',
    moduleId: 'net-mod-ipv4-binary',
    trackId: 'network',
    slug: 'ipv4-anatomy-dotted-decimal',
    title: 'IPv4 32-Bit Structure, Octets & Dotted Decimal',
    difficulty: 'beginner',
    estimatedMinutes: 20,
    objectives: [
      'Explain the 32-bit binary structure of an IPv4 address.',
      'Understand how 4 octets of 8 bits each form dotted-decimal notation.',
      'Identify private address allocations defined in RFC 1918.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Composition of an IPv4 Address',
        content: 'An IPv4 address is fundamentally a 32-bit unsigned binary integer. Because reading a string of thirty-two ones and zeros (e.g. 11000000101010000001111100000001) is unmanageable for humans, the 32 bits are divided into four groups of 8 bits called OCTETS. Each 8-bit octet is converted into a decimal number between 0 and 255 and separated by dots: 192.168.31.1.'
      },
      {
        type: 'table',
        heading: 'RFC 1918 Private IPv4 Address Space',
        headers: ['Class', 'Private Range', 'CIDR Prefix', 'Total Addresses', 'Common Use Case'],
        rows: [
          ['Class A', '10.0.0.0 – 10.255.255.255', '10.0.0.0/8', '16,777,216', 'Large enterprise networks & cloud VPCs'],
          ['Class B', '172.16.0.0 – 172.31.255.255', '172.16.0.0/12', '1,048,576', 'Mid-size corporate subnets & lab clusters'],
          ['Class C', '192.168.0.0 – 192.168.255.255', '192.168.0.0/16', '65,536', 'Small office / home routers (SOHO)']
        ]
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'RFC 1918 Non-Routable Standard',
        content: 'Private IP addresses are non-routable on the public Internet. Internet Service Provider edge routers will silently drop any packet with a private source or destination IP. To access the Internet, private addresses must undergo Network Address Translation (NAT).'
      }
    ],
    quizId: 'quiz-ip-addressing',
    labIds: ['net-subnetting-trainer'],
    prevLessonId: 'net-structured-triage',
    nextLessonId: 'net-binary-math'
  },
  {
    id: 'net-binary-math',
    courseId: 'ip-addressing',
    moduleId: 'net-mod-ipv4-binary',
    trackId: 'network',
    slug: 'binary-math-conversion',
    title: 'Binary Conversion & Positional Notation for Octets',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Master the 8 positional binary values: 128, 64, 32, 16, 8, 4, 2, 1.',
      'Convert decimal numbers (0-255) to 8-bit binary strings quickly in your head.',
      'Convert 8-bit binary patterns back to decimal.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The 8-Bit Positional Chart',
        content: 'Every octet has 8 bit positions. Each bit represents a power of 2, starting from 2^0 on the far right to 2^7 on the far left. Memorizing this 8-number chart is the single most important skill in IP subnetting.'
      },
      {
        type: 'table',
        heading: 'The 8-Bit Binary Weight Table',
        headers: ['Bit 7', 'Bit 6', 'Bit 5', 'Bit 4', 'Bit 3', 'Bit 2', 'Bit 1', 'Bit 0'],
        rows: [
          ['2^7', '2^6', '2^5', '2^4', '2^3', '2^2', '2^1', '2^0'],
          ['128', '64', '32', '16', '8', '4', '2', '1']
        ]
      },
      {
        type: 'worked-example',
        heading: 'Converting Decimal 192, 168, and 31 to Binary',
        steps: [
          {
            title: 'Converting 192',
            content: '192 >= 128? YES (remainder 64). 64 >= 64? YES (remainder 0). All others 0.\nBinary: 11000000'
          },
          {
            title: 'Converting 168',
            content: '168 >= 128? YES (rem 40). 40 >= 64? NO. 40 >= 32? YES (rem 8). 8 >= 16? NO. 8 >= 8? YES (rem 0).\nBinary: 10101000'
          },
          {
            title: 'Converting 31',
            content: '31 < 128, 64, 32. 31 >= 16 (rem 15). 15 >= 8 (rem 7). 7 >= 4 (rem 3). 3 >= 2 (rem 1). 1 >= 1.\nBinary: 00011111'
          }
        ]
      }
    ],
    quizId: 'quiz-ip-addressing',
    labIds: ['net-subnetting-trainer'],
    prevLessonId: 'net-ipv4-anatomy',
    nextLessonId: 'net-classless-cidr'
  },
  {
    id: 'net-classless-cidr',
    courseId: 'ip-addressing',
    moduleId: 'net-mod-ipv4-binary',
    trackId: 'network',
    slug: 'subnet-masks-cidr-notation',
    title: 'Subnet Masks, Prefix Lengths & CIDR Notation',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Explain how a subnet mask divides an address into Network bits and Host bits.',
      'Interpret Classless Inter-Domain Routing (CIDR) prefix notation (/24, /27, /16).',
      'Perform binary ANDing to extract the network address.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Why an IP Address Alone Is Incomplete',
        content: 'An IP address like 192.168.10.50 by itself is meaningless without a SUBSET MASK. The mask tells devices where the Network portion ends and where the Host portion begins. A subnet mask is a contiguous string of binary 1s followed by contiguous binary 0s. The 1s represent the network bits; the 0s represent host bits.'
      },
      {
        type: 'worked-example',
        heading: 'Binary ANDing in Action',
        steps: [
          {
            title: 'IP Address: 192.168.10.34',
            content: '11000000 . 10101000 . 00001010 . 00100010'
          },
          {
            title: 'Subnet Mask: 255.255.255.224 (/27)',
            content: '11111111 . 11111111 . 11111111 . 11100000'
          },
          {
            title: 'Logical AND Result (1 AND 1 = 1, otherwise 0)',
            content: '11000000 . 10101000 . 00001010 . 00100000 = 192.168.10.32 (Network Address!)'
          }
        ]
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'CIDR Prefix Shorthand',
        content: 'Instead of typing 255.255.255.224, RFC 1519 introduced Classless Inter-Domain Routing (CIDR) slash notation: /27 means exactly 27 contiguous 1s from the left.'
      }
    ],
    quizId: 'quiz-ip-addressing',
    labIds: ['net-subnetting-trainer'],
    prevLessonId: 'net-binary-math',
    nextLessonId: 'net-subnet-step-by-step'
  },

  // Module 2.2: Subnet Boundaries & Calculations
  {
    id: 'net-subnet-step-by-step',
    courseId: 'ip-addressing',
    moduleId: 'net-mod-subnet-calc',
    trackId: 'network',
    slug: 'subnetting-step-by-step',
    title: 'Calculating Network, Broadcast & Usable Host Ranges',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Calculate the Network ID, First Usable, Last Usable, and Broadcast address for any IPv4 prefix.',
      'Explain why 2 addresses are subtracted from total capacity (2^H - 2).',
      'Validate boundary calculations across different octets (/27, /24, /20, /16).'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The 4 Essential Address Milestones',
        content: 'Every IPv4 subnet contains four critical boundaries: The Network Address (all host bits 0), the First Usable Host IP, the Last Usable Host IP, and the Broadcast Address (all host bits 1). Hosts cannot be assigned the Network ID or the Broadcast ID.'
      },
      {
        type: 'worked-example',
        heading: 'Worked Example: 192.168.10.34/27',
        steps: [
          {
            title: 'Step 1: Determine Interesting Octet and Host Bits',
            content: '/27 has 27 network bits and 32 - 27 = 5 host bits. The interesting octet is the 4th octet (27 is between 24 and 32).'
          },
          {
            title: 'Step 2: Calculate Block Size (Magic Number)',
            content: 'Block size = 2^(host bits in that octet) = 2^5 = 32. Alternatively, 256 - 224 = 32.'
          },
          {
            title: 'Step 3: Find Subnet Boundaries',
            content: 'Multiples of 32: 0, 32, 64, 96... Since host is .34, it falls into the 192.168.10.32 subnet.'
          },
          {
            title: 'Step 4: Determine Boundaries',
            content: 'Network Address: 192.168.10.32\nFirst Usable Host: 192.168.10.33\nLast Usable Host: 192.168.10.62\nBroadcast Address: 192.168.10.63 (Next subnet is .64, so .64 - 1 = .63)\nTotal Hosts: 32 | Usable Hosts: 30'
          }
        ]
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'Mandatory Validation Checkpoints',
        content: '• 192.168.10.34/27 -> Network 192.168.10.32\n• 192.168.10.34/24 -> Network 192.168.10.0\n• 10.10.25.5/16 -> Network 10.10.0.0\n• 172.16.2.9/20 -> Network 172.16.0.0'
      }
    ],
    quizId: 'quiz-ip-addressing',
    labIds: ['net-subnetting-trainer'],
    prevLessonId: 'net-classless-cidr',
    nextLessonId: 'net-magic-number'
  },
  {
    id: 'net-magic-number',
    courseId: 'ip-addressing',
    moduleId: 'net-mod-subnet-calc',
    trackId: 'network',
    slug: 'magic-number-method',
    title: 'The "Magic Number" Method for Instant Mental Subnetting',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Calculate subnet boundaries mentally in under 15 seconds without binary conversion.',
      'Use the 256 - Mask value formula to identify block size instantly.',
      'Handle subnets across 2nd, 3rd, and 4th octets (/12 to /30).'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Bypassing Tedious Binary Math',
        content: 'During high-stakes enterprise troubleshooting or certification exams, writing out 32 binary bits takes too long. The "Magic Number" method enables you to determine any subnet boundary in seconds by working exclusively with decimal arithmetic in the "interesting" octet.'
      },
      {
        type: 'worked-example',
        heading: 'Worked Example: 172.16.2.9/20',
        steps: [
          {
            title: '1. Identify Interesting Octet',
            content: '/20 has 20 network bits. Octet 1 = 8 bits, Octet 2 = 16 bits, Octet 3 has 4 bits (16 to 24). The interesting octet is Octet 3!'
          },
          {
            title: '2. Convert /20 to Subnet Mask',
            content: '4 bits turned on in Octet 3: 128 + 64 + 32 + 16 = 240. Mask is 255.255.240.0.'
          },
          {
            title: '3. Magic Number = 256 - 240 = 16',
            content: 'Subnets in Octet 3 jump in increments of 16: 0, 16, 32, 48... Since our IP has 2 in the 3rd octet, it belongs to the 0 block!'
          },
          {
            title: '4. Full Range',
            content: 'Network: 172.16.0.0\nBroadcast: 172.16.15.255 (Next subnet is 172.16.16.0, minus 1)\nUsable: 172.16.0.1 to 172.16.15.254 (4,094 usable hosts!)'
          }
        ]
      }
    ],
    quizId: 'quiz-ip-addressing',
    labIds: ['net-subnetting-trainer'],
    prevLessonId: 'net-subnet-step-by-step',
    nextLessonId: 'net-vlsm-design'
  },
  {
    id: 'net-vlsm-design',
    courseId: 'ip-addressing',
    moduleId: 'net-mod-subnet-calc',
    trackId: 'network',
    slug: 'vlsm-subnet-design',
    title: 'Variable-Length Subnet Masking (VLSM) Strategy',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Explain the efficiency of VLSM over fixed-length subnet masking (FLSM).',
      'Design subnets by allocating from the largest host requirement to the smallest.',
      'Allocate point-to-point router WAN links using /30 or /31 without address waste.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Eliminating Address Waste in Enterprise Architecture',
        content: 'In early networking, Classful routing forced every subnet to share the same subnet mask. If your largest branch needed 50 hosts (/26) and your smallest router link needed only 2 hosts, you still had to assign a /26 to the 2-host link, wasting 60 IP addresses! Variable-Length Subnet Masking (VLSM) allows an administrator to subnet an already subnetted address space, tailoring mask lengths to exact host requirements.'
      },
      {
        type: 'worked-example',
        heading: 'Golden Rule of VLSM Allocation: Largest to Smallest',
        steps: [
          {
            title: 'Requirement Scenario',
            content: 'Starting block: 192.168.1.0/24. Subnets needed: Dept A (100 hosts), Dept B (50 hosts), Dept C (20 hosts), WAN Link (2 hosts).'
          },
          {
            title: '1. Allocate Dept A (100 hosts needed -> /25 = 126 hosts)',
            content: '192.168.1.0/25 (Covers .0 through .127). Remaining space: .128 to .255.'
          },
          {
            title: '2. Allocate Dept B (50 hosts needed -> /26 = 62 hosts)',
            content: '192.168.1.128/26 (Covers .128 through .191). Remaining space: .192 to .255.'
          },
          {
            title: '3. Allocate Dept C (20 hosts needed -> /27 = 30 hosts)',
            content: '192.168.1.192/27 (Covers .192 through .223). Remaining space: .224 to .255.'
          },
          {
            title: '4. Allocate WAN Link (2 hosts needed -> /30 = 2 hosts)',
            content: '192.168.1.224/30 (Covers .224 through .227). Remaining space: .228 to .255 preserved for future expansion!'
          }
        ]
      }
    ],
    quizId: 'quiz-ip-addressing',
    labIds: ['net-subnetting-trainer'],
    prevLessonId: 'net-magic-number',
    nextLessonId: 'net-ipv6-structure'
  },

  // Module 2.3: IPv6 Fundamentals
  {
    id: 'net-ipv6-structure',
    courseId: 'ip-addressing',
    moduleId: 'net-mod-ipv6',
    trackId: 'network',
    slug: 'ipv6-addressing-structure',
    title: '128-Bit IPv6 Addressing, Hexadecimal & Compression',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Describe the 128-bit structure of an IPv6 address organized into 8 hextets.',
      'Apply RFC 5952 compression rules: leading zero suppression and double-colon :: reduction.',
      'Explain why broadcast addresses no longer exist in IPv6.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Next Generation Internet Protocol',
        content: 'With only ~4.3 billion possible addresses, IPv4 address exhaustion became critical in the 2010s. IPv6 (RFC 8200) expands address space to 128 bits, providing approximately 3.4 x 10^38 unique addresses—enough to assign trillions of addresses to every grain of sand on Earth. IPv6 addresses are written in hexadecimal separated by colons into 8 fields of 16 bits called HEXTETS.'
      },
      {
        type: 'worked-example',
        heading: 'RFC 5952 Address Compression Rules',
        steps: [
          {
            title: 'Raw Uncompressed IPv6 Address',
            content: '2001:0db8:0000:0000:0000:0000:0000:0001'
          },
          {
            title: 'Rule 1: Omit Leading Zeros in any Hextet',
            content: '2001:db8:0:0:0:0:0:1 (0000 becomes 0, 0db8 becomes db8)'
          },
          {
            title: 'Rule 2: Compress Longest Contiguous Zeros with Double Colon (::)',
            content: '2001:db8::1 (The :: replaces the 5 contiguous zero hextets. Permitted ONCE per address!)'
          }
        ]
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'No Broadcasts in IPv6',
        content: 'IPv6 completely eliminates broadcast addressing! Instead, all one-to-all communication is replaced with efficient, targeted MULTICAST groups (ff02::), drastically reducing background network noise.'
      }
    ],
    quizId: 'quiz-ip-addressing',
    labIds: ['net-subnetting-trainer'],
    prevLessonId: 'net-vlsm-design',
    nextLessonId: 'net-ipv6-unicast-multicast'
  },
  {
    id: 'net-ipv6-unicast-multicast',
    courseId: 'ip-addressing',
    moduleId: 'net-mod-ipv6',
    trackId: 'network',
    slug: 'ipv6-address-types',
    title: 'GUA, ULA, Link-Local (fe80::) & Multicast (ff02::)',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Differentiate Global Unicast (GUA), Unique Local (ULA), and Link-Local addresses.',
      'Identify standard IPv6 well-known prefixes: 2000::/3, fc00::/7, fe80::/10, ff00::/8.',
      'Explain how IPv6 interfaces always have at least one Link-Local address active.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The IPv6 Address Taxonomy',
        content: 'Unlike IPv4 where an interface typically has only one IP address, an IPv6 interface normally possesses multiple IPv6 addresses simultaneously for different routing scopes.'
      },
      {
        type: 'table',
        heading: 'Key IPv6 Address Scopes & Prefixes',
        headers: ['Address Type', 'Prefix Range', 'Scope', 'IPv4 Equivalent'],
        rows: [
          ['Global Unicast (GUA)', '2000::/3 (2001:... to 3fff:...)', 'Public Internet Routable', 'Public IPv4 Address'],
          ['Unique Local (ULA)', 'fc00::/7 (fd00::/8 commonly)', 'Private Enterprise Internal', 'RFC 1918 Private IP'],
          ['Link-Local (LLA)', 'fe80::/10', 'Single Physical Link Only', '169.254.x.x (APIPA)'],
          ['Loopback', '::1/128', 'Local Host Only', '127.0.0.1'],
          ['Multicast', 'ff00::/8 (ff02:: on-link)', 'Subscribed Group Members', '224.0.0.0/4 Multicast']
        ]
      }
    ],
    quizId: 'quiz-ip-addressing',
    labIds: ['net-subnetting-trainer'],
    prevLessonId: 'net-ipv6-structure',
    nextLessonId: 'net-ndp-slaac'
  },
  {
    id: 'net-ndp-slaac',
    courseId: 'ip-addressing',
    moduleId: 'net-mod-ipv6',
    trackId: 'network',
    slug: 'ndp-slaac-discovery',
    title: 'Neighbor Discovery Protocol (NDP) & SLAAC Auto-Config',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Describe how ICMPv6 Neighbor Discovery Protocol (NDP) replaces ARP.',
      'Explain Neighbor Solicitation (NS) and Neighbor Advertisement (NA) packets.',
      'Describe Stateless Address Autoconfiguration (SLAAC) using Router Advertisements (RA).'
    ],
    sections: [
      {
        type: 'text',
        heading: 'ARP Replacement and Plug-and-Play Addressing',
        content: 'Because IPv6 has no broadcasts, it cannot use ARP. Instead, it utilizes the Neighbor Discovery Protocol (NDP / RFC 4861), which operates via targeted ICMPv6 multicast packets. Furthermore, SLAAC allows a client to configure its own global IPv6 address without needing a DHCP server.'
      },
      {
        type: 'table',
        heading: 'Key NDP ICMPv6 Message Types',
        headers: ['Message Type', 'ICMPv6 Type', 'Purpose'],
        rows: [
          ['Router Solicitation (RS)', '133', 'Client asks: "Are there any routers on this link?" sent to ff02::2 (All Routers)'],
          ['Router Advertisement (RA)', '134', 'Router announces: Prefix, default gateway, and DNS info to ff02::1 (All Nodes)'],
          ['Neighbor Solicitation (NS)', '135', 'Replaces ARP Request: "Who has this IPv6 address?" sent to Solicited-Node Multicast'],
          ['Neighbor Advertisement (NA)', '136', 'Replaces ARP Reply: "I have that IPv6 address; here is my MAC address!"']
        ]
      }
    ],
    quizId: 'quiz-ip-addressing',
    labIds: ['net-subnetting-trainer'],
    prevLessonId: 'net-ipv6-unicast-multicast',
    nextLessonId: 'net-vlan-segmentation'
  },

  // --- Course 3: Switching and Routing ---
  // Module 3.1: VLANs & Trunking
  {
    id: 'net-vlan-segmentation',
    courseId: 'switching-routing',
    moduleId: 'net-mod-vlans',
    trackId: 'network',
    slug: 'vlan-segmentation-access-ports',
    title: 'Virtual LANs (VLANs) & Access Port Configuration',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Explain how VLANs break a single physical switch into multiple isolated broadcast domains.',
      'Configure Cisco IOS switchports in Access mode assigned to specific VLAN IDs (1-4094).',
      'Describe the security and performance benefits of VLAN segmentation.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Logical Separation of Campus Networks',
        content: 'In a flat network without VLANs, all devices connected to all switchports exist in the same broadcast domain. A malware infected workstation sending broadcast scans or an engineer misconfiguring a rogue DHCP server disrupts every department in the building. Virtual Local Area Networks (VLANs / IEEE 802.1Q) partition a physical switch into multiple isolated logical switches. Devices in VLAN 10 (Engineering) cannot communicate with devices in VLAN 20 (Finance) at Layer 2, even if plugged into neighboring ports on the exact same switch!'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Cisco IOS VLAN & Access Port Configuration',
        content: `Switch(config)# vlan 10
Switch(config-vlan)# name ENGINEERING
Switch(config-vlan)# exit

Switch(config)# vlan 20
Switch(config-vlan)# name FINANCE
Switch(config-vlan)# exit

Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# no shutdown`
      }
    ],
    quizId: 'quiz-switching-routing',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-ndp-slaac',
    nextLessonId: 'net-8021q-trunking'
  },
  {
    id: 'net-8021q-trunking',
    courseId: 'switching-routing',
    moduleId: 'net-mod-vlans',
    trackId: 'network',
    slug: '8021q-trunking-allowed-lists',
    title: '802.1Q Frame Tagging, Native VLAN & Allowed Lists',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Explain how 802.1Q trunk links multiplex traffic for dozens of VLANs across a single cable.',
      'Understand the Native VLAN concept and potential VLAN Hopping security vulnerabilities.',
      'Prune and restrict trunk links using switchport trunk allowed vlan.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Multiplexing Multi-VLAN Traffic Across Switches',
        content: 'When an organization has multiple switches, running a dedicated physical cable between switches for every single VLAN is cost-prohibitive. TRUNK LINKS carry traffic for multiple VLANs over a single physical cable by inserting an IEEE 802.1Q 4-byte header tag (TPID 0x8100 + VLAN ID) into every frame. When the frame exits an access port to an end host, the switch strips the tag, keeping tagging transparent to end user devices.'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Configuring a Secure 802.1Q Trunk Link',
        content: `Switch(config)# interface GigabitEthernet0/24
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk native vlan 999
Switch(config-if)# switchport trunk allowed vlan 10,20,30
Switch(config-if)# switchport nonegotiate`
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'Native VLAN Security Warning',
        content: 'The Native VLAN is the single VLAN whose frames are transmitted across a trunk UNTAGGED. By default in Cisco switches, the Native VLAN is VLAN 1. Leaving the Native VLAN as VLAN 1 exposes the network to double-tagging VLAN hopping attacks. Best practice is to set the Native VLAN to an unused dummy VLAN (e.g. VLAN 999) across all switches.'
      }
    ],
    quizId: 'quiz-switching-routing',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-vlan-segmentation',
    nextLessonId: 'net-inter-vlan-routing'
  },
  {
    id: 'net-inter-vlan-routing',
    courseId: 'switching-routing',
    moduleId: 'net-mod-vlans',
    trackId: 'network',
    slug: 'inter-vlan-routing-svi',
    title: 'Inter-VLAN Routing: Router-on-a-Stick vs L3 SVIs',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Configure Router-on-a-Stick (ROAS) using subinterfaces with 802.1Q encapsulation.',
      'Configure Switched Virtual Interfaces (SVIs) on Layer 3 Multilayer Switches.',
      'Compare throughput performance and scalability between ROAS and L3 switching.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Connecting Isolated VLANs at Layer 3',
        content: 'Because VLANs are separate broadcast domains, traffic cannot cross from VLAN 10 to VLAN 20 at Layer 2. To communicate, packets must pass through a Layer 3 routing device. There are two primary architectural designs for Inter-VLAN Routing: Router-on-a-Stick (ROAS) and Multilayer Switch SVIs.'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Router-on-a-Stick Subinterface Configuration',
        content: `Router(config)# interface GigabitEthernet0/0.10
Router(config-subif)# encapsulation dot1Q 10
Router(config-subif)# ip address 192.168.10.1 255.255.255.0

Router(config)# interface GigabitEthernet0/0.20
Router(config-subif)# encapsulation dot1Q 20
Router(config-subif)# ip address 192.168.20.1 255.255.255.0`
      },
      {
        type: 'code',
        language: 'text',
        title: 'Layer 3 Switch SVI Configuration (Hardware Wire-Speed)',
        content: `Switch3850(config)# ip routing
Switch3850(config)# interface vlan 10
Switch3850(config-if)# ip address 192.168.10.1 255.255.255.0
Switch3850(config-if)# no shutdown

Switch3850(config)# interface vlan 20
Switch3850(config-if)# ip address 192.168.20.1 255.255.255.0
Switch3850(config-if)# no shutdown`
      }
    ],
    quizId: 'quiz-switching-routing',
    labIds: ['net-vlan-lab', 'net-routing-explorer'],
    prevLessonId: 'net-8021q-trunking',
    nextLessonId: 'net-stp-fundamentals'
  },

  // Module 3.2: STP & LACP
  {
    id: 'net-stp-fundamentals',
    courseId: 'switching-routing',
    moduleId: 'net-mod-stp-lacp',
    trackId: 'network',
    slug: 'spanning-tree-protocol-8021d',
    title: 'Spanning Tree Protocol (STP 802.1D) & Loop Prevention',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Explain how physical loops cause broadcast storms and MAC table instability.',
      'Describe the Root Bridge election process based on Bridge ID (Priority + MAC).',
      'Identify Root Ports, Designated Ports, and Blocking / Alternate Ports.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Redundancy Without Self-Destruction',
        content: 'Enterprise networks require redundant physical links between switches so that if a single cable is severed or a switch module fails, traffic continues flowing. However, redundant links create Layer 2 LOOPS. Because Ethernet frames lack a TTL field, broadcast frames circulate infinitely. Spanning Tree Protocol (IEEE 802.1D) solves this by building a loop-free logical tree, placing redundant links into a blocking state until a primary link fails.'
      },
      {
        type: 'worked-example',
        heading: 'The Root Bridge Election Process',
        steps: [
          {
            title: '1. Bridge ID (BID) Comparison',
            content: 'Switches exchange Bridge Protocol Data Units (BPDUs). The switch with the LOWEST Bridge ID becomes the Root Bridge. BID = Priority (default 32768) + MAC address.'
          },
          {
            title: '2. Root Ports (RP) Selected',
            content: 'Every non-root switch selects exactly one Root Port—the port with the lowest path cost back to the Root Bridge.'
          },
          {
            title: '3. Designated Ports (DP) & Blocking Ports',
            content: 'On each network segment, the port with the lowest cost to root is Designated (Forwarding). All other redundant ports are set to Blocking (Alternate) to prevent loops.'
          }
        ]
      }
    ],
    quizId: 'quiz-switching-routing',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-inter-vlan-routing',
    nextLessonId: 'net-rstp-convergence'
  },
  {
    id: 'net-rstp-convergence',
    courseId: 'switching-routing',
    moduleId: 'net-mod-stp-lacp',
    trackId: 'network',
    slug: 'rstp-convergence-portfast-bpduguard',
    title: 'Rapid STP (802.1w), PortFast & BPDU Guard',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Compare legacy 802.1D convergence (30-50 seconds) with Rapid STP (802.1w sub-second convergence).',
      'Configure Cisco PortFast on edge ports connecting to workstations and servers.',
      'Enable BPDU Guard to protect access ports against rogue switch insertions.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Accelerating Enterprise Convergence',
        content: 'Legacy 802.1D Spanning Tree took 30 to 50 seconds to transition a blocking port to forwarding through Listening and Learning timers. In modern data centers, a 50-second outage drops thousands of VoIP calls and database sessions. Rapid Spanning Tree Protocol (RSTP / IEEE 802.1w) achieves sub-second failover using proactive proposal/agreement handshakes.'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Cisco IOS PortFast & BPDU Guard Hardening',
        content: `Switch(config)# spanning-tree mode rapid-pvst

Switch(config)# interface range GigabitEthernet0/1 - 20
Switch(config-if-range)# spanning-tree portfast
%Warning: portfast should only be enabled on ports connected to a single host.

Switch(config-if-range)# spanning-tree bpduguard enable
! Shuts down the port immediately (err-disabled) if a rogue switch sends a BPDU!`
      }
    ],
    quizId: 'quiz-switching-routing',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-stp-fundamentals',
    nextLessonId: 'net-etherchannel-lacp'
  },
  {
    id: 'net-etherchannel-lacp',
    courseId: 'switching-routing',
    moduleId: 'net-mod-stp-lacp',
    trackId: 'network',
    slug: 'etherchannel-lacp-aggregation',
    title: 'Link Aggregation (802.3ad LACP) & EtherChannel',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Bundle up to 8 physical links into a single logical Port-Channel interface.',
      'Explain how EtherChannel bypasses Spanning Tree blocking to double or quadruple bandwidth.',
      'Configure Link Aggregation Control Protocol (IEEE 802.3ad LACP).'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Multiplying Bandwidth While Retaining Redundancy',
        content: 'If you connect two switches with two 1 Gbps cables, Spanning Tree will block one of them to prevent a loop, leaving you with only 1 Gbps of usable throughput. EtherChannel (Link Aggregation) bonds up to 8 physical links into a single logical interface (Port-Channel). Spanning Tree views the bundle as a single link, allowing ALL cables to forward traffic simultaneously, providing 2 Gbps, 4 Gbps, or 8 Gbps of aggregated bandwidth with instant link failover.'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Cisco IOS LACP Configuration',
        content: `Switch(config)# interface range GigabitEthernet0/1 - 2
Switch(config-if-range)# channel-group 1 mode active
! Mode active initiates LACP negotiation (802.3ad standard)

Switch(config)# interface port-channel 1
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20,30`
      }
    ],
    quizId: 'quiz-switching-routing',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-rstp-convergence',
    nextLessonId: 'net-routing-table-lookup'
  },

  // Module 3.3: Routing Tables & Dynamic Protocols
  {
    id: 'net-routing-table-lookup',
    courseId: 'switching-routing',
    moduleId: 'net-mod-routing',
    trackId: 'network',
    slug: 'routing-table-longest-prefix-match',
    title: 'Longest-Prefix Match & Administrative Distance',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Trace the router forwarding decision process using Longest-Prefix Match (LPM).',
      'Explain Administrative Distance (AD) and how routers rank competing route sources.',
      'Differentiate route installation into the RIB from packet forwarding in the FIB/CEF.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Routing Table Decision Engine',
        content: 'When a router receives a packet, it consults its Routing Information Base (RIB). A common misconception is that a router chooses routes based on administrative distance or protocol type. In reality, during packet forwarding, LONGEST-PREFIX MATCH ALWAYS WINS! The route with the most specific subnet mask (longest prefix length) matching the destination IP is selected, regardless of where the route came from.'
      },
      {
        type: 'table',
        heading: 'Standard Cisco Administrative Distance (AD) Hierarchy',
        headers: ['Route Source', 'Administrative Distance', 'Trustworthiness'],
        rows: [
          ['Connected Interface', '0', 'Most Trusted (Direct physical attachment)'],
          ['Static Route', '1', 'Explicit administrator configuration'],
          ['eBGP', '20', 'External Border Gateway Protocol'],
          ['EIGRP (Internal)', '90', 'Cisco Advanced Distance Vector'],
          ['OSPF', '110', 'Open Shortest Path First (Link-State standard)'],
          ['IS-IS', '115', 'Intermediate System to Intermediate System'],
          ['RIP', '120', 'Routing Information Protocol (Hop count metric)'],
          ['Unreachable / Discard', '255', 'Untrusted / Do not install']
        ]
      }
    ],
    quizId: 'quiz-switching-routing',
    labIds: ['net-routing-explorer'],
    prevLessonId: 'net-etherchannel-lacp',
    nextLessonId: 'net-static-default-routing'
  },
  {
    id: 'net-static-default-routing',
    courseId: 'switching-routing',
    moduleId: 'net-mod-routing',
    trackId: 'network',
    slug: 'static-default-floating-routes',
    title: 'Static Routes, Floating Routes & Gateway of Last Resort',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Configure standard static routes specifying next-hop IP or exit interface.',
      'Configure a default static route (0.0.0.0/0) as the Gateway of Last Resort.',
      'Deploy floating static routes with elevated Administrative Distance for automated backup.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Deterministic Routing Control',
        content: 'While dynamic routing protocols automatically discover paths, static routing provides absolute administrative control, zero CPU routing overhead, and total link bandwidth preservation. Default routes (0.0.0.0/0) ensure that packets destined for unknown global Internet destinations are forwarded to the upstream ISP gateway.'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Cisco IOS Static & Floating Route Configuration',
        content: `! 1. Standard Static Route to Remote Branch
Router(config)# ip route 10.50.0.0 255.255.0.0 192.168.12.2

! 2. Gateway of Last Resort (Default Route to ISP)
Router(config)# ip route 0.0.0.0 0.0.0.0 203.0.113.1

! 3. Floating Static Backup Route via 4G/LTE (AD 120 beats OSPF AD 110 on failure)
Router(config)# ip route 0.0.0.0 0.0.0.0 198.51.100.1 120`
      }
    ],
    quizId: 'quiz-switching-routing',
    labIds: ['net-routing-explorer'],
    prevLessonId: 'net-routing-table-lookup',
    nextLessonId: 'net-ospf-single-area'
  },
  {
    id: 'net-ospf-single-area',
    courseId: 'switching-routing',
    moduleId: 'net-mod-routing',
    trackId: 'network',
    slug: 'ospf-single-area-configuration',
    title: 'Open Shortest Path First (OSPFv2) Single-Area Configuration',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Explain Link-State routing mechanics: Link State Advertisements (LSAs) and Dijkstra SPF algorithm.',
      'Configure single-area OSPFv2 in Area 0 (Backbone Area).',
      'Verify OSPF neighbor adjacencies, DR/BDR elections, and cost metrics.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Enterprise Interior Gateway Protocol Standard',
        content: 'OSPFv2 (RFC 2328) is the industry standard link-state routing protocol for enterprise networks. Unlike distance-vector protocols that route "by rumor", every OSPF router floods Link State Advertisements (LSAs) describing its active interfaces and neighbors. Each router constructs an identical map of the entire network topology and runs Dijkstra\'s Shortest Path First (SPF) algorithm to calculate the optimal path.'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Cisco IOS OSPFv2 Configuration',
        content: `Router(config)# router ospf 1
Router(config-router)# router-id 1.1.1.1
Router(config-router)# network 192.168.10.0 0.0.0.255 area 0
Router(config-router)# network 10.0.0.0 0.0.0.3 area 0
Router(config-router)# passive-interface GigabitEthernet0/1

! Verification
Router# show ip ospf neighbor
Neighbor ID     Pri   State           Dead Time   Address         Interface
2.2.2.2           1   FULL/BDR        00:00:34    10.0.0.2        Gi0/0`
      }
    ],
    quizId: 'quiz-switching-routing',
    labIds: ['net-routing-explorer'],
    prevLessonId: 'net-static-default-routing',
    nextLessonId: 'net-dhcp-operation'
  },

  // --- Course 4: Network Services and Operations ---
  // Module 4.1: Core Services
  {
    id: 'net-dhcp-operation',
    courseId: 'network-services',
    moduleId: 'net-mod-ip-services',
    trackId: 'network',
    slug: 'dhcp-dora-relay-operation',
    title: 'DHCP DORA Handshake, Relay Agents & Lease Management',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Trace the 4-step DHCP exchange: Discover, Offer, Request, and Acknowledgment.',
      'Configure a DHCP server pool with network range, default gateway, and DNS options.',
      'Configure an ip helper-address (DHCP Relay Agent) to forward broadcast requests across routers.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Automated IP Configuration at Scale',
        content: 'Dynamic Host Configuration Protocol (DHCP / RFC 2131) automatically provides clients with IP addresses, subnet masks, default gateways, DNS server addresses, and domain suffixes. Communication occurs over UDP ports 67 (server) and 68 (client).'
      },
      {
        type: 'worked-example',
        heading: 'The DORA Exchange Sequence',
        steps: [
          {
            title: '1. Discover (Client Broadcast)',
            content: 'Client boots with 0.0.0.0 and sends a broadcast to 255.255.255.255: "I need an IP address!"'
          },
          {
            title: '2. Offer (Server Unicast/Broadcast)',
            content: 'DHCP server reserves an available IP and replies offering 192.168.1.50 with lease parameters.'
          },
          {
            title: '3. Request (Client Selection Broadcast)',
            content: 'Client formally requests the offered IP, broadcasting to inform other potential DHCP servers that their offers were not chosen.'
          },
          {
            title: '4. Acknowledge (Server Confirmation)',
            content: 'DHCP server commits the lease in its database and sends DHCPACK confirming the lease duration (typically 8 days).'
          }
        ]
      },
      {
        type: 'code',
        language: 'text',
        title: 'Cisco IOS DHCP Server & IP Helper Configuration',
        content: `! 1. Local DHCP Pool
Router(config)# ip dhcp excluded-address 192.168.10.1 192.168.10.10
Router(config)# ip dhcp pool USERS_VLAN10
Router(config-dhcp)# network 192.168.10.0 255.255.255.0
Router(config-dhcp)# default-router 192.168.10.1
Router(config-dhcp)# dns-server 1.1.1.1 8.8.8.8
Router(config-dhcp)# lease 7

! 2. Forwarding DHCP broadcasts from remote client VLAN to central server
Router(config)# interface GigabitEthernet0/0.20
Router(config-subif)# ip helper-address 10.0.0.254`
      }
    ],
    quizId: 'quiz-network-services',
    labIds: ['sys-dns-dhcp-lab'],
    prevLessonId: 'net-ospf-single-area',
    nextLessonId: 'net-dns-resolution'
  },
  {
    id: 'net-dns-resolution',
    courseId: 'network-services',
    moduleId: 'net-mod-ip-services',
    trackId: 'network',
    slug: 'dns-resolution-records-ttl',
    title: 'Domain Name System (DNS): Hierarchy, Recursion & Records',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Trace recursive and iterative DNS resolution from root servers to authoritative name servers.',
      'Differentiate common DNS record types: A, AAAA, CNAME, MX, PTR, TXT, and SRV.',
      'Explain Time to Live (TTL) caching behavior and negative response caching.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Global Distributed Naming Directory',
        content: 'Humans remember names (api.github.com); routers only understand IP addresses (140.82.121.4). The Domain Name System (DNS / RFC 1035) is a hierarchical, distributed database operating over UDP/TCP port 53. The DNS hierarchy is anchored by 13 root server clusters (a.root-servers.net to m.root-servers.net), followed by Top-Level Domains (.com, .org, .net), second-level domains, and subdomains.'
      },
      {
        type: 'table',
        heading: 'Core Enterprise DNS Record Types',
        headers: ['Record Type', 'Function', 'Example Value'],
        rows: [
          ['A', 'Maps hostname to 32-bit IPv4 address', 'dc01.corp.test -> 192.168.10.10'],
          ['AAAA', 'Maps hostname to 128-bit IPv6 address', 'dc01.corp.test -> 2001:db8::10'],
          ['CNAME', 'Canonical Name: creates an alias pointing to another hostname', 'www.corp.test -> web-farm.corp.test'],
          ['MX', 'Mail Exchanger: specifies priority and hostname of mail server', 'corp.test -> 10 mail.corp.test'],
          ['PTR', 'Pointer: Reverse DNS mapping IP address back to hostname', '10.10.168.192.in-addr.arpa -> dc01.corp.test'],
          ['TXT', 'Text: stores SPF records, DKIM public keys, and verification strings', 'v=spf1 include:_spf.google.com ~all'],
          ['SRV', 'Service locator specifying port, protocol, weight, and target', '_ldap._tcp.corp.test -> port 389 dc01']
        ]
      }
    ],
    quizId: 'quiz-network-services',
    labIds: ['sys-dns-dhcp-lab'],
    prevLessonId: 'net-dhcp-operation',
    nextLessonId: 'net-nat-pat'
  },
  {
    id: 'net-nat-pat',
    courseId: 'network-services',
    moduleId: 'net-mod-ip-services',
    trackId: 'network',
    slug: 'nat-pat-port-translation',
    title: 'IPv4 Exhaustion: Static NAT, Dynamic NAT & PAT (Overload)',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Explain how Port Address Translation (PAT) allows thousands of hosts to share a single public IP.',
      'Differentiate Inside Local, Inside Global, Outside Local, and Outside Global address terms.',
      'Configure Cisco IOS NAT Overload (PAT) on an edge gateway.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Extending the Lifespan of IPv4',
        content: 'When IPv4 address space became constrained in the 1990s, Network Address Translation (NAT / RFC 3022) was introduced as a transitional stopgap. By translating non-routable RFC 1918 private addresses into a globally routable public IP address at the firewall or edge router, an entire enterprise campus with 10,000 workstations can access the public Internet simultaneously using a single public IP address.'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Cisco IOS PAT (NAT Overload) Configuration',
        content: `! 1. Define Inside and Outside Interfaces
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ip nat inside
Router(config)# interface GigabitEthernet0/1
Router(config-if)# ip nat outside

! 2. Identify traffic to be translated (ACL 1)
Router(config)# access-list 1 permit 192.168.0.0 0.0.255.255

! 3. Enable PAT (Overload) using the public WAN interface address
Router(config)# ip nat inside source list 1 interface GigabitEthernet0/1 overload

! Verification
Router# show ip nat translations
Pro Inside global          Inside local           Outside local         Outside global
tcp 203.0.113.5:54122      192.168.10.15:54122    140.82.121.4:443      140.82.121.4:443`
      }
    ],
    quizId: 'quiz-network-services',
    labIds: ['net-packet-journey'],
    prevLessonId: 'net-dns-resolution',
    nextLessonId: 'net-standard-extended-acls'
  },

  // Module 4.2: Security & Access Control
  {
    id: 'net-standard-extended-acls',
    courseId: 'network-services',
    moduleId: 'net-mod-net-security',
    trackId: 'network',
    slug: 'standard-extended-ipv4-acls',
    title: 'Access Control Lists (ACLs): Standard vs Extended Rules',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Compare Standard ACLs (source IP only) with Extended ACLs (source, destination, protocol, ports).',
      'Explain the mandatory Implicit Deny All present at the end of every ACL.',
      'Apply wildcard masks (inverse masks) to match subnets and individual host addresses.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Stateless Packet Filtering at Line Rate',
        content: 'Access Control Lists (ACLs) are ordered collections of permit and deny conditions applied to router interfaces. When an ACL is bound to an interface (inbound or outbound), the router inspects every packet header sequentially from top to bottom. As soon as a match is found, the permit or deny action is executed, and no further rules are evaluated. CRITICAL: Every ACL concludes with an invisible IMPLICIT DENY ALL!'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Cisco IOS Extended Named ACL Configuration',
        content: `! Block Engineering (VLAN 10) from accessing Finance (VLAN 20) servers, except HTTPS
Router(config)# ip access-list extended FILTER_VLAN10_IN
Router(config-ext-nacl)# permit tcp 192.168.10.0 0.0.0.255 192.168.20.50 0.0.0.0 eq 443
Router(config-ext-nacl)# deny ip 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255
Router(config-ext-nacl)# permit ip any any

! Apply to Interface Inbound
Router(config)# interface GigabitEthernet0/0.10
Router(config-subif)# ip access-group FILTER_VLAN10_IN in`
      },
      {
        type: 'callout',
        tone: 'tip',
        title: 'ACL Placement Golden Rules',
        content: '• Standard ACLs: Place as CLOSE TO THE DESTINATION as possible (because they only filter on Source IP; placing them near the source blocks traffic to all other destinations).\n• Extended ACLs: Place as CLOSE TO THE SOURCE as possible (to drop prohibited traffic immediately before it consumes transit bandwidth).'
      }
    ],
    quizId: 'quiz-network-services',
    labIds: ['net-routing-explorer'],
    prevLessonId: 'net-nat-pat',
    nextLessonId: 'net-port-security'
  },
  {
    id: 'net-port-security',
    courseId: 'network-services',
    moduleId: 'net-mod-net-security',
    trackId: 'network',
    slug: 'switchport-port-security-hardening',
    title: 'Switchport Security, Sticky MACs & Violation Modes',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Configure Cisco Port Security to restrict access based on authorized MAC addresses.',
      'Explain Sticky MAC learning and automated persistence in running configuration.',
      'Compare the three security violation modes: Protect, Restrict, and Shutdown.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Hardening the Physical Layer 2 Edge',
        content: 'Without physical security controls, a rogue visitor can walk into an enterprise conference room, unplug an office printer, and plug in a rogue Linux laptop or unauthorized Wi-Fi access point. Port Security restricts a switchport to only permit specific MAC addresses, preventing unauthorized device attachment and MAC flooding attacks.'
      },
      {
        type: 'table',
        heading: 'Port Security Violation Actions Comparison',
        headers: ['Violation Mode', 'Drops Unauthorized Frames?', 'Sends SNMP Trap & Syslog?', 'Shuts Down Port?'],
        rows: [
          ['Protect', 'YES (Silently drops rogue frames)', 'NO', 'NO (Port remains Up)'],
          ['Restrict', 'YES (Drops rogue frames)', 'YES (Increments violation counter)', 'NO (Port remains Up)'],
          ['Shutdown (Default)', 'YES', 'YES (Logs critical alert)', 'YES (Places port in err-disabled state)']
        ]
      },
      {
        type: 'code',
        language: 'text',
        title: 'Cisco IOS Port Security Configuration',
        content: `Switch(config)# interface GigabitEthernet0/5
Switch(config-if)# switchport mode access
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 1
Switch(config-if)# switchport port-security mac-address sticky
Switch(config-if)# switchport port-security violation shutdown`
      }
    ],
    quizId: 'quiz-network-services',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-standard-extended-acls',
    nextLessonId: 'net-wireless-fundamentals'
  },
  {
    id: 'net-wireless-fundamentals',
    courseId: 'network-services',
    moduleId: 'net-mod-net-security',
    trackId: 'network',
    slug: 'wireless-architecture-wpa3',
    title: 'Wireless Networking (802.11): SSIDs, WPA3 & Radio Bands',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Compare 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E/7) radio frequency spectrums.',
      'Differentiate Autonomous APs from Lightweight APs (LWAPP/CAPWAP) managed by a WLC.',
      'Explain WPA3 enterprise security enhancements including SAE and PMF.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Enterprise Radio Frequency Architecture',
        content: 'IEEE 802.11 wireless networking translates Ethernet frames into radio frequency (RF) signals. In enterprise deployments, standalone Autonomous Access Points are replaced with centralized Wireless LAN Controllers (WLCs) managing dozens or hundreds of Lightweight Access Points (LAPs) via encrypted CAPWAP tunnels.'
      },
      {
        type: 'table',
        heading: 'Wi-Fi Frequency Bands Comparison',
        headers: ['Band', 'Frequency', 'Range / Wall Penetration', 'Non-Overlapping Channels', 'Interference Risk'],
        rows: [
          ['2.4 GHz', '2.400 - 2.484 GHz', 'Long range, high penetration', '3 channels only (1, 6, 11)', 'High (Bluetooth, microwaves)'],
          ['5 GHz', '5.150 - 5.850 GHz', 'Medium range, lower penetration', '24+ non-overlapping channels', 'Low (DFS radar sharing)'],
          ['6 GHz (6E/7)', '5.925 - 7.125 GHz', 'Short range, high attenuation', '59 non-overlapping 20MHz channels', 'Near Zero (Clean spectrum)']
        ]
      }
    ],
    quizId: 'quiz-network-services',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-port-security',
    nextLessonId: 'net-snmp-syslog-ntp'
  },

  // Module 4.3: Automation, Monitoring & APIs
  {
    id: 'net-snmp-syslog-ntp',
    courseId: 'network-services',
    moduleId: 'net-mod-net-automation',
    trackId: 'network',
    slug: 'network-monitoring-snmp-syslog-ntp',
    title: 'Telemetry Foundations: SNMPv3, Syslog Severities & NTP',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Explain the 8 Syslog severity levels from Emergency (0) to Debugging (7).',
      'Describe Simple Network Management Protocol (SNMP) MIBs, OIDs, Polling, and Traps.',
      'Explain why Network Time Protocol (NTP) synchronization is mandatory for cryptographic forensics.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Observability & Network Time Synchronization',
        content: 'A network cannot be defended or troubleshot without unified telemetry. Network Time Protocol (NTP / UDP 123) synchronizes clocks across routers, switches, servers, and firewalls to within milliseconds of UTC. Without synchronized clocks, correlating an intrusion attempt in firewall logs with switchport state changes in syslog is mathematically impossible.'
      },
      {
        type: 'table',
        heading: 'Syslog Severity Hierarchy (RFC 5424)',
        headers: ['Level', 'Severity Name', 'Description', 'Action Required'],
        rows: [
          ['0', 'Emergency', 'System is unusable', 'Immediate full incident escalation'],
          ['1', 'Alert', 'Action must be taken immediately', 'Primary link failure, power loss'],
          ['2', 'Critical', 'Critical condition', 'Core service crash, memory exhaustion'],
          ['3', 'Error', 'Error conditions', 'Interface down, routing peer lost'],
          ['4', 'Warning', 'Warning conditions', 'High CPU utilization, BPF drop rate'],
          ['5', 'Notice', 'Normal but significant condition', 'Configuration saved, cold restart'],
          ['6', 'Informational', 'Informational messages', 'Port link status Up/Down, user login'],
          ['7', 'Debug', 'Debugging messages', 'Packet trace, protocol debug']
        ]
      }
    ],
    quizId: 'quiz-network-services',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-wireless-fundamentals',
    nextLessonId: 'net-restconf-netconf'
  },
  {
    id: 'net-restconf-netconf',
    courseId: 'network-services',
    moduleId: 'net-mod-net-automation',
    trackId: 'network',
    slug: 'programmability-restconf-netconf-yang',
    title: 'Network Programmability: RESTCONF, NETCONF & YANG',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Explain why legacy CLI screen scraping (Expect/Telnet) fails in automated CI/CD pipelines.',
      'Compare NETCONF (SSH/XML) and RESTCONF (HTTPS/JSON) programmable APIs.',
      'Understand how YANG data models define device configuration structure.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'The Transition from Human CLI to Machine APIs',
        content: 'For three decades, network engineers configured devices by manually typing commands into terminal windows. However, unstructured text output changes across firmware versions, causing automated screen-scraping scripts to break. Modern network operating systems implement structured Model-Driven Programmability using YANG (RFC 6020) data models accessed via NETCONF (RFC 6241) and RESTCONF (RFC 8040).'
      },
      {
        type: 'code',
        language: 'text',
        title: 'RESTCONF HTTP GET Example',
        content: `GET /restconf/data/ietf-interfaces:interfaces/interface=GigabitEthernet1 HTTP/1.1
Host: router.corp.test:443
Accept: application/yang-data+json
Authorization: Basic YWRtaW46YWRtaW4yMDI2IQ==

Response (Structured JSON):
{
  "ietf-interfaces:interface": {
    "name": "GigabitEthernet1",
    "description": "Uplink to Core Switch SW-01",
    "type": "iana-if-type:ethernetCsmacd",
    "enabled": true,
    "ietf-ip:ipv4": {
      "address": [
        {
          "ip": "10.0.0.1",
          "netmask": "255.255.255.252"
        }
      ]
    }
  }
}`
      }
    ],
    quizId: 'quiz-network-services',
    labIds: ['net-routing-explorer'],
    prevLessonId: 'net-snmp-syslog-ntp',
    nextLessonId: 'net-python-automation'
  },
  {
    id: 'net-python-automation',
    courseId: 'network-services',
    moduleId: 'net-mod-net-automation',
    trackId: 'network',
    slug: 'python-network-automation-netmiko',
    title: 'Automating Network Operations with Python & Netmiko',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Write a Python script using Netmiko to automate SSH configuration across multiple switches.',
      'Parse command outputs and automate backup archiving of running configurations.',
      'Implement error handling and credential protection in network automation scripts.'
    ],
    sections: [
      {
        type: 'text',
        heading: 'Practical Automation for the Network Engineer',
        content: 'Deploying a new VLAN across 40 edge switches by hand takes hours and invites human typos. Using Python with libraries such as Netmiko, Paramiko, or Scrapli, an engineer can script the deployment across all 40 switches in parallel in under 30 seconds, verifying compliance and archiving configurations automatically.'
      },
      {
        type: 'code',
        language: 'text',
        title: 'Automated Multi-Device Configuration Script (Python)',
        content: `from netmiko import ConnectHandler

devices = [
    {'device_type': 'cisco_ios', 'host': '192.168.10.2', 'username': 'admin', 'password': 'SecuredPassword!'},
    {'device_type': 'cisco_ios', 'host': '192.168.10.3', 'username': 'admin', 'password': 'SecuredPassword!'}
]

commands = [
    'vlan 50',
    'name SECURE_IOT',
    'exit',
    'interface range Gi0/10 - 15',
    'switchport mode access',
    'switchport access vlan 50',
    'spanning-tree portfast'
]

for dev in devices:
    print(f"Connecting to {dev['host']}...")
    with ConnectHandler(**dev) as net_connect:
        output = net_connect.send_config_set(commands)
        print(f"Output from {dev['host']}:\\n{output}")
        net_connect.save_config()`
      }
    ],
    quizId: 'quiz-network-services',
    labIds: ['net-vlan-lab'],
    prevLessonId: 'net-restconf-netconf',
    nextLessonId: null
  }
];

module.exports = {
  NETWORK_COURSES,
  NETWORK_MODULES,
  NETWORK_LESSONS
};
