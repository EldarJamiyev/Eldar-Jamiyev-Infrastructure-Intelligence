/**
 * EJII Learning Center — Embedded AI Mentor, Protocol Math Tutor,
 * Interactive Simulation Engine & SM-2 Spaced-Repetition Analytics
 *
 * Provides:
 *   1. Context-Aware Multi-Tier AI Mentor (BEGINNER | NOC_OPERATOR | SENIOR_ARCHITECT)
 *   2. Real-Time Subnetting, CIDR, OSPF Cost & TCP BDP Step-by-Step Math Solver
 *   3. Interactive Protocol State-Machine & Packet Encapsulation Visual Specs
 *   4. Interactive Lab Sandbox Command Coach & Diagnostic Hint Engine
 *   5. SuperMemo-2 (SM-2) Spaced-Repetition Scheduler & Cross-Workstation Synergy Links
 */

'use strict';

const {
  getLesson,
  getCourse,
  getModule,
  getQuiz,
  getLab,
  getLessons,
  getCourses,
  searchCatalog
} = require('./catalog');
const { progressService } = require('./progress-service');

const EXPERTISE_TIERS = Object.freeze({
  BEGINNER: {
    id: 'BEGINNER',
    label: 'Beginner / CCNA Candidate',
    tone: 'Clear, analogy-rich, step-by-step foundational explanation with zero unexplained jargon.'
  },
  NOC_OPERATOR: {
    id: 'NOC_OPERATOR',
    label: 'NOC / SRE Operator',
    tone: 'Operational, CLI-focused, emphasizing live wire symptoms, triage commands, and SLA impact.'
  },
  SENIOR_ARCHITECT: {
    id: 'SENIOR_ARCHITECT',
    label: 'Senior Network / Systems Architect',
    tone: 'RFC-rigorous, packet-header bit-level, kernel state-machine, and distributed control-plane trade-offs.'
  }
});

/**
 * Maps lessons/topics to interactive protocol simulations and live EJII Workbench jump targets
 */
const PROTOCOL_SIMULATION_LIBRARY = Object.freeze({
  OSI_ENCAPSULATION: {
    simulationId: 'OSI_ENCAPSULATION',
    title: 'OSI 7-Layer & TCP/IP Packet Encapsulation Pipeline',
    protocol: 'Ethernet / IPv4 / TCP / HTTP',
    rfcReference: 'RFC 791 (IPv4), RFC 9293 (TCP), IEEE 802.3',
    workbenchSynergy: {
      viewId: 'sniffer',
      buttonLabel: 'Inspect Live L2–L7 Encapsulation in Packet Analysis Workbench',
      presetTarget: '127.0.0.1',
      presetProtocol: 'TCP',
      academyBridgeNote: 'Compare each PDU header (L7 Payload -> L4 TCP Segment -> L3 IPv4 Packet -> L2 Ethernet Frame) against live captured packets.'
    },
    stages: [
      {
        step: 1,
        layer: 'Layer 7 — Application (HTTP/TLS)',
        pduName: 'Data / Application Stream',
        headerAdded: 'HTTP/1.1 GET /api/health + Host Header (64 bytes)',
        wireHexPreview: '47 45 54 20 2f 61 70 69 2f 68 65 61 6c 74 68 20 48 54 54 50 2f 31 2e 31',
        keyFields: ['Method: GET', 'URI: /api/health', 'TLS SNI: app.internal'],
        diagnosticCheck: 'If L4 connects but L7 hangs, inspect TLS ALPN/SNI mismatch or backend worker starvation.'
      },
      {
        step: 2,
        layer: 'Layer 4 — Transport (TCP)',
        pduName: 'Segment',
        headerAdded: '20-byte TCP Header + 12-byte Options (MSS=1460, SACK_PERM, WS=7)',
        wireHexPreview: 'd4 31 01 bb 8a 10 4c 01 00 00 00 00 80 02 fa f0',
        keyFields: ['SrcPort: 54321', 'DstPort: 443', 'Seq: 0x8a104c01', 'Flags: SYN (0x02)', 'Win: 64240'],
        diagnosticCheck: 'RST after SYN indicates closed listener (ECONNREFUSED); silence after SYN indicates firewall drop.'
      },
      {
        step: 3,
        layer: 'Layer 3 — Network (IPv4)',
        pduName: 'Packet',
        headerAdded: '20-byte IPv4 Header (Version=4, IHL=5, TTL=64, Protocol=6 TCP, DSCP=CS0)',
        wireHexPreview: '45 00 00 60 3c 1b 40 00 40 06 7a 91 c0 a8 01 0a 0a 00 00 01',
        keyFields: ['SrcIP: 192.168.1.10', 'DstIP: 10.0.0.1', 'TTL: 64', 'DF: 1 (Don\'t Fragment)'],
        diagnosticCheck: 'If packet size > 1500B with DF=1 on a 1400B VPN tunnel, router drops packet and emits ICMP Type 3 Code 4.'
      },
      {
        step: 4,
        layer: 'Layer 2 — Data Link (Ethernet II / 802.1Q)',
        pduName: 'Frame',
        headerAdded: '14-byte Ethernet Header (DstMAC, SrcMAC, EtherType=0x0800) + 4-byte FCS Trailer',
        wireHexPreview: '00 1a 2b 3c 4d 5e aa bb cc dd ee ff 08 00 ... [FCS 4B]',
        keyFields: ['DstMAC: Default Gateway ARP', 'SrcMAC: Host NIC MAC', 'EtherType: 0x0800 (IPv4)'],
        diagnosticCheck: 'Note that DstMAC is rewritten at EVERY router hop while DstIP remains end-to-end.'
      }
    ]
  },
  TCP_HANDSHAKE_CWND: {
    simulationId: 'TCP_HANDSHAKE_CWND',
    title: 'TCP 3-Way Handshake, Seq/Ack State Machine & Congestion Window',
    protocol: 'TCP (RFC 9293 / RFC 5681)',
    rfcReference: 'RFC 9293 (TCP), RFC 5681 (Congestion Control)',
    workbenchSynergy: {
      viewId: 'diagnostics',
      buttonLabel: 'Run Live TCP 3-Way Handshake Probe in Core Diagnostics',
      presetTarget: '127.0.0.1',
      presetPort: 3000,
      academyBridgeNote: 'Measure real kernel SYN -> SYN-ACK -> ACK connect latency and verify socket states.'
    },
    stages: [
      {
        step: 1,
        layer: 'Client -> Server: SYN',
        pduName: 'SYN (ISN_c = 1000, CTL=SYN)',
        headerAdded: 'Client selects cryptographic Initial Sequence Number (ISN_c = 1000), negotiates MSS=1460 & Window Scale.',
        wireHexPreview: 'Flags [S], seq 1000, win 64240, options [mss 1460,sackOK,TS,nop,wscale 7]',
        keyFields: ['State: SYN_SENT', 'Seq: 1000', 'Ack: 0', 'SYN consumes 1 virtual sequence byte'],
        diagnosticCheck: 'Repeated SYN retransmissions (1s, 3s, 7s) prove path blackhole or silent firewall drop.'
      },
      {
        step: 2,
        layer: 'Server -> Client: SYN-ACK',
        pduName: 'SYN-ACK (ISN_s = 5000, ACK = 1001)',
        headerAdded: 'Server allocates TCB in SYN backlog, replies with own ISN_s = 5000 and ACK = ISN_c + 1 = 1001.',
        wireHexPreview: 'Flags [S.], seq 5000, ack 1001, win 65160, options [mss 1460,sackOK,wscale 7]',
        keyFields: ['State: SYN_RCVD', 'Seq: 5000', 'Ack: 1001', 'Measured RTT sample locked'],
        diagnosticCheck: 'If server replies RST-ACK [R.] instead of SYN-ACK, no process is bound to that port.'
      },
      {
        step: 3,
        layer: 'Client -> Server: ACK & Slow Start',
        pduName: 'ACK (Seq = 1001, Ack = 5001, cwnd = 10*MSS)',
        headerAdded: 'Client enters ESTABLISHED state, sends ACK=5001, and initializes Congestion Window (IW10 = 14,600 bytes).',
        wireHexPreview: 'Flags [.], seq 1001, ack 5001, win 502',
        keyFields: ['State: ESTABLISHED', 'Seq: 1001', 'Ack: 5001', 'cwnd: 10 MSS (RFC 6928)'],
        diagnosticCheck: 'Triple duplicate ACKs trigger Fast Retransmit & CUBIC/Reno cwnd reduction.'
      }
    ]
  },
  VLAN_8021Q_TRUNKING: {
    simulationId: 'VLAN_8021Q_TRUNKING',
    title: 'IEEE 802.1Q VLAN Tag Insertion, Access vs Trunk Ports & Router-on-a-Stick',
    protocol: 'IEEE 802.1Q / L2 Switching',
    rfcReference: 'IEEE 802.1Q-2022',
    workbenchSynergy: {
      viewId: 'topology',
      buttonLabel: 'Explore L2/L3 Subnet & Gateway Segmentation in Topology Map',
      presetTarget: '127.0.0.1',
      academyBridgeNote: 'Visualize broadcast domain boundaries, cut-vertex gateways, and inter-VLAN routing paths.'
    },
    stages: [
      {
        step: 1,
        layer: 'Ingress Access Port (Untagged Frame)',
        pduName: 'Standard Ethernet Frame (VLAN 10 Host)',
        headerAdded: 'Host sends standard untagged frame into switch port Gi0/1 configured with `switchport access vlan 10`.',
        wireHexPreview: '[DstMAC 6B] [SrcMAC 6B] [0x0800 IPv4 2B] [IPv4 Payload...]',
        keyFields: ['Port Mode: Access', 'Assigned PVID: VLAN 10', 'Tag on Wire: None (Untagged)'],
        diagnosticCheck: 'End hosts are VLAN-unaware; the ingress switch port classifies the frame into VLAN 10.'
      },
      {
        step: 2,
        layer: '802.1Q Trunk Link (4-Byte Tag Inserted)',
        pduName: '802.1Q Tagged Frame (TPID 0x8100, VID=10)',
        headerAdded: 'Switch inserts 4-byte 802.1Q tag between SrcMAC and EtherType and recomputes the 32-bit CRC FCS.',
        wireHexPreview: '[DstMAC 6B] [SrcMAC 6B] [81 00 00 0A (TPID=0x8100, PCP=0, DEI=0, VID=10)] [08 00]',
        keyFields: ['TPID: 0x8100 (16 bits)', 'PCP: 3 bits (QoS CoS)', 'DEI: 1 bit', 'VID: 12 bits (1..4094)'],
        diagnosticCheck: 'Native VLAN mismatch across trunk peers causes STP PVID inconsistency and traffic leakage.'
      },
      {
        step: 3,
        layer: 'Inter-VLAN Subinterface Routing (802.1Q Encapsulation)',
        pduName: 'Router Subinterface Gi0/0.10 -> Gi0/0.20',
        headerAdded: 'Router strips VLAN 10 tag, performs L3 longest-prefix lookup, decrements TTL, and re-tags with VLAN 20.',
        wireHexPreview: 'Rx VID=10 -> L3 FIB Lookup (10.20.0.0/24) -> Tx VID=20 (81 00 00 14)',
        keyFields: ['Ingress: Gi0/0.10 (dot1Q 10)', 'Egress: Gi0/0.20 (dot1Q 20)', 'TTL: Decremented by 1'],
        diagnosticCheck: 'If same-VLAN ping works but inter-VLAN fails, verify subinterface `encapsulation dot1Q` and host default gateway.'
      }
    ]
  },
  DNS_DHCP_DORA: {
    simulationId: 'DNS_DHCP_DORA',
    title: 'DHCP DORA 4-Step Lease Allocation & Recursive DNS Resolution Hierarchy',
    protocol: 'DHCP (UDP 67/68) & DNS (UDP/TCP 53)',
    rfcReference: 'RFC 2131 (DHCP), RFC 1035 / RFC 4035 (DNS/DNSSEC)',
    workbenchSynergy: {
      viewId: 'diagnostics',
      buttonLabel: 'Run Live DNS Lookup & Resolver Health Audit in Core Diagnostics',
      presetTarget: 'localhost',
      academyBridgeNote: 'Test live recursive resolver latency, authoritative NS records, and local hosts resolution.'
    },
    stages: [
      {
        step: 1,
        layer: 'DHCP Discover & Offer (D-O)',
        pduName: 'Broadcast 0.0.0.0:68 -> 255.255.255.255:67',
        headerAdded: 'Unconfigured client broadcasts DHCPDISCOVER; DHCP server (or `ip helper-address` relay) responds with DHCPOFFER.',
        wireHexPreview: 'UDP 0.0.0.0:68 -> 255.255.255.255:67 | BootP Op=1, Opt53=1 (DISCOVER), Chaddr=MAC',
        keyFields: ['Opt 53: Msg Type (1=Discover, 2=Offer)', 'YIADDR: Offered IP', 'Opt 3: Router', 'Opt 6: DNS'],
        diagnosticCheck: 'If client falls back to APIPA 169.254.x.x/16, DHCP broadcast failed to reach server or scope is exhausted.'
      },
      {
        step: 2,
        layer: 'DHCP Request & Acknowledge (R-A)',
        pduName: 'DHCPREQUEST -> DHCPACK (Lease Bound + T1/T2 Timers)',
        headerAdded: 'Client requests offered IP (Opt 50); server commits lease in DB and returns DHCPACK with T1 (50%) and T2 (87.5%).',
        wireHexPreview: 'UDP Server:67 -> Client:68 | Opt53=5 (ACK), Opt51=86400s, Opt3=GW, Opt6=DNS',
        keyFields: ['T1 Renewal: 50% lease (Unicast)', 'T2 Rebind: 87.5% lease (Broadcast)', 'DAD: Gratuitous ARP check'],
        diagnosticCheck: 'Enable DHCP Snooping on access switches so rogue DHCP servers cannot inject MITM default gateways.'
      },
      {
        step: 3,
        layer: 'Recursive DNS Resolution Chain',
        pduName: 'Stub Resolver -> Recursive Resolver -> Root (.) -> TLD -> Authoritative NS',
        headerAdded: 'Stub sends UDP/53 query with RD=1; Recursive Resolver walks Root -> TLD -> Auth NS and caches RRset by TTL.',
        wireHexPreview: 'DNS Query ID=0x4f2a Flags=0x0100 (RD=1) QNAME=api.corp.example.com QTYPE=A',
        keyFields: ['RCODE 0: NOERROR', 'RCODE 2: SERVFAIL (DNSSEC/Upstream)', 'RCODE 3: NXDOMAIN'],
        diagnosticCheck: 'Always separate DNS failure (NXDOMAIN/SERVFAIL) from TCP/ICMP connectivity failure during triage.'
      }
    ]
  },
  OSPF_BGP_ROUTING: {
    simulationId: 'OSPF_BGP_ROUTING',
    title: 'OSPFv2 Link-State Adjacency (Down -> Full) & Longest-Prefix Match FIB Lookup',
    protocol: 'OSPFv2 (IP Proto 89) & L3 Routing',
    rfcReference: 'RFC 2328 (OSPFv2), RFC 4271 (BGP-4)',
    workbenchSynergy: {
      viewId: 'enterprise-noc',
      buttonLabel: 'Open Enterprise NOC Cut-Vertex & Path Risk Analyzer',
      presetTarget: '127.0.0.1',
      academyBridgeNote: 'Inspect how single-point-of-failure cut-vertices and link saturation impact multi-site routing.'
    },
    stages: [
      {
        step: 1,
        layer: 'OSPF Hello & Parameter Verification (Down -> Init -> 2-Way)',
        pduName: 'Multicast 224.0.0.5 (AllSPFRouters) IP Proto 89',
        headerAdded: 'Routers exchange Hello packets every 10s; must match Area ID, Hello/Dead timers, Subnet Mask, Stub Flag, and Auth.',
        wireHexPreview: 'IP 10.0.12.1 -> 224.0.0.5 Proto=89 | OSPF v2 Type=1 (Hello) RID=1.1.1.1 Area=0.0.0.0',
        keyFields: ['State: 2-Way (DR/BDR Election on Broadcast)', 'Hello/Dead: 10s / 40s', 'Area: 0.0.0.0'],
        diagnosticCheck: 'Stuck in INIT or 2-WAY? Check mismatched Hello/Dead timers, Area ID, or subnet mask.'
      },
      {
        step: 2,
        layer: 'LSDB Synchronization (ExStart -> Exchange -> Loading -> Full)',
        pduName: 'DBD (MTU Check) -> LSR -> LSU -> LSAck',
        headerAdded: 'Master/Slave elected by highest Router ID; routers exchange Database Descriptors (DBD) and flood Type-1/Type-2 LSAs.',
        wireHexPreview: 'OSPF Type=2 (DBD) InterfaceMTU=1500 Flags=[I,M,MS] Seq=0x1a04',
        keyFields: ['ExStart: MTU Verification', 'Loading: LSR/LSU exchange', 'Full: Identical LSDBs'],
        diagnosticCheck: 'Stuck in EXSTART/EXCHANGE is the classic signature of an Interface MTU mismatch across the link!'
      },
      {
        step: 3,
        layer: 'Dijkstra SPF Calculation & Longest-Prefix Match vs AD',
        pduName: 'RIB Candidate Selection -> FIB Hardware Programming',
        headerAdded: 'Router runs Dijkstra SPF (Cost = RefBW / IntBW), compares Administrative Distance (Connected=0, Static=1, eBGP=20, OSPF=110), and matches Longest Prefix (/26 beats /24).',
        wireHexPreview: 'FIB Match: 10.10.20.45 -> 10.10.20.0/26 (OSPF AD 110) beats 10.10.20.0/24 (Static AD 1)',
        keyFields: ['Rule 1: Longest Prefix (/26 > /24)', 'Rule 2: Lowest AD (1 < 110)', 'Rule 3: Lowest Metric'],
        diagnosticCheck: 'A more specific /26 route ALWAYS wins forwarding over a less specific /24 route regardless of Administrative Distance.'
      }
    ]
  },
  SYSTEMS_KERBEROS_SYSTEMD: {
    simulationId: 'SYSTEMS_KERBEROS_SYSTEMD',
    title: 'Active Directory Kerberos KDC Ticket Flow & Linux systemd / Kernel Socket Triage',
    protocol: 'Kerberos V5 (TCP/UDP 88) & Linux Kernel /proc/net',
    rfcReference: 'RFC 4120 (Kerberos V5), POSIX / Linux Netstack',
    workbenchSynergy: {
      viewId: 'automation',
      buttonLabel: 'Open Host Automation & Socket-to-PID Inspector',
      presetTarget: '127.0.0.1',
      academyBridgeNote: 'Correlate live listening ports, PIDs, CPU/RAM pressure, and service health on the local host.'
    },
    stages: [
      {
        step: 1,
        layer: 'Kerberos AS-REQ / AS-REP (Authentication Service)',
        pduName: 'Pre-Authentication Timestamp -> TGT Issued',
        headerAdded: 'Client encrypts current UTC timestamp with password hash; KDC validates within 5-minute clock skew and returns TGT encrypted with krbtgt key.',
        wireHexPreview: 'KRB5 AS-REQ Realm=CORP.LOCAL CName=alice EType=AES256-CTS-HMAC-SHA1-96',
        keyFields: ['Port: UDP/TCP 88', 'Max Clock Skew: 5 minutes', 'Artifact: Ticket Granting Ticket (TGT)'],
        diagnosticCheck: 'KRB5KRB_AP_ERR_SKEW means NTP time synchronization drifted > 5 minutes between client and Domain Controller.'
      },
      {
        step: 2,
        layer: 'Kerberos TGS-REQ / TGS-REP & Service AP-REQ',
        pduName: 'TGT + SPN -> Service Ticket -> Target Server',
        headerAdded: 'Client presents TGT to KDC requesting Service Principal Name (SPN e.g. HTTP/intranet.corp.local); presents Service Ticket to server.',
        wireHexPreview: 'KRB5 TGS-REQ SName=HTTP/intranet.corp.local -> TGS-REP Ticket[Encrypted with Service Key]',
        keyFields: ['SPN Lookup: Active Directory LDAP', 'PAC: Group SIDs embedded in ticket'],
        diagnosticCheck: 'Duplicate or missing SPNs cause silent fallback to NTLM or HTTP 401 Negotiate failures.'
      },
      {
        step: 3,
        layer: 'Linux systemd Unit Lifecycle & Socket-to-PID Binding',
        pduName: 'systemd -> fork/exec -> bind(0.0.0.0:443) -> /proc/net/tcp',
        headerAdded: 'systemd spawns daemon in cgroup, applies ProtectSystem=strict, and binds socket fd to TCP listener queue.',
        wireHexPreview: 'ss -tulpn | LISTEN 0 4096 0.0.0.0:443 users:(("nginx",pid=1842,fd=6))',
        keyFields: ['127.0.0.1:port = Loopback Only', '0.0.0.0:port = All IPv4 Interfaces', 'Exit 137 = SIGKILL OOM'],
        diagnosticCheck: 'If service works locally via curl 127.0.0.1:3000 but fails from LAN, verify whether daemon bound to 127.0.0.1 instead of 0.0.0.0.'
      }
    ]
  }
});

class AiMentorService {
  constructor() {
    this.mentorHistoryByUser = new Map();
    this.sm2CardsByUser = new Map();
  }

  /**
   * Selects the best interactive protocol simulation for a given lesson or course
   */
  getSimulationForLesson(lessonOrId) {
    const lesson = typeof lessonOrId === 'string' ? getLesson(lessonOrId) : lessonOrId;
    const text = `${lesson?.id || ''} ${lesson?.courseId || ''} ${lesson?.title || ''}`.toLowerCase();

    if (/vlan|802\.1q|trunk|stp|switching/.test(text)) {
      return PROTOCOL_SIMULATION_LIBRARY.VLAN_8021Q_TRUNKING;
    }
    if (/ospf|bgp|routing|route|acl|nat/.test(text)) {
      return PROTOCOL_SIMULATION_LIBRARY.OSPF_BGP_ROUTING;
    }
    if (/dns|dhcp|dora|wireless|automation|snmp|ntp/.test(text)) {
      return PROTOCOL_SIMULATION_LIBRARY.DNS_DHCP_DORA;
    }
    if (/tcp|udp|transport|port|subnet|ipv4|ipv6|cidr|vlsm/.test(text)) {
      return PROTOCOL_SIMULATION_LIBRARY.TCP_HANDSHAKE_CWND;
    }
    if (/windows|linux|active-directory|kerberos|gpo|systemd|incident|sre|enterprise/.test(text)) {
      return PROTOCOL_SIMULATION_LIBRARY.SYSTEMS_KERBEROS_SYSTEMD;
    }
    return PROTOCOL_SIMULATION_LIBRARY.OSI_ENCAPSULATION;
  }

  /**
   * Detects and solves IPv4 CIDR / Subnetting math step-by-step if the question contains an IP/CIDR or subnetting prompt
   */
  solveSubnettingMathIfPresent(questionText) {
    const raw = String(questionText || '');
    const cidrMatch = raw.match(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*\/\s*(\d{1,2})\b/);
    if (!cidrMatch) return null;

    const octets = [
      Number(cidrMatch[1]),
      Number(cidrMatch[2]),
      Number(cidrMatch[3]),
      Number(cidrMatch[4])
    ];
    const prefix = Number(cidrMatch[5]);
    if (octets.some((o) => o < 0 || o > 255) || prefix < 1 || prefix > 32) {
      return null;
    }

    const ipInt =
      ((octets[0] << 24) >>> 0) +
      ((octets[1] << 16) >>> 0) +
      ((octets[2] << 8) >>> 0) +
      (octets[3] >>> 0);
    const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const wildcardInt = (~maskInt) >>> 0;
    const networkInt = (ipInt & maskInt) >>> 0;
    const broadcastInt = (networkInt | wildcardInt) >>> 0;

    const intToIp = (n) => [
      (n >>> 24) & 255,
      (n >>> 16) & 255,
      (n >>> 8) & 255,
      n & 255
    ].join('.');

    const intToBinaryOctets = (n) => [
      ((n >>> 24) & 255).toString(2).padStart(8, '0'),
      ((n >>> 16) & 255).toString(2).padStart(8, '0'),
      ((n >>> 8) & 255).toString(2).padStart(8, '0'),
      (n & 255).toString(2).padStart(8, '0')
    ].join('.');

    const hostBits = 32 - prefix;
    const totalAddresses = Math.pow(2, hostBits);
    const usableHosts = hostBits >= 2 ? totalAddresses - 2 : (hostBits === 1 ? 2 : 1);
    const firstUsable = hostBits >= 2 ? intToIp((networkInt + 1) >>> 0) : intToIp(networkInt);
    const lastUsable = hostBits >= 2 ? intToIp((broadcastInt - 1) >>> 0) : intToIp(broadcastInt);
    const interestingOctetIndex = Math.floor((prefix - 1) / 8) + 1;
    const blockSize = Math.pow(2, (8 - (prefix % 8 || 8)));

    return {
      inputCidr: `${octets.join('.')}/${prefix}`,
      prefixLength: prefix,
      hostBits,
      subnetMask: intToIp(maskInt),
      wildcardMask: intToIp(wildcardInt),
      networkAddress: intToIp(networkInt),
      broadcastAddress: intToIp(broadcastInt),
      firstUsableHost: firstUsable,
      lastUsableHost: lastUsable,
      totalAddresses,
      usableHosts,
      interestingOctet: interestingOctetIndex,
      magicBlockSize: blockSize,
      binaryIp: intToBinaryOctets(ipInt),
      binaryMask: intToBinaryOctets(maskInt),
      binaryNetwork: intToBinaryOctets(networkInt),
      steps: [
        `1. **Prefix & Host Bits**: \`/${prefix}\` means **${prefix} network bits** (1s) and **$32 - ${prefix} = ${hostBits}$ host bits** (0s).`,
        `2. **Subnet & Wildcard Mask**: Subnet mask = \`${intToIp(maskInt)}\` (\`${intToBinaryOctets(maskInt)}\`), Wildcard mask = \`${intToIp(wildcardInt)}\`.`,
        `3. **Magic Block Size**: In Octet #${interestingOctetIndex}, the block size is $2^{${8 - (prefix % 8 || 8)}} = ${blockSize}$. Multiples of ${blockSize} establish subnet boundaries.`,
        `4. **Bitwise AND -> Network ID**: \`${octets.join('.')}\` AND \`${intToIp(maskInt)}\` = **\`${intToIp(networkInt)}/${prefix}\`**.`,
        `5. **Broadcast & Usable Host Range**: Next subnet starts at +${blockSize}, so Broadcast = **\`${intToIp(broadcastInt)}\`**, First Usable = **\`${firstUsable}\`**, Last Usable = **\`${lastUsable}\`**, Total Usable Hosts = **$2^{${hostBits}} - 2 = ${usableHosts}$**.`
      ]
    };
  }

  /**
   * Answers a student or operator question with full awareness of active Lesson, Course, Lab, Quiz, and Expertise Tier
   */
  askMentor({
    userId = 'anonymous',
    question = '',
    lessonId = null,
    courseId = null,
    quizId = null,
    questionId = null,
    selectedOptionId = null,
    labId = null,
    expertiseTier = 'NOC_OPERATOR'
  } = {}) {
    const tierKey = EXPERTISE_TIERS[expertiseTier] ? expertiseTier : 'NOC_OPERATOR';
    const tierInfo = EXPERTISE_TIERS[tierKey];
    const cleanQuestion = String(question || '').trim() || 'Explain the core operational takeaway and how to verify it on a live network.';

    const lesson = lessonId ? getLesson(lessonId) : null;
    const course = courseId ? getCourse(courseId) : (lesson ? getCourse(lesson.courseId) : null);
    const quiz = quizId ? getQuiz(quizId) : (course ? getQuiz(course.quizId) : null);
    const lab = labId ? getLab(labId) : (lesson?.labIds?.[0] ? getLab(lesson.labIds[0]) : null);

    const simulation = this.getSimulationForLesson(lesson || { id: courseId || '', title: cleanQuestion });
    const subnetMath = this.solveSubnettingMathIfPresent(cleanQuestion);

    // Check if the user is asking about a specific quiz question/option
    let quizExplanation = null;
    if (quiz && questionId) {
      const qObj = (quiz.questions || []).find((q) => q.id === questionId);
      if (qObj) {
        const correctIds = qObj.correctOptionIds || [];
        const correctOpts = (qObj.options || []).filter((o) => correctIds.includes(o.id));
        const chosenOpt = selectedOptionId ? (qObj.options || []).find((o) => o.id === selectedOptionId) : null;
        quizExplanation = {
          questionPrompt: qObj.prompt,
          selectedOptionText: chosenOpt ? chosenOpt.text : null,
          isSelectedCorrect: chosenOpt ? correctIds.includes(chosenOpt.id) : null,
          correctAnswerSummary: correctOpts.map((o) => o.text).join(' + '),
          canonicalExplanation: qObj.explanation || 'Verify protocol state transitions and header fields at the active OSI layer.'
        };
      }
    }

    // Build tiered pedagogical response
    const contextTitle = lesson ? lesson.title : (course ? course.title : 'Enterprise Networking & Systems Architecture');
    const objectives = lesson?.objectives || course?.objectives || [
      'Isolate faults across OSI Layers 1–7 using empirical protocol telemetry',
      'Verify routing, switching, DNS, and host socket states without guesswork'
    ];

    let tierAdaptation = '';
    if (tierKey === 'BEGINNER') {
      tierAdaptation =
        `**Foundational Mental Model (${tierInfo.label}):**\n` +
        `Think of **${contextTitle}** as a deterministic contract between layers. Each layer only trusts the header directly below it and serves the layer directly above it. ` +
        `When troubleshooting, always ask: *1) Did the name resolve (DNS)? 2) Can packets reach the IP (L3 Routing/ICMP)? 3) Did the service port accept the connection (L4 TCP SYN/SYN-ACK)? 4) Did the application reply cleanly (L7 HTTP/TLS)?*`;
    } else if (tierKey === 'SENIOR_ARCHITECT') {
      tierAdaptation =
        `**Architectural & RFC Control-Plane Deep Dive (${tierInfo.label}):**\n` +
        `In **${contextTitle}**, production failures rarely manifest as clean binary outages—they emerge as **non-linear queueing cliffs** ($\\Phi(\\rho) = \\rho / (1 - \\rho)$), **MTU blackholes** (ICMP Type 3 Code 4 filtered with IPv4 \`DF=1\`), **split-brain control planes** (OSPF \`ExStart\` MTU mismatch or Kerberos \`KRB5KRB_AP_ERR_SKEW\`), or **ephemeral socket / SYN backlog exhaustion** (\`net.core.somaxconn\`).`;
    } else {
      tierAdaptation =
        `**NOC / SRE Operational Triage Workflow (${tierInfo.label}):**\n` +
        `For **${contextTitle}**, separate **control-plane configuration** from **data-plane wire evidence**. Run targeted probes to maximize Shannon Information Gain ($\\Delta H$ bits) so a single verification command eliminates half of the competing root-cause domains.`;
    }

    // Topic-specific deep answer synthesis
    const qLower = `${cleanQuestion} ${contextTitle}`.toLowerCase();
    let topicDeepDive = '';
    let cliVerificationCommands = [];

    if (subnetMath) {
      topicDeepDive =
        `### Live CIDR & Subnetting Binary Derivation for \`${subnetMath.inputCidr}\`\n` +
        subnetMath.steps.join('\n') +
        `\n\n- **Binary IP:** \`${subnetMath.binaryIp}\`\n- **Binary Mask:** \`${subnetMath.binaryMask}\`\n- **Binary Network ID:** \`${subnetMath.binaryNetwork}\``;
      cliVerificationCommands = [
        `ipcalc ${subnetMath.inputCidr}`,
        `ip route get ${subnetMath.firstUsableHost}`,
        `ping -c 2 ${subnetMath.firstUsableHost}`
      ];
    } else if (/vlan|802\.1q|trunk|native|stp|switch/.test(qLower)) {
      topicDeepDive =
        `### IEEE 802.1Q VLAN Tagging & L2 Switching Mechanics\n` +
        `- **Access vs. Trunk Ports:** Access ports carry untagged traffic for a single VLAN; 802.1Q trunks insert a **4-byte tag** (\`TPID = 0x8100\`, \`PCP = 3 bits\`, \`DEI = 1 bit\`, \`VID = 12 bits\`) and recompute the 4-byte Ethernet FCS.\n` +
        `- **Inter-VLAN Routing:** Devices in different VLANs sit in separate L2 broadcast domains and **cannot** communicate without a Layer 3 gateway (Router-on-a-Stick 802.1Q subinterface or L3 Switch SVI).\n` +
        `- **Classic Failure Modes:** Missing VLAN on trunk allowed list (\`switchport trunk allowed vlan add <id>\`), Native VLAN mismatch across trunk peers, or host default gateway pointing to the wrong SVI.`;
      cliVerificationCommands = [
        'show interfaces trunk',
        'show vlan brief',
        'show spanning-tree vlan 10',
        'ip -d link show'
      ];
    } else if (/ospf|bgp|route|routing|longest prefix|administrative distance|ad\b|nat|acl/.test(qLower)) {
      topicDeepDive =
        `### Layer 3 Routing Selection, OSPF Adjacency & Longest-Prefix Match\n` +
        `- **Order of Operations (Non-Negotiable):**\n` +
        `  1. **Longest Prefix Match Always Wins First:** A \`/26\` route beats a \`/24\` route beats \`0.0.0.0/0\`, regardless of Administrative Distance.\n` +
        `  2. **Administrative Distance (Tie-Breaker for Identical Prefix Lengths):** Connected (\`0\`) < Static (\`1\`) < eBGP (\`20\`) < EIGRP (\`90\`) < OSPF (\`110\`) < RIP (\`120\`).\n` +
        `  3. **Routing Metric (Tie-Breaker for Identical Prefix + Same Protocol):** OSPF Cost $= \\text{Reference BW} / \\text{Interface BW}$.\n` +
        `- **OSPF Stuck States:** Stuck in \`INIT\` / \`2-WAY\` $\\rightarrow$ mismatched Hello/Dead timers, Area ID, or subnet mask. Stuck in \`EXSTART\` / \`EXCHANGE\` $\\rightarrow$ **Interface MTU mismatch**.`;
      cliVerificationCommands = [
        'show ip ospf neighbor',
        'show ip route',
        'ip route get 10.20.30.40',
        'traceroute -n 10.20.30.40'
      ];
    } else if (/tcp|udp|handshake|syn|rst|port|time_wait|close_wait|socket|congestion|mtu|mss/.test(qLower)) {
      topicDeepDive =
        `### Layer 4 TCP State Machine, Handshake Signatures & Socket Exhaustion\n` +
        `- **SYN $\\rightarrow$ RST-ACK (\`ECONNREFUSED\`):** The host is reachable at Layer 3, and no firewall dropped the packet, but **no application process is listening** on that \`IP:port\` (or it bound to \`127.0.0.1\` instead of \`0.0.0.0\`).\n` +
        `- **SYN $\\rightarrow$ Timeout (\`ETIMEDOUT\`):** Silent packet drop by a stateful firewall/ACL, asymmetric return route, or blackhole.\n` +
        `- **\`CLOSE_WAIT\` vs. \`TIME_WAIT\`:** Many sockets stuck in \`CLOSE_WAIT\` prove an **application bug** (remote peer sent \`FIN\`, kernel sent \`ACK\`, but local process never called \`close(fd)\`). \`TIME_WAIT\` ($2 \\times \\text{MSL}$) is normal kernel protection on the active closer.`;
      cliVerificationCommands = [
        'ss -tulpn',
        'ss -tan state close-wait',
        'nc -vz 127.0.0.1 3000',
        'tcpdump -ni any "tcp[tcpflags] & (tcp-syn|tcp-rst) != 0"'
      ];
    } else if (/dns|nxdomain|servfail|dhcp|dora|apipa|169\.254|ntp|snmp/.test(qLower)) {
      topicDeepDive =
        `### Essential Network Services: DNS Resolution & DHCP DORA\n` +
        `- **DNS Error Disambiguation:**\n` +
        `  - \`NXDOMAIN\` (RCODE 3): Authoritative server confirmed the domain name does not exist.\n` +
        `  - \`SERVFAIL\` (RCODE 2): Recursive resolver failed upstream communication or **DNSSEC cryptographic RRSIG/DS validation failed**.\n` +
        `- **DHCP DORA & APIPA:** Client broadcasts \`DISCOVER\` $\\rightarrow$ Server sends \`OFFER\` $\\rightarrow$ Client broadcasts \`REQUEST\` $\\rightarrow$ Server commits \`ACK\`. If a router separates client and server, configure \`ip helper-address\`. Failure results in \`169.254.x.x/16\` (APIPA).`;
      cliVerificationCommands = [
        'dig +trace example.com A',
        'nslookup -type=MX example.com',
        'ipconfig /all',
        'journalctl -u systemd-resolved -n 30'
      ];
    } else if (/active directory|kerberos|gpo|domain controller|spn|ntlm|windows|powershell/.test(qLower)) {
      topicDeepDive =
        `### Windows Server, Active Directory & Kerberos V5 Authentication\n` +
        `- **Kerberos 3-Step Exchange (Port 88):** 1) \`AS-REQ / AS-REP\` validates pre-auth timestamp (must be within **5-minute NTP skew**) and issues a **TGT**. 2) \`TGS-REQ / TGS-REP\` exchanges TGT + **SPN** for a Service Ticket. 3) \`AP-REQ\` authenticates to the target service.\n` +
        `- **GPO Precedence (\`LSDOU\`):** Applied in order **Local $\\rightarrow$ Site $\\rightarrow$ Domain $\\rightarrow$ Organizational Unit (OU)**, where the closest OU wins unless a parent GPO is marked **Enforced**.`;
      cliVerificationCommands = [
        'nltest /dsgetdc:corp.local',
        'klist tickets',
        'setspn -Q HTTP/*',
        'gpresult /r'
      ];
    } else {
      topicDeepDive =
        `### Cross-Layer Protocol & Systems Engineering Analysis\n` +
        `- **Primary Lesson Focus:** ${contextTitle}\n` +
        `- **Key Mastery Objectives:**\n` +
        objectives.map((o) => `  - ${o}`).join('\n') +
        `\n- **Systematic Debugging Rule:** Never guess or change production configuration before isolating whether the failure originates in **Naming (DNS)**, **Path/Reachability (L2/L3)**, **Transport Listener (L4 TCP)**, **Host/Kernel Resources (PID/Socket/RAM)**, or **Application/Security Policy (L7/TLS)**.`;
      cliVerificationCommands = [
        'ip addr show && ip route show',
        'ss -tulpn',
        'curl -Iv https://127.0.0.1:3000/'
      ];
    }

    const answerMarkdown = [
      tierAdaptation,
      ...(quizExplanation ? [
        `### Quiz Question & Option Breakdown\n` +
        `- **Question:** ${quizExplanation.questionPrompt}\n` +
        (quizExplanation.selectedOptionText
          ? `- **Your Selection:** \`${quizExplanation.selectedOptionText}\` (${quizExplanation.isSelectedCorrect ? 'CORRECT' : 'NEEDS CORRECTION'})\n`
          : '') +
        `- **Verified Answer:** **${quizExplanation.correctAnswerSummary}**\n` +
        `- **Why It Works:** ${quizExplanation.canonicalExplanation}`
      ] : []),
      topicDeepDive,
      `### Live CLI Verification & Workbench Synergy\n` +
      `- **Commands to Run:** \`${cliVerificationCommands.join('` · `')}\`\n` +
      `- **Interactive Workbench Bridge:** ${simulation.workbenchSynergy.academyBridgeNote}`
    ].join('\n\n');

    const responsePayload = {
      mentorResponseId: `mentor-${Date.now()}`,
      expertiseTier: tierKey,
      expertiseTierLabel: tierInfo.label,
      context: {
        lessonId: lesson?.id || lessonId,
        lessonTitle: lesson?.title || null,
        courseId: course?.id || courseId,
        courseTitle: course?.title || null,
        quizId: quiz?.id || quizId,
        labId: lab?.id || labId
      },
      question: cleanQuestion,
      answerMarkdown,
      subnetMath,
      quizExplanation,
      cliVerificationCommands,
      interactiveSimulation: simulation,
      workbenchSynergy: simulation.workbenchSynergy,
      followUpPrompts: [
        'Walk me through a real packet capture example of this protocol.',
        'What are the top 3 production outage traps for this topic?',
        'Give me a subnetting or protocol state calculation challenge to test my mastery.'
      ],
      generatedAt: new Date().toISOString()
    };

    const userHistory = this.mentorHistoryByUser.get(userId) || [];
    userHistory.push({
      id: responsePayload.mentorResponseId,
      question: cleanQuestion,
      lessonId: responsePayload.context.lessonId,
      expertiseTier: tierKey,
      timestamp: responsePayload.generatedAt
    });
    if (userHistory.length > 30) userHistory.shift();
    this.mentorHistoryByUser.set(userId, userHistory);

    return responsePayload;
  }

  /**
   * Coaches a student in an interactive Lab Sandbox step
   */
  coachLabCommand({
    labId,
    command = '',
    stepIndex = 0,
    expertiseTier = 'NOC_OPERATOR'
  } = {}) {
    const lab = labId ? getLab(labId) : null;
    if (!lab) {
      return {
        valid: false,
        error: `Lab '${labId}' not found.`
      };
    }

    const steps = lab.steps || [];
    const currentStep = steps[stepIndex] || steps[0] || {};
    const cmdClean = String(command || '').trim();
    const expectedList = currentStep.expectedCommands || [];
    const isMatched = expectedList.some((exp) => cmdClean.toLowerCase() === exp.toLowerCase());

    return {
      valid: true,
      labId: lab.id,
      labTitle: lab.title,
      stepIndex,
      stepInstruction: currentStep.instruction || '',
      submittedCommand: cmdClean,
      isMatched,
      expertiseTier,
      coachingFeedback: isMatched
        ? `Excellent execution! \`${cmdClean}\` directly interrogates the target subsystem. Inspect the output values carefully to confirm whether the state matches baseline expectations.`
        : (cmdClean
          ? `Your command \`${cmdClean}\` is a good instinct, but for this step we specifically want to inspect: **${currentStep.instruction}**. Hint: ${currentStep.hint || `Try using \`${expectedList[0] || 'help'}\`.`}`
          : `Step Goal: **${currentStep.instruction}**. ${currentStep.hint || ''}`),
      protocolMechanicsNote: currentStep.explanation || 'Every diagnostic command reads either kernel state tables, live wire responses, or control-plane configurations.',
      suggestedNextCommand: expectedList[0] || null
    };
  }

  /**
   * SuperMemo-2 (SM-2) Spaced-Repetition Scheduler
   * qualityRating: 0..5 (0-2 = Needs Review/Reset interval, 3 = Hard, 4 = Good, 5 = Easy/Instant)
   */
  computeSm2Schedule({
    userId = 'anonymous',
    cardId,
    qualityRating = 4,
    previousRepetitions = 0,
    previousIntervalDays = 0,
    previousEaseFactor = 2.5
  } = {}) {
    const q = Math.max(0, Math.min(5, Number(qualityRating) || 0));
    let repetitions = Number(previousRepetitions) || 0;
    let intervalDays = Number(previousIntervalDays) || 0;
    let easeFactor = Number(previousEaseFactor) || 2.5;

    if (q < 3) {
      repetitions = 0;
      intervalDays = 1;
    } else {
      if (repetitions === 0) {
        intervalDays = 1;
      } else if (repetitions === 1) {
        intervalDays = 6;
      } else {
        intervalDays = Math.round(intervalDays * easeFactor);
      }
      repetitions += 1;
    }

    easeFactor = easeFactor + (0.1 - (5 - q) * (0.08 + (5 - q) * 0.02));
    if (easeFactor < 1.3) easeFactor = 1.3;
    easeFactor = Number(easeFactor.toFixed(2));

    const nextReviewAt = new Date(Date.now() + intervalDays * 86400 * 1000).toISOString();
    const record = {
      cardId: String(cardId || 'general-card'),
      qualityRating: q,
      repetitions,
      intervalDays,
      easeFactor,
      nextReviewAt,
      masteryTier: repetitions >= 3 && easeFactor >= 2.4 ? 'MASTERED' : (repetitions >= 1 ? 'RETAINING' : 'LEARNING'),
      updatedAt: new Date().toISOString()
    };

    const userCards = this.sm2CardsByUser.get(userId) || new Map();
    userCards.set(record.cardId, record);
    this.sm2CardsByUser.set(userId, userCards);

    return record;
  }

  /**
   * Generates comprehensive Mastery Analytics, Spaced-Repetition Queue, and Cross-Workstation Synergy Map
   */
  getMasteryAnalytics(userId = 'anonymous') {
    const courses = getCourses();
    const lessons = getLessons();
    let dashboard = null;
    try {
      if (userId && userId !== 'anonymous') {
        dashboard = progressService.getUserDashboard(userId);
      }
    } catch (_) {
      dashboard = null;
    }

    const userCards = this.sm2CardsByUser.get(userId) || new Map();
    const sm2Records = Array.from(userCards.values());

    const domainPillars = courses.map((course) => {
      const courseLessons = lessons.filter((l) => l.courseId === course.id);
      let completedPct = 0;
      if (dashboard && Array.isArray(dashboard.courses)) {
        const found = dashboard.courses.find((c) => c.courseId === course.id);
        if (found) completedPct = found.percentComplete || 0;
      }
      const sim = this.getSimulationForLesson({ id: course.id, courseId: course.id, title: course.title });
      return {
        courseId: course.id,
        trackId: course.trackId,
        title: course.title,
        difficulty: course.difficulty,
        lessonCount: courseLessons.length,
        completedPct,
        simulationId: sim.simulationId,
        workbenchSynergy: sim.workbenchSynergy
      };
    });

    return {
      userId,
      expertiseTiers: Object.values(EXPERTISE_TIERS),
      domainPillars,
      simulationsCount: Object.keys(PROTOCOL_SIMULATION_LIBRARY).length,
      simulations: Object.values(PROTOCOL_SIMULATION_LIBRARY),
      spacedRepetitionSummary: {
        trackedCardsCount: sm2Records.length,
        masteredCount: sm2Records.filter((r) => r.masteryTier === 'MASTERED').length,
        dueSoonCards: sm2Records.slice(0, 10)
      },
      generatedAt: new Date().toISOString()
    };
  }
}

const aiMentorService = new AiMentorService();

module.exports = {
  AiMentorService,
  aiMentorService,
  EXPERTISE_TIERS,
  PROTOCOL_SIMULATION_LIBRARY
};
