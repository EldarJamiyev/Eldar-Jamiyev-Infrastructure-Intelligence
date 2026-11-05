/**
 * EJII Learning Center — Quizzes & Knowledge Check Definitions
 * Defines question prompts, options, server-side verified answer keys, and pedagogical explanations.
 * Server-side evaluation ensures correctOptionIds are never sent to unauthenticated or pre-submission clients.
 */

'use strict';

const QUIZZES = [
  {
    id: 'quiz-network-fundamentals',
    courseId: 'network-fundamentals',
    title: 'Network Fundamentals & OSI Comprehensive Quiz',
    passPercent: 80,
    questions: [
      {
        id: 'q-net-fund-1',
        type: 'single_choice',
        prompt: 'At which layer of the OSI model does IP packet addressing and logical routing occur?',
        options: [
          { id: 'opt-a', text: 'Layer 2 (Data Link Layer)' },
          { id: 'opt-b', text: 'Layer 3 (Network Layer)' },
          { id: 'opt-c', text: 'Layer 4 (Transport Layer)' },
          { id: 'opt-d', text: 'Layer 7 (Application Layer)' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'Layer 3 (Network Layer) is responsible for logical host addressing (IPv4/IPv6) and path determination (routing) across interconnected networks.',
        points: 1
      },
      {
        id: 'q-net-fund-2',
        type: 'multiple_select',
        prompt: 'Which of the following headers or trailers are added at the Data Link layer during encapsulation? (Select two)',
        options: [
          { id: 'opt-a', text: 'Source MAC Address' },
          { id: 'opt-b', text: 'Frame Check Sequence (FCS) / CRC trailer' },
          { id: 'opt-c', text: 'TCP Sequence Number' },
          { id: 'opt-d', text: 'Time to Live (TTL)' }
        ],
        correctOptionIds: ['opt-a', 'opt-b'],
        explanation: 'Layer 2 Ethernet encapsulation encapsulates the L3 packet inside an Ethernet frame with Source/Destination MAC addresses and a Frame Check Sequence (FCS) trailer for error detection.',
        points: 2
      },
      {
        id: 'q-net-fund-3',
        type: 'true_false',
        prompt: 'A transparent Ethernet switch forwards unicast frames destined for an unknown MAC address out of all ports except the receiving port (flooding).',
        options: [
          { id: 'opt-true', text: 'True' },
          { id: 'opt-false', text: 'False' }
        ],
        correctOptionIds: ['opt-true'],
        explanation: 'True. When a switch receives a frame destined for a MAC address not currently in its MAC table, it floods the frame out of all ports within the same broadcast domain (VLAN) except the ingress port.',
        points: 1
      },
      {
        id: 'q-net-fund-4',
        type: 'single_choice',
        prompt: 'What protocol is used by a host to discover the Layer 2 MAC address corresponding to a known target IPv4 address on the local subnet?',
        options: [
          { id: 'opt-a', text: 'DNS' },
          { id: 'opt-b', text: 'ARP (Address Resolution Protocol)' },
          { id: 'opt-c', text: 'DHCP' },
          { id: 'opt-d', text: 'ICMP' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'ARP broadcasts a request ("Who has IP x.x.x.x? Tell y.y.y.y") to map the target IPv4 address to its physical Layer 2 MAC address on the local link.',
        points: 1
      },
      {
        id: 'q-net-fund-5',
        type: 'short_answer',
        prompt: 'What is the acronym for the 4-byte trailer placed at the end of an Ethernet frame used for cyclic redundancy error checking?',
        correctAnswers: ['FCS', 'CRC', 'FRAME CHECK SEQUENCE'],
        explanation: 'The Frame Check Sequence (FCS) uses a 32-bit CRC calculation to verify frame integrity upon arrival.',
        points: 1
      }
    ]
  },
  {
    id: 'quiz-ip-addressing',
    courseId: 'ip-addressing',
    title: 'IP Addressing, Subnetting & VLSM Assessment',
    passPercent: 80,
    questions: [
      {
        id: 'q-ip-addr-1',
        type: 'single_choice',
        prompt: 'For the host address 192.168.10.34/27, what is the valid subnet network address?',
        options: [
          { id: 'opt-a', text: '192.168.10.0' },
          { id: 'opt-b', text: '192.168.10.32' },
          { id: 'opt-c', text: '192.168.10.16' },
          { id: 'opt-d', text: '192.168.10.63' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'A /27 mask is 255.255.255.224. The block size (magic number) is 256 - 224 = 32. Subnet boundaries are multiples of 32: 0, 32, 64... Host 34 falls in the 192.168.10.32 subnet.',
        points: 1
      },
      {
        id: 'q-ip-addr-2',
        type: 'single_choice',
        prompt: 'How many usable host addresses are provided by a /29 subnet mask?',
        options: [
          { id: 'opt-a', text: '6' },
          { id: 'opt-b', text: '8' },
          { id: 'opt-c', text: '14' },
          { id: 'opt-d', text: '30' }
        ],
        correctOptionIds: ['opt-a'],
        explanation: 'In a /29, there are 32 - 29 = 3 host bits. Total addresses = 2^3 = 8. Subtracting network and broadcast addresses (2^3 - 2) yields 6 usable host addresses.',
        points: 1
      },
      {
        id: 'q-ip-addr-3',
        type: 'multiple_select',
        prompt: 'Which of the following are valid IPv6 address representations or compression rules? (Select two)',
        options: [
          { id: 'opt-a', text: 'Leading zeros in any 16-bit hextet can be omitted' },
          { id: 'opt-b', text: 'The double colon (::) can appear multiple times in a single address' },
          { id: 'opt-c', text: 'A single contiguous string of all-zero hextets can be replaced by "::"' },
          { id: 'opt-d', text: 'IPv6 uses 32-bit hexadecimal notation separated by periods' }
        ],
        correctOptionIds: ['opt-a', 'opt-c'],
        explanation: 'RFC 5952 dictates that leading zeros may be omitted, and a single contiguous block of zeros may be compressed with "::" exactly once per address to prevent ambiguity.',
        points: 2
      },
      {
        id: 'q-ip-addr-4',
        type: 'single_choice',
        prompt: 'What prefix length is designated by RFC 6164 / RFC 3021 for point-to-point links between two routers where broadcast addresses are not required?',
        options: [
          { id: 'opt-a', text: '/30' },
          { id: 'opt-b', text: '/31' },
          { id: 'opt-c', text: '/28' },
          { id: 'opt-d', text: '/29' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'RFC 3021 defines the use of 31-bit prefixes for IPv4 point-to-point links, conserving address space by allowing exactly two host addresses without dedicated network and broadcast overhead.',
        points: 1
      },
      {
        id: 'q-ip-addr-5',
        type: 'true_false',
        prompt: 'The IPv6 Link-Local address prefix is fe80::/10.',
        options: [
          { id: 'opt-true', text: 'True' },
          { id: 'opt-false', text: 'False' }
        ],
        correctOptionIds: ['opt-true'],
        explanation: 'True. IPv6 Link-Local addresses always begin with fe80::/10 and are used exclusively for communication on the local physical link.',
        points: 1
      }
    ]
  },
  {
    id: 'quiz-switching-routing',
    courseId: 'switching-routing',
    title: 'Switching, VLANs & Routing Protocol Assessment',
    passPercent: 80,
    questions: [
      {
        id: 'q-sw-rt-1',
        type: 'single_choice',
        prompt: 'What protocol tag does IEEE 802.1Q insert into an Ethernet frame to identify VLAN membership across trunk links?',
        options: [
          { id: 'opt-a', text: '4-byte Tag Protocol Identifier (TPID 0x8100) & TCI' },
          { id: 'opt-b', text: '26-byte ISL header' },
          { id: 'opt-c', text: '8-byte GRE encapsulation' },
          { id: 'opt-d', text: '20-byte IP header' }
        ],
        correctOptionIds: ['opt-a'],
        explanation: '802.1Q inserts a 4-byte tag into the original frame between the Source MAC and EtherType, consisting of a TPID (0x8100) and Tag Control Information (Priority + 12-bit VLAN ID).',
        points: 1
      },
      {
        id: 'q-sw-rt-2',
        type: 'single_choice',
        prompt: 'When a router has multiple routes to a destination in its routing table, which rule takes precedence during the packet forwarding decision?',
        options: [
          { id: 'opt-a', text: 'Lowest Administrative Distance regardless of prefix length' },
          { id: 'opt-b', text: 'Longest-Prefix Match (most specific subnet mask)' },
          { id: 'opt-c', text: 'Lowest interface metric' },
          { id: 'opt-d', text: 'First route learned chronologically' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'During forwarding, the router always selects the route with the Longest-Prefix Match (most specific prefix length, e.g., /28 over /24). Administrative distance only decides which route enters the routing table from competing routing protocols.',
        points: 1
      },
      {
        id: 'q-sw-rt-3',
        type: 'multiple_select',
        prompt: 'Which states are part of the Rapid Spanning Tree Protocol (RSTP / 802.1w) port state model? (Select three)',
        options: [
          { id: 'opt-a', text: 'Discarding' },
          { id: 'opt-b', text: 'Learning' },
          { id: 'opt-c', text: 'Forwarding' },
          { id: 'opt-d', text: 'Listening' }
        ],
        correctOptionIds: ['opt-a', 'opt-b', 'opt-c'],
        explanation: 'RSTP collapses the legacy 802.1D Disabled, Blocking, and Listening states into a single unified "Discarding" state, maintaining Learning and Forwarding.',
        points: 2
      },
      {
        id: 'q-sw-rt-4',
        type: 'single_choice',
        prompt: 'What metric does Open Shortest Path First (OSPF) use by default to determine the path cost of an interface?',
        options: [
          { id: 'opt-a', text: 'Hop count' },
          { id: 'opt-b', text: 'Bandwidth (Reference Bandwidth / Interface Bandwidth)' },
          { id: 'opt-c', text: 'Delay and Reliability' },
          { id: 'opt-d', text: 'MTU' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'OSPF uses Cost based on interface bandwidth (Default formula: 100 Mbps / Bandwidth in Mbps).',
        points: 1
      },
      {
        id: 'q-sw-rt-5',
        type: 'true_false',
        prompt: 'A floating static route is configured with a higher Administrative Distance than the primary dynamic routing protocol to act as a backup path.',
        options: [
          { id: 'opt-true', text: 'True' },
          { id: 'opt-false', text: 'False' }
        ],
        correctOptionIds: ['opt-true'],
        explanation: 'True. A floating static route has an AD higher than the primary route (e.g., AD 120 vs OSPF AD 110), remaining dormant until the primary route drops out of the routing table.',
        points: 1
      }
    ]
  },
  {
    id: 'quiz-network-services',
    courseId: 'network-services',
    title: 'Network Services, Security & Automation Assessment',
    passPercent: 80,
    questions: [
      {
        id: 'q-net-serv-1',
        type: 'single_choice',
        prompt: 'What is the correct 4-step message exchange sequence for dynamic IPv4 client address assignment via DHCP?',
        options: [
          { id: 'opt-a', text: 'SYN, SYN-ACK, ACK, FIN' },
          { id: 'opt-b', text: 'Discover, Offer, Request, Acknowledge (DORA)' },
          { id: 'opt-c', text: 'Query, Response, Authorize, Commit' },
          { id: 'opt-d', text: 'Solicit, Advertise, Request, Reply' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'DHCP uses the DORA sequence: DHCPDISCOVER (broadcast by client), DHCPOFFER (unicast/broadcast by server), DHCPREQUEST (client requesting offered IP), and DHCPACK (server confirmation).',
        points: 1
      },
      {
        id: 'q-net-serv-2',
        type: 'single_choice',
        prompt: 'What form of Network Address Translation allows thousands of internal private IP addresses to share a single public routable IP address using Layer 4 port numbers?',
        options: [
          { id: 'opt-a', text: 'Static 1:1 NAT' },
          { id: 'opt-b', text: 'Port Address Translation (PAT / NAT Overload)' },
          { id: 'opt-c', text: 'Carrier-Grade IPv6 NAT' },
          { id: 'opt-d', text: 'Dynamic Pool NAT without Overload' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'PAT (Port Address Translation / NAT Overload) tracks TCP/UDP source ports to map multiple private IP addresses to a single public IP address.',
        points: 1
      },
      {
        id: 'q-net-serv-3',
        type: 'multiple_select',
        prompt: 'Which security enhancements were introduced in WPA3 compared to WPA2? (Select two)',
        options: [
          { id: 'opt-a', text: 'Simultaneous Authentication of Equals (SAE) preventing offline dictionary attacks' },
          { id: 'opt-b', text: 'Removal of Pre-Shared Key functionality entirely' },
          { id: 'opt-c', text: 'Mandatory Protected Management Frames (PMF) to mitigate deauthentication attacks' },
          { id: 'opt-d', text: 'Replacement of AES with WEP encryption' }
        ],
        correctOptionIds: ['opt-a', 'opt-c'],
        explanation: 'WPA3 replaces the vulnerable 4-way handshake PSK with SAE (Dragonfly handshake) to resist offline dictionary attacks, and mandates PMF to block management-frame spoofing.',
        points: 2
      },
      {
        id: 'q-net-serv-4',
        type: 'single_choice',
        prompt: 'In Cisco IOS standard access control lists (numbered 1-99), what criteria can be inspected for traffic filtering?',
        options: [
          { id: 'opt-a', text: 'Source IPv4 address only' },
          { id: 'opt-b', text: 'Source and Destination IPv4 addresses and TCP/UDP ports' },
          { id: 'opt-c', text: 'Destination IPv4 address and protocol type only' },
          { id: 'opt-d', text: 'HTTP URL strings' }
        ],
        correctOptionIds: ['opt-a'],
        explanation: 'Standard ACLs (1-99 and 1300-1999) can only filter traffic based on the Source IPv4 address. Extended ACLs (100-199) filter by Source, Destination, Protocol, and Port.',
        points: 1
      },
      {
        id: 'q-net-serv-5',
        type: 'true_false',
        prompt: 'RESTCONF uses HTTP verbs (GET, POST, PUT, PATCH, DELETE) to retrieve and manipulate network configuration data modeled in YANG format.',
        options: [
          { id: 'opt-true', text: 'True' },
          { id: 'opt-false', text: 'False' }
        ],
        correctOptionIds: ['opt-true'],
        explanation: 'True. RFC 8040 defines RESTCONF as an HTTP-based protocol that provides a programmatic interface for accessing data defined in YANG, using XML or JSON payloads.',
        points: 1
      }
    ]
  },
  {
    id: 'quiz-windows-administration',
    courseId: 'windows-administration',
    title: 'Windows Administration & Troubleshooting Assessment',
    passPercent: 80,
    questions: [
      {
        id: 'q-win-admin-1',
        type: 'single_choice',
        prompt: 'In Windows operating system architecture, which mode executes critical hardware drivers and memory management, protected from direct application tampering?',
        options: [
          { id: 'opt-a', text: 'User Mode (Ring 3)' },
          { id: 'opt-b', text: 'Kernel Mode (Ring 0)' },
          { id: 'opt-c', text: 'Session Isolation Mode' },
          { id: 'opt-d', text: 'Hypervisor User Space' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'Kernel Mode (Ring 0) executes the core OS executive, kernel, device drivers, and HAL with unrestricted access to physical hardware and system memory.',
        points: 1
      },
      {
        id: 'q-win-admin-2',
        type: 'multiple_select',
        prompt: 'When determining effective access to a shared folder across a network, how do NTFS permissions and SMB Share permissions interact? (Select two)',
        options: [
          { id: 'opt-a', text: 'The most restrictive permission between the share and NTFS applies' },
          { id: 'opt-b', text: 'Share permissions override and cancel out NTFS Deny permissions' },
          { id: 'opt-c', text: 'Both Share and NTFS permissions are evaluated independently' },
          { id: 'opt-d', text: 'NTFS permissions are ignored for network users' }
        ],
        correctOptionIds: ['opt-a', 'opt-c'],
        explanation: 'For network access, Windows evaluates both Share permissions and NTFS permissions. The resulting effective permission is the most restrictive combination of the two.',
        points: 2
      },
      {
        id: 'q-win-admin-3',
        type: 'single_choice',
        prompt: 'Which Windows Event Log channel contains records of user logons, privilege use, and object access auditing?',
        options: [
          { id: 'opt-a', text: 'Application Log' },
          { id: 'opt-b', text: 'System Log' },
          { id: 'opt-c', text: 'Security Log' },
          { id: 'opt-d', text: 'Setup Log' }
        ],
        correctOptionIds: ['opt-c'],
        explanation: 'The Security Log records security audit events configured by audit policy, including successful and failed logons (Event IDs 4624/4625) and privilege assignments.',
        points: 1
      },
      {
        id: 'q-win-admin-4',
        type: 'single_choice',
        prompt: 'In PowerShell, what cmdlet retrieves active TCP/IP connection socket states and listening ports on the local host?',
        options: [
          { id: 'opt-a', text: 'Get-Process' },
          { id: 'opt-b', text: 'Get-NetTCPConnection' },
          { id: 'opt-c', text: 'Test-NetConnection' },
          { id: 'opt-d', text: 'Get-Service' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'Get-NetTCPConnection queries the local TCP/IP stack for active connections, listening endpoints, local/remote ports, and owning process IDs (similar to netstat -ano).',
        points: 1
      },
      {
        id: 'q-win-admin-5',
        type: 'true_false',
        prompt: 'In NTFS file permissions, an explicit Deny permission takes precedence over inherited Allow permissions.',
        options: [
          { id: 'opt-true', text: 'True' },
          { id: 'opt-false', text: 'False' }
        ],
        correctOptionIds: ['opt-true'],
        explanation: 'True. In NTFS access control evaluation, explicit permissions take precedence over inherited permissions, and explicit Deny takes precedence over explicit Allow.',
        points: 1
      }
    ]
  },
  {
    id: 'quiz-windows-server',
    courseId: 'windows-server',
    title: 'Windows Server, Active Directory & Services Assessment',
    passPercent: 80,
    questions: [
      {
        id: 'q-win-srv-1',
        type: 'single_choice',
        prompt: 'What is the default processing order for Group Policy Objects (GPO) in Active Directory?',
        options: [
          { id: 'opt-a', text: 'OU, Domain, Site, Local' },
          { id: 'opt-b', text: 'Local, Site, Domain, OU (LSDOU)' },
          { id: 'opt-c', text: 'Domain, OU, Site, Local' },
          { id: 'opt-d', text: 'Site, Local, Domain, OU' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'GPOs are applied in the LSDOU sequence: Local policy first, then Site, then Domain, and finally Organizational Unit (OU). The settings applied last (child OU) take precedence unless Block Inheritance or Enforce is set.',
        points: 1
      },
      {
        id: 'q-win-srv-2',
        type: 'multiple_select',
        prompt: 'Which DNS record types are critical for domain controllers to register so clients can discover Active Directory authentication services? (Select two)',
        options: [
          { id: 'opt-a', text: 'SRV records (_ldap._tcp.dc._msdcs.<domain>)' },
          { id: 'opt-b', text: 'MX records (Mail Exchanger)' },
          { id: 'opt-c', text: 'Host (A/AAAA) records for the Domain Controller' },
          { id: 'opt-d', text: 'PTR records for the public Internet' }
        ],
        correctOptionIds: ['opt-a', 'opt-c'],
        explanation: 'AD domain controllers register Service (SRV) records to announce LDAP, Kerberos, and GC services, along with Host (A/AAAA) records mapping the DC hostname to its IP address.',
        points: 2
      },
      {
        id: 'q-win-srv-3',
        type: 'single_choice',
        prompt: 'What primary authentication protocol does Active Directory Domain Services utilize for SSO within trusted enterprise networks?',
        options: [
          { id: 'opt-a', text: 'NTLMv1' },
          { id: 'opt-b', text: 'Kerberos V5 (Ticket Granting Service / TGT)' },
          { id: 'opt-c', text: 'RADIUS' },
          { id: 'opt-d', text: 'PAP' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'Active Directory uses Kerberos V5 with ticket-granting tickets (TGT) and service tickets issued by the Key Distribution Center (KDC) running on domain controllers.',
        points: 1
      },
      {
        id: 'q-win-srv-4',
        type: 'single_choice',
        prompt: 'What command-line tool is used on a Windows client to generate a comprehensive Resultant Set of Policy (RSoP) report displaying applied GPOs and security settings?',
        options: [
          { id: 'opt-a', text: 'gpupdate /force' },
          { id: 'opt-b', text: 'gpresult /h report.html' },
          { id: 'opt-c', text: 'dcdiag' },
          { id: 'opt-d', text: 'netdom query' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'gpresult /h report.html generates an HTML report detailing all applied user and computer Group Policy settings, winning GPOs, and security group memberships.',
        points: 1
      },
      {
        id: 'q-win-srv-5',
        type: 'true_false',
        prompt: 'Active Directory Global Security Groups can contain user accounts from their own domain and can be placed inside Domain Local groups in any trusting domain.',
        options: [
          { id: 'opt-true', text: 'True' },
          { id: 'opt-false', text: 'False' }
        ],
        correctOptionIds: ['opt-true'],
        explanation: 'True. Under the AGDLP principle (Accounts -> Global -> Domain Local -> Permissions), Global groups aggregate accounts from the same domain and are nested into Domain Local groups that grant access to local resources.',
        points: 1
      }
    ]
  },
  {
    id: 'quiz-linux-administration',
    courseId: 'linux-administration',
    title: 'Linux Administration, Systemd & Networking Assessment',
    passPercent: 80,
    questions: [
      {
        id: 'q-linux-adm-1',
        type: 'single_choice',
        prompt: 'In Linux permissions, what octal numerical value represents read, write, and execute permissions for the owner, and read-and-execute permissions for group and others?',
        options: [
          { id: 'opt-a', text: '644 (rw-r--r--)' },
          { id: 'opt-b', text: '755 (rwxr-xr-x)' },
          { id: 'opt-c', text: '700 (rwx------)' },
          { id: 'opt-d', text: '777 (rwxrwxrwx)' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'In octal: r=4, w=2, x=1. Owner: 4+2+1 = 7. Group: 4+0+1 = 5. Others: 4+0+1 = 5. Total = 755.',
        points: 1
      },
      {
        id: 'q-linux-adm-2',
        type: 'single_choice',
        prompt: 'Which systemd utility is used to query and view structured system and service logs collected by systemd-journald?',
        options: [
          { id: 'opt-a', text: 'systemctl' },
          { id: 'opt-b', text: 'journalctl' },
          { id: 'opt-c', text: 'dmesg' },
          { id: 'opt-d', text: 'syslog-ng' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'journalctl is the dedicated command-line interface for querying the systemd journal logs (e.g. journalctl -u nginx.service -n 50).',
        points: 1
      },
      {
        id: 'q-linux-adm-3',
        type: 'multiple_select',
        prompt: 'Which modern Linux iproute2 commands replace the deprecated ifconfig, netstat, and route utilities? (Select three)',
        options: [
          { id: 'opt-a', text: 'ip addr (replaces ifconfig for interface addressing)' },
          { id: 'opt-b', text: 'ip route (replaces route for routing table inspection)' },
          { id: 'opt-c', text: 'ss (replaces netstat for socket statistics)' },
          { id: 'opt-d', text: 'traceroute (replaces ping)' }
        ],
        correctOptionIds: ['opt-a', 'opt-b', 'opt-c'],
        explanation: 'The iproute2 suite provides "ip addr" and "ip link" (replacing ifconfig), "ip route" (replacing route), and "ss" (replacing netstat with direct netlink kernel socket queries).',
        points: 3
      },
      {
        id: 'q-linux-adm-4',
        type: 'single_choice',
        prompt: 'In an OpenSSH server configuration (/etc/ssh/sshd_config), which setting disables password-based authentication to enforce cryptographic key-only logins?',
        options: [
          { id: 'opt-a', text: 'PermitRootLogin no' },
          { id: 'opt-b', text: 'PasswordAuthentication no' },
          { id: 'opt-c', text: 'ChallengeResponseAuthentication yes' },
          { id: 'opt-d', text: 'UsePAM yes' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'Setting "PasswordAuthentication no" in sshd_config instructs sshd to reject plain password logins, forcing clients to authenticate with SSH public-key cryptography.',
        points: 1
      },
      {
        id: 'q-linux-adm-5',
        type: 'true_false',
        prompt: 'In Linux, the /etc/fstab file defines persistent static filesystem mounts that are automatically mounted during system boot.',
        options: [
          { id: 'opt-true', text: 'True' },
          { id: 'opt-false', text: 'False' }
        ],
        correctOptionIds: ['opt-true'],
        explanation: 'True. /etc/fstab (file systems table) specifies block devices or UUIDs, mount points, filesystem types, and mount options processed by systemd-fstab-generator during boot.',
        points: 1
      }
    ]
  },
  {
    id: 'quiz-enterprise-operations',
    courseId: 'enterprise-operations',
    title: 'Enterprise Operations, DR & Incident Management Assessment',
    passPercent: 80,
    questions: [
      {
        id: 'q-ops-1',
        type: 'single_choice',
        prompt: 'Under the 3-2-1 backup strategy, how should enterprise backups be stored?',
        options: [
          { id: 'opt-a', text: '3 copies of data, on 2 different media types, with 1 copy stored offsite' },
          { id: 'opt-b', text: '3 days of retention, 2 cloud providers, 1 local USB drive' },
          { id: 'opt-c', text: '3 servers, 2 administrators, 1 password' },
          { id: 'opt-d', text: '3 hourly snapshots, 2 daily backups, 1 weekly archive' }
        ],
        correctOptionIds: ['opt-a'],
        explanation: 'The industry-standard 3-2-1 rule dictates maintaining at least 3 total copies of critical data, across 2 different storage media types, with at least 1 copy located off-site or in an immutable cloud bucket.',
        points: 1
      },
      {
        id: 'q-ops-2',
        type: 'single_choice',
        prompt: 'In disaster recovery planning, what does the Recovery Point Objective (RPO) specify?',
        options: [
          { id: 'opt-a', text: 'The maximum acceptable duration of time to restore a system after an outage' },
          { id: 'opt-b', text: 'The maximum acceptable amount of data loss measured in time backward from the disaster' },
          { id: 'opt-c', text: 'The financial cost of recovering damaged hardware' },
          { id: 'opt-d', text: 'The number of staff members needed to initiate a failover' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'RPO (Recovery Point Objective) defines the maximum tolerable age of files or database records that must be recovered from backup storage (i.e. maximum tolerable data loss). RTO (Recovery Time Objective) defines how quickly the system must be restored to service.',
        points: 1
      },
      {
        id: 'q-ops-3',
        type: 'multiple_select',
        prompt: 'Which practices are critical for maintaining safe enterprise patching workflows? (Select two)',
        options: [
          { id: 'opt-a', text: 'Deploying patches to a non-production pilot/canary ring before broad rollout' },
          { id: 'opt-b', text: 'Applying updates immediately to production domain controllers without a test window' },
          { id: 'opt-c', text: 'Documenting a validated rollback plan and taking a verified system snapshot prior to patching' },
          { id: 'opt-d', text: 'Disabling all monitoring alarms during patch deployment permanently' }
        ],
        correctOptionIds: ['opt-a', 'opt-c'],
        explanation: 'Safe change management requires phased ring deployment (canary/pilot) to catch regressions, alongside a verified rollback plan (e.g. VM snapshot or backup) before touching production systems.',
        points: 2
      },
      {
        id: 'q-ops-4',
        type: 'single_choice',
        prompt: 'During root-cause analysis (RCA), what is the primary purpose of an incident post-mortem report?',
        options: [
          { id: 'opt-a', text: 'To assign individual blame and disciplinary action to the responsible engineer' },
          { id: 'opt-b', text: 'To understand systemic contributing factors, timeline, and implement preventative controls blamelessly' },
          { id: 'opt-c', text: 'To satisfy legal requirements while hiding technical deficiencies' },
          { id: 'opt-d', text: 'To reset monitoring thresholds to prevent future alerts from triggering' }
        ],
        correctOptionIds: ['opt-b'],
        explanation: 'A blameless post-mortem focuses on systemic vulnerabilities, architectural single-points-of-failure, monitoring gaps, and actionable preventative remediations rather than individual fault.',
        points: 1
      },
      {
        id: 'q-ops-5',
        type: 'true_false',
        prompt: 'Synthetic transaction monitoring simulates real user interactions at scheduled intervals to detect service degradation before real end users are impacted.',
        options: [
          { id: 'opt-true', text: 'True' },
          { id: 'opt-false', text: 'False' }
        ],
        correctOptionIds: ['opt-true'],
        explanation: 'True. Synthetic monitoring generates active simulated requests (e.g. synthetic HTTP transactions, DNS queries, authentication handshakes) to continuously verify service health and latency proactively.',
        points: 1
      }
    ]
  }
];

module.exports = {
  QUIZZES
};
