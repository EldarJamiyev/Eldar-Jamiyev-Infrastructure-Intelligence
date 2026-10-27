/**
 * EJII Learning Center — Educational Lab Definitions
 * Structured metadata, learning objectives, initial state, and evaluation rules for simulated labs.
 * Mandate: Educational simulations only. No actual execution against host or external network.
 */

'use strict';

const LABS = [
  {
    id: 'net-subnetting-trainer',
    title: 'IPv4 Subnetting & CIDR Trainer',
    trackId: 'network',
    difficulty: 'beginner',
    estimatedMinutes: 20,
    objectives: [
      'Calculate network addresses from IP and prefix length (/0 to /32).',
      'Determine broadcast address, usable host ranges, and total address capacity.',
      'Differentiate point-to-point /31 and host-route /32 conventions.'
    ],
    supportedModes: ['calculator', 'practice'],
    instructions: 'Enter any IPv4 address and CIDR prefix (or click Random Practice) to calculate the subnet boundaries step-by-step.'
  },
  {
    id: 'net-packet-journey',
    title: 'L2/L3 Packet Journey Visualizer',
    trackId: 'network',
    difficulty: 'intermediate',
    estimatedMinutes: 25,
    objectives: [
      'Trace packet movement across local broadcast domains vs routed hops.',
      'Observe ARP request/reply and frame encapsulation at each link.',
      'Understand why L2 MAC addresses change hop-by-hop while L3 IP addresses stay constant.'
    ],
    supportedModes: ['same-subnet', 'different-subnet'],
    instructions: 'Step forward through the journey to see how encapsulation, ARP tables, and routing decisions operate at each node.'
  },
  {
    id: 'net-vlan-lab',
    title: 'VLAN Segmentation & 802.1Q Trunking Lab',
    trackId: 'network',
    difficulty: 'intermediate',
    estimatedMinutes: 30,
    objectives: [
      'Assign switchports to Access VLANs and configure 802.1Q Trunk links.',
      'Troubleshoot VLAN mismatches and trunk allowed-list pruning.',
      'Evaluate inter-switch traffic isolation.'
    ],
    supportedModes: ['interactive', 'troubleshoot'],
    instructions: 'Configure switchports SW1 and SW2, select access VLANs or trunk allowed lists, and click Test Connectivity.'
  },
  {
    id: 'net-routing-explorer',
    title: 'Longest-Prefix Match Routing Explorer',
    trackId: 'network',
    difficulty: 'intermediate',
    estimatedMinutes: 20,
    objectives: [
      'Predict outgoing interface and next-hop based on routing table entries.',
      'Understand Longest-Prefix Match (LPM) tie-breaking rules.',
      'Differentiate direct connected, static, dynamic, and default routes (0.0.0.0/0).'
    ],
    supportedModes: ['interactive', 'exercise'],
    instructions: 'Enter a destination IP or choose a scenario. The explorer evaluates candidate routes and explains which route wins.'
  },
  {
    id: 'sys-powershell-sandbox',
    title: 'PowerShell Diagnostic Command Sandbox',
    trackId: 'system',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Run common administrative PowerShell cmdlets in a safe, simulated environment.',
      'Inspect simulated service states, running processes, event logs, and IP configuration.',
      'Master pipeline filtering and object property selection.'
    ],
    supportedModes: ['terminal', 'guided-tasks'],
    instructions: 'Type supported cmdlets (e.g. Get-Service, Get-Process, Get-NetIPConfiguration) or click sample commands to execute.'
  },
  {
    id: 'sys-linux-sandbox',
    title: 'Linux Command & Filesystem Trainer',
    trackId: 'system',
    difficulty: 'beginner',
    estimatedMinutes: 25,
    objectives: [
      'Navigate the Linux Filesystem Hierarchy Standard (FHS).',
      'Inspect file permissions, view configuration files, and check systemd services.',
      'Diagnose networking with ip, ss, and inspect journalctl logs.'
    ],
    supportedModes: ['terminal', 'filesystem-browser'],
    instructions: 'Interact with the virtual Linux host using commands like pwd, ls, cd, cat, systemctl, ss, and ip.'
  },
  {
    id: 'sys-active-directory-lab',
    title: 'Active Directory & Permissions Explorer',
    trackId: 'system',
    difficulty: 'advanced',
    estimatedMinutes: 30,
    objectives: [
      'Inspect domain structure, OUs, user accounts, and security group memberships.',
      'Evaluate Group Policy Object (GPO) inheritance and LSDOU precedence.',
      'Calculate effective NTFS and SMB share access permissions.'
    ],
    supportedModes: ['ou-tree', 'effective-access'],
    instructions: 'Select users and organizational units, toggle group memberships, and inspect calculated access and policy results.'
  },
  {
    id: 'sys-dns-dhcp-lab',
    title: 'DNS & DHCP Troubleshooting Simulator',
    trackId: 'system',
    difficulty: 'advanced',
    estimatedMinutes: 35,
    objectives: [
      'Diagnose 8 real-world enterprise infrastructure service faults.',
      'Identify DHCP pool exhaustion, rogue DHCP servers, DNS resolution failures, and IP conflicts.',
      'Formulate evidence-based diagnoses and apply corrective remediations.'
    ],
    supportedModes: ['scenarios'],
    instructions: 'Review client symptoms, run diagnostics, choose your diagnosis, and verify the remediation.'
  }
];

module.exports = {
  LABS
};
