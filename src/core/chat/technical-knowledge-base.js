/**
 * EJII Dual-Mode Technical Knowledge Base & Cautious Typo Classifier
 *
 * Powers Informational & Technical Engineering Mode (Part III, Section 4, Mode 2)
 * when users ask conceptual, protocol, or command explanations without requesting
 * a live network probe against a target.
 *
 * Strictly labeled as general technical explanation — never presented as live telemetry.
 */

'use strict';

// Unambiguous TLD typo map (.ocm -> .com, .con -> .com, etc.)
const UNAMBIGUOUS_TLD_TYPO_MAP = Object.freeze({
  ocm: 'com',
  con: 'com',
  cmo: 'com',
  vom: 'com',
  xom: 'com',
  comm: 'com',
  comn: 'com',
  coim: 'com',
  ogr: 'org',
  rog: 'org',
  orgg: 'org',
  nte: 'net',
  ent: 'net',
  nett: 'net',
  iio: 'io',
  dve: 'dev',
  gvo: 'gov',
  eud: 'edu'
});

// Unambiguous well-known host typos
const KNOWN_HOST_TYPO_MAP = Object.freeze({
  'localhsot': 'localhost',
  'locahost': 'localhost',
  'localost': 'localhost',
  'localhots': 'localhost',
  'loaclhost': 'localhost',
  'gogle.com': 'google.com',
  'googel.com': 'google.com',
  'googl.com': 'google.com',
  'gooogle.com': 'google.com',
  'google.ocm': 'google.com',
  'google.con': 'google.com',
  'google.cmo': 'google.com',
  'cloudfalre.com': 'cloudflare.com',
  'cloudlfare.com': 'cloudflare.com',
  'cloudflare.ocm': 'cloudflare.com',
  'githbu.com': 'github.com',
  'gihub.com': 'github.com',
  'github.ocm': 'github.com',
  'amazno.com': 'amazon.com',
  'amzon.com': 'amazon.com',
  'amazon.ocm': 'amazon.com',
  'microsfot.com': 'microsoft.com',
  'mircosoft.com': 'microsoft.com',
  'microsoft.ocm': 'microsoft.com',
  'exmaple.com': 'example.com',
  'exapmle.com': 'example.com',
  'example.ocm': 'example.com',
  'example.con': 'example.com'
});

/**
 * Detect whether a hostname is a likely typo.
 * Returns { corrected, confidence: 'high' | 'uncertain', reason } or null.
 */
function classifyDomainTypo(hostname, sessionTargets = []) {
  if (!hostname || typeof hostname !== 'string') return null;
  const clean = hostname.trim().toLowerCase();
  if (KNOWN_HOST_TYPO_MAP[clean]) {
    return {
      original: clean,
      corrected: KNOWN_HOST_TYPO_MAP[clean],
      confidence: 'high',
      reason: 'Known hostname/TLD typographical error'
    };
  }
  const parts = clean.split('.');
  if (parts.length >= 2) {
    const tld = parts[parts.length - 1];
    if (UNAMBIGUOUS_TLD_TYPO_MAP[tld]) {
      const correctedParts = [...parts.slice(0, -1), UNAMBIGUOUS_TLD_TYPO_MAP[tld]];
      const candidate = correctedParts.join('.');
      return {
        original: clean,
        corrected: KNOWN_HOST_TYPO_MAP[candidate] || candidate,
        confidence: 'high',
        reason: `Unambiguous TLD typo (.${tld} -> .${UNAMBIGUOUS_TLD_TYPO_MAP[tld]})`
      };
    }
  }

  // Check 1-character Levenshtein distance against previously tested session targets (uncertain suggestion)
  for (const prev of sessionTargets) {
    const p = String(prev || '').toLowerCase();
    if (p && p !== clean && Math.abs(p.length - clean.length) <= 1 && levenshteinDistance(clean, p) === 1) {
      return {
        original: clean,
        corrected: p,
        confidence: 'uncertain',
        reason: `Similar to previously tested host "${p}" in this session`
      };
    }
  }

  return null;
}

function detectDomainTypo(hostname) {
  const res = classifyDomainTypo(hostname);
  return res ? res.corrected : null;
}

function levenshteinDistance(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

/**
 * Determine whether a user message is a greeting or general capability inquiry
 */
function isGreetingPrompt(rawText) {
  const clean = String(rawText || '').trim().replace(/[!?.]+$/, '').toLowerCase();
  return /^(hello|hi|hey|good morning|good afternoon|good evening|greetings|hello ejii|hi ejii|hey ejii|help|what can you do|who are you|capabilities)$/i.test(clean);
}

/**
 * Determine whether a user message is a conceptual/informational technical question
 * that should NOT execute live network probes.
 */
function isInformationalTechnicalQuestion(rawText) {
  const clean = String(rawText || '').trim();
  const lower = clean.toLowerCase();

  // If the user explicitly commands a live check ("check my ip", "ping ...", "check dns for ...", "test port ...", "show active connections"), it is operational
  if (/^(check|test|ping|resolve|nslookup|dig|traceroute|trace|scan|investigate|show|list|find|inspect|verify|flush|heal|repair)\b/i.test(lower)) {
    return false;
  }

  // Conceptual & engineering question patterns
  if (
    /\b(what is a default gateway|what is default gateway|difference between tcp and udp|tcp vs udp|difference between connection refused and timeout|connection refused vs timeout|what does (?:this|the) (?:powershell|bash|linux|ss|netstat|ipconfig) command do|prepare a troubleshooting checklist|troubleshooting checklist for|how does (?:dns|tls|https|arp|nat|traceroute|icmp|tcp handshake) work|what is (?:nat|arp|dns|icmp|tls|ssl|mtu|cidr|subnet mask|loopback|localhost|econnrefused|etimedout|nxdomain))\b/i.test(lower)
  ) {
    return true;
  }

  if (
    /^(what is|what are|explain|how does|how do|describe|define)\b/i.test(lower) &&
    !/\b(my ip|my gateway|my network|my dns|active connections|running applications|talking to|what happened|what changed|previous test|same host|that host)\b/i.test(lower)
  ) {
    return true;
  }

  return false;
}

/**
 * Generate a precise, honest engineering answer for an informational technical question
 */
function answerInformationalQuestion(rawText) {
  const lower = String(rawText || '').toLowerCase();

  if (lower.includes('default gateway')) {
    return {
      topic: 'Default Gateway (Layer 3 Routing)',
      result: 'A default gateway is the Layer 3 router interface on your local subnet to which a host forwards packets when the destination IP address does not match any local subnet route.',
      meaning:
        'When your machine sends traffic to an IP address, the OS kernel inspects its routing table (`0.0.0.0/0` in IPv4 or `::/0` in IPv6). If the destination is on the same local subnet, the host uses ARP/NDP to deliver frames directly at Layer 2. If the destination is outside the local subnet, the host encapsulates the IP packet in an Ethernet frame addressed to the default gateway’s MAC address so the router can forward it across external networks.',
      nextStep:
        'To inspect or test your actual configured gateway on this system, ask *"Check my IP"* or *"Ping my default gateway"*.'
    };
  }

  if ((lower.includes('tcp') && lower.includes('udp')) || lower.includes('tcp vs udp')) {
    return {
      topic: 'TCP vs. UDP (Layer 4 Transport Protocols)',
      result: 'TCP (Transmission Control Protocol) is a connection-oriented, reliable byte-stream protocol with a 3-way handshake, whereas UDP (User Datagram Protocol) is connectionless and sends discrete datagrams with minimal overhead.',
      meaning:
        '- **Connection State:** TCP establishes state via `SYN -> SYN-ACK -> ACK` before data transfer; UDP sends packets immediately without a handshake.\n' +
        '- **Reliability & Ordering:** TCP guarantees in-order delivery using sequence numbers, acknowledgments, and retransmissions; UDP does not retransmit lost packets or reorder datagrams at the transport layer.\n' +
        '- **Diagnostic Implication:** An open TCP port can be verified directly by completing a 3-way handshake (`checkPort`), whereas a UDP port often produces no reply unless an application-layer payload (such as a DNS query or QUIC Initial packet) triggers a response.',
      nextStep:
        'To inspect live TCP and UDP sockets on this machine, ask *"Show me the active connections"* or test a specific TCP port with *"Check whether port 443 is open on example.com"*.'
    };
  }

  if ((lower.includes('refused') && lower.includes('timeout')) || lower.includes('econnrefused') || lower.includes('etimedout')) {
    return {
      topic: 'Connection Refused (ECONNREFUSED) vs. Connection Timeout (ETIMEDOUT)',
      result: '`Connection Refused (ECONNREFUSED)` means the target host is reachable and actively rejected the connection with a TCP `RST` packet, whereas `Connection Timeout (ETIMEDOUT)` means no reply was received within the deadline.',
      meaning:
        '- **Connection Refused (`TCP RST` / `ECONNREFUSED`):** Proves that Layer 3 routing is working and the packet reached the destination host (or an inline reject rule), but **no application process is listening** on that TCP port.\n' +
        '- **Connection Timeout (`ETIMEDOUT`):** The client sent TCP `SYN` packets and received neither `SYN-ACK` nor `RST`. This happens when a firewall silently drops (`DROP`) the packet, a routing blackhole exists along the path, or the target host is powered off.',
      nextStep:
        'To test how a live target responds on a specific port, ask *"Check port 8080 on localhost"* or *"Check port 443 on example.com"*.'
    };
  }

  if (lower.includes('powershell') || lower.includes('get-net') || lower.includes('test-netconnection') || lower.includes('command do')) {
    return {
      topic: 'Command & Shell Diagnostic Explanation',
      result: 'Network diagnostic commands inspect OS kernel networking structures (interfaces, routing tables, socket tables, or DNS resolvers) or send active wire probes.',
      meaning:
        '- **`Get-NetTCPConnection` / `ss -tunap` / `netstat -ano`:** Enumerates active kernel TCP/UDP sockets, local/remote endpoints, connection states (`ESTABLISHED`, `LISTENING`, `TIME_WAIT`), and owning PIDs.\n' +
        '- **`Get-NetIPConfiguration` / `ip addr` & `ip route`:** Reads interface IP/prefix assignments, DNS servers, and the `0.0.0.0/0` default gateway route.\n' +
        '- **`Test-NetConnection -ComputerName <host> -Port <port>`:** Performs DNS lookup followed by an active TCP 3-way handshake test.',
      nextStep:
        'You can run the equivalent live inspections directly in EJII by asking *"Show me the active connections"*, *"Check my IP"*, or *"Check port 443 on example.com"*.'
    };
  }

  if (lower.includes('checklist')) {
    return {
      topic: 'Layered Network & Service Troubleshooting Checklist',
      result: 'A structured bottom-up / top-down troubleshooting checklist isolates faults across Local Host -> Gateway -> DNS -> TCP Transport -> TLS -> HTTP Application.',
      meaning:
        '1. **Local Interface & Routing:** Verify local IP assignment and verified default gateway (*"Check my IP"*).\n' +
        '2. **DNS Resolution:** Confirm the hostname resolves to the expected A/AAAA record without `NXDOMAIN` or `ETIMEOUT` (*"Check DNS for <hostname>"*).\n' +
        '3. **L3 Reachability (ICMP):** Test packet loss and round-trip latency while noting whether firewalls filter ICMP (*"Ping <hostname>"*).\n' +
        '4. **L4 TCP Listener:** Verify whether the service port completes a 3-way handshake (`OPEN`), returns `RST` (`CLOSED`), or times out (`FILTERED`) (*"Check port 443 on <hostname>"*).\n' +
        '5. **L6/L7 TLS & HTTP:** Validate certificate chain expiration, SNI, and HTTP status codes (`200`, `301/302`, `4xx`, `5xx`) (*"Check whether https://<hostname> is working"*).',
      nextStep:
        'Provide any hostname, IP address, or URL to execute this multi-layer workflow automatically (for example: *"Investigate why 127.0.0.1:8080 is not responding"*).'
    };
  }

  return {
    topic: 'Infrastructure & Network Engineering Concept',
    result: 'In network diagnostics, separating protocol layers (Local NIC/Routing, DNS, ICMP, TCP Transport, TLS, and HTTP Application) ensures faults are isolated from measured evidence rather than guesswork.',
    meaning:
      '- **DNS (`resolveRecord`):** Translates domain names into IPv4/IPv6 addresses via configured recursive resolvers or OS `getaddrinfo`.\n' +
      '- **ICMP (`realPing`):** Measures Layer 3 echo reachability and round-trip time, though many cloud firewalls filter ICMP while allowing TCP.\n' +
      '- **TCP (`checkPort`):** Verifies whether a remote process is actively accepting connections on a specific port (`SYN -> SYN-ACK`).\n' +
      '- **TLS & HTTP (`auditTls`, `probeHttp`):** Validates X.509 certificates, cipher negotiation, and application status codes.',
    nextStep:
      'Ask a specific diagnostic question against a live target (e.g., *"Check DNS for example.com"*, *"Check my IP"*, or *"Show me the active connections"*).'
  };
}

module.exports = {
  UNAMBIGUOUS_TLD_TYPO_MAP,
  KNOWN_HOST_TYPO_MAP,
  classifyDomainTypo,
  detectDomainTypo,
  isGreetingPrompt,
  isInformationalTechnicalQuestion,
  answerInformationalQuestion
};
