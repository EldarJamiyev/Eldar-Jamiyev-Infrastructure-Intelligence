/**
 * EJII Conversational Knowledge Base, Semantic Concept Explainer & Cautious Typo Classifier
 *
 * Powers EJII's Brain-First Conversational & Informational Understanding:
 *   - Recognizes natural conversation ("How are you?", "Do you understand me?", "That was interesting", greetings, thanks)
 *   - Detects negative scope constraints ("don't run anything yet", "just explain the concept")
 *   - Resolves natural brand shorthand ("Google's IP?" -> google.com)
 *   - Answers conceptual & engineering questions in natural colleague prose with 0 live network probes
 *   - Classifies unambiguous vs. uncertain domain typos
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

// Well-known conversational brand shorthand ("What's Google's IP?", "Resolve Google for me")
const WELL_KNOWN_BRAND_DOMAINS = Object.freeze({
  google: 'google.com',
  cloudflare: 'cloudflare.com',
  github: 'github.com',
  microsoft: 'microsoft.com',
  amazon: 'amazon.com',
  aws: 'aws.amazon.com',
  apple: 'apple.com',
  example: 'example.com',
  wikipedia: 'wikipedia.org',
  npm: 'npmjs.com',
  nodejs: 'nodejs.org'
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
 * Check if the user explicitly instructed EJII NOT to run any live tools/probes yet.
 * Examples:
 *   "Explain why this happens, but don't run anything yet."
 *   "Don't run anything; just explain the concept."
 *   "Without running any probes, tell me what could cause a timeout."
 */
function hasNegativeExecutionConstraint(rawText) {
  const lower = String(rawText || '').trim().toLowerCase();
  return /\b(don'?t run anything|do not run anything|don'?t run any|do not run any|don'?t test anything|do not test anything|don'?t execute|do not execute|without running any|without probing|no live probes|just explain|only explain|don'?t probe|do not probe|don'?t check yet|do not check yet)\b/i.test(lower);
}

/**
 * Extract well-known brand shorthand when the user naturally refers to a known service without a TLD
 * e.g. "What's Google's IP?", "IP of google", "Resolve Google for me", "Show me the IPs for Google"
 */
function extractBrandHostnameShorthand(rawText) {
  const lower = String(rawText || '').trim().toLowerCase();
  for (const [brand, domain] of Object.entries(WELL_KNOWN_BRAND_DOMAINS)) {
    const regex = new RegExp(`\\b${brand}(?:'s)?\\b`, 'i');
    if (regex.test(lower)) {
      return domain;
    }
  }
  return null;
}

/**
 * Determine whether a user message is a natural conversational exchange
 * (greetings, "how are you?", "do you understand me?", "that was interesting", thanks, etc.)
 * Returns { matched: true, subtype, reply, summary } or null.
 */
function classifyConversationalTurn(rawText, session = null) {
  const raw = String(rawText || '').trim();
  const clean = raw.replace(/[!?.]+$/, '').trim().toLowerCase();

  // 1. How are you / status check
  if (/^(how are you|how are you doing|how's it going|how is it going|how do you do|you doing okay|are you there|you awake)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'how_are_you',
      reply: "I'm doing well, thanks. What are we working on today?",
      summary: "I'm doing well and ready to help."
    };
  }

  // 2. Do you understand me / natural language check
  if (
    /^(do you understand( me)?|do you actually understand( what i write| me)?|can you understand( me| what i say| plain english| natural language)?|are you following( me)?|do you get what i mean)$/i.test(clean)
  ) {
    return {
      matched: true,
      subtype: 'understanding_check',
      reply: "Yes — you can describe what you need in your own words. Whether you want to talk through a network problem, ask a technical question, or run a live check on a host or port, you don't need to use memorized commands.",
      summary: 'Confirmed natural-language understanding.'
    };
  }

  // 3. Greetings & capability overview
  if (/^(hello|hi|hey|hey there|hi there|hello there|good morning|good afternoon|good evening|greetings|hello ejii|hi ejii|hey ejii)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'greeting',
      reply: 'Hello! What can I help you investigate or explain today?',
      summary: 'Greeted the user.'
    };
  }

  if (/^(help|what can you do|who are you|capabilities|what are your capabilities)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'capabilities',
      reply:
        'I can help you investigate network and infrastructure issues or answer engineering questions. For example, I can resolve DNS records, test TCP ports, run ICMP ping and traceroute checks, inspect HTTPS/TLS certificates, check local network interfaces and default gateways, list active OS socket connections, or explain networking concepts in plain language.',
      summary: 'Explained available diagnostic and engineering capabilities.'
    };
  }

  // 4. Conversational acknowledgments & remarks ("That was interesting", "Thanks", "Got it", "Cool")
  if (
    /^(that was interesting|that's interesting|interesting|cool|nice|got it|makes sense|that makes sense|i see|okay|ok|alright|thanks|thank you|thanks a lot|appreciate it|good job|great|awesome)$/i.test(clean)
  ) {
    const contextHint = session?.lastValidTarget
      ? ` If you want to dig deeper into \`${session.lastValidTarget}\` or switch to something else, just let me know.`
      : ' Let me know whenever you want to look into another question or check a system.';
    return {
      matched: true,
      subtype: 'acknowledgment',
      reply: `Glad that helped.${contextHint}`,
      summary: 'Acknowledged user remark.'
    };
  }

  return null;
}

/**
 * Legacy helper preserved for compatibility with existing callers/tests
 */
function isGreetingPrompt(rawText) {
  const conv = classifyConversationalTurn(rawText);
  return Boolean(conv && conv.matched);
}

/**
 * Determine whether a user message is a conceptual/informational technical question
 * that should NOT execute live network probes.
 */
function isInformationalTechnicalQuestion(rawText) {
  const clean = String(rawText || '').trim();
  const lower = clean.toLowerCase();

  // Explicit negative constraint ("Explain why this happens, but don't run anything yet")
  if (hasNegativeExecutionConstraint(clean)) {
    return true;
  }

  // If the user explicitly asks for a specific brand or domain's live IP ("What's Google's IP?", "IP of google.com"), that's a DNS lookup, not conceptual
  if (/\b(what's|what is|find|show|get)\s+(?:the\s+)?(?:ip|address)\s+(?:of|for)\b/i.test(lower) || /\b[a-z0-9-]+\.[a-z]{2,}\b/i.test(lower) && /\b(ip|resolve|lookup)\b/i.test(lower)) {
    return false;
  }
  if (/\b[a-z0-9]+(?:'s)\s+ip\b/i.test(lower)) {
    return false;
  }

  // Conceptual questions about why ping works while a port fails (e.g. "Why can a server respond to ping but reject port 443?")
  if (
    /\b(why (?:can|does|would|might) (?:a |an |the )?(?:server|host|machine|device) (?:respond|reply) to ping|respond to ping but (?:reject|refuse|block|fail|drop)|ping works? but port|ping succeeds? but (?:tcp|port|http|https))\b/i.test(lower)
  ) {
    return true;
  }

  // Conceptual questions about DNS, gateway, TCP/UDP, timeout vs refused, commands, checklists
  if (
    /\b(what (?:exactly )?is a default gateway|what is default gateway|difference between tcp and udp|tcp vs\.? udp|difference between (?:a )?connection refused and (?:a )?timeout|is a timeout the same(?: thing)? as connection refused|timeout vs\.? connection refused|connection refused vs\.? timeout|what does (?:this|the) (?:powershell|bash|linux|ss|netstat|ipconfig) command do|prepare a troubleshooting checklist|troubleshooting checklist for|can you explain what dns (?:actually )?does|what does dns (?:actually )?do|how does (?:dns|tls|https|arp|nat|traceroute|icmp|tcp handshake|dhcp) work|what is (?:nat|arp|dns|icmp|tls|ssl|mtu|cidr|subnet mask|loopback|localhost|econnrefused|etimedout|nxdomain|apipa|bgp|ospf|quic))\b/i.test(lower)
  ) {
    return true;
  }

  // If the user explicitly commands a live check ("check my ip", "ping ...", "check dns for ...", "test port ...", "show active connections"), it is operational
  if (/^(check|test|ping|resolve|nslookup|dig|traceroute|trace|scan|investigate|show|list|find|inspect|verify|flush|heal|repair)\b/i.test(lower)) {
    return false;
  }

  if (
    /^(what is|what are|what exactly is|can you explain|explain|how does|how do|describe|define|is a |why can a |why does a |why do )\b/i.test(lower) &&
    !/\b(my ip|my gateway|my network|my dns|active connections|running applications|talking to|what happened|what changed|previous test|previous result|last check|same host|that host|google's ip)\b/i.test(lower)
  ) {
    return true;
  }

  return false;
}

/**
 * Generate a clear, natural, colleague-grade engineering explanation for an informational question (0 live probes).
 */
function answerInformationalQuestion(rawText) {
  const lower = String(rawText || '').toLowerCase();

  if (
    (lower.includes('ping') && (lower.includes('port') || lower.includes('443') || lower.includes('reject') || lower.includes('refuse') || lower.includes('tcp'))) ||
    /\brespond to ping but\b/i.test(lower)
  ) {
    const result = 'A server can respond to ping while rejecting port 443 because ICMP echo and TCP port listeners operate at different layers of the network stack.';
    const meaning =
      'ICMP ping (`Echo Request` / `Echo Reply`) is handled directly by the operating system kernel at Layer 3 (Network) to confirm that the host is online and IP routing works. Port 443 uses TCP at Layer 4 (Transport) and requires an application process—such as Nginx, Apache, or Node.js—to be actively bound and listening on that port (and permitted by firewall rules). If the host is online but the HTTPS service is stopped or a firewall rejects the port, the kernel still answers ICMP pings while returning `TCP RST` (`Connection Refused`) or timing out on port 443.';
    const nextStep = 'If you have a specific host exhibiting this behavior, tell me its hostname or IP and I can check its TCP port state directly.';
    return {
      topic: 'ICMP Reachability vs. TCP Port Listeners',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}`
    };
  }

  if (lower.includes('default gateway')) {
    const result = 'A default gateway is the router on your local network that your computer sends traffic to when the destination IP address is outside your local subnet.';
    const meaning =
      'When your operating system wants to send a packet, it checks its local routing table (`0.0.0.0/0` for IPv4). If the destination IP is on the same local subnet, your machine delivers the frame directly over Layer 2 (using ARP). If the destination is on another network or the public internet, your machine forwards the packet to the default gateway so that router can route it toward the destination.';
    const nextStep = 'If you would like to inspect or test the default gateway configured on this system, just ask.';
    return {
      topic: 'Default Gateway (Layer 3 Routing)',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}`
    };
  }

  if (lower.includes('what dns') || lower.includes('does dns') || (lower.includes('explain') && lower.includes('dns'))) {
    const result = 'DNS (Domain Name System) translates human-readable domain names like `example.com` into the numerical IP addresses (`93.184.215.14` or IPv6) that routers and operating systems need to open network connections.';
    const meaning =
      'When you access a hostname, your OS checks its local hosts file and stub cache first, and then queries a recursive DNS resolver. That resolver traverses the DNS hierarchy (root, TLD, and authoritative nameservers) to retrieve records such as `A` (IPv4), `AAAA` (IPv6), `CNAME` (aliases), `MX` (mail servers), or `TXT` records. If DNS fails (`NXDOMAIN`, `SERVFAIL`, or timeout), browsers and applications cannot even begin a TCP or TLS handshake because they do not know which IP address to contact.';
    const nextStep = 'If you want to look up a domain’s live DNS records, tell me the domain name.';
    return {
      topic: 'How DNS (Domain Name System) Works',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}`
    };
  }

  if ((lower.includes('tcp') && lower.includes('udp')) || lower.includes('tcp vs udp')) {
    const result = 'TCP (Transmission Control Protocol) is a connection-oriented protocol that guarantees reliable, ordered delivery via a 3-way handshake, whereas UDP (User Datagram Protocol) is connectionless and sends discrete packets with minimal overhead.';
    const meaning =
      '- **Connection State:** TCP establishes a session (`SYN -> SYN-ACK -> ACK`) before sending application data; UDP transmits datagrams immediately without a handshake.\n' +
      '- **Reliability & Ordering:** TCP tracks sequence numbers, acknowledges received bytes, and retransmits lost packets; UDP does not retransmit or reorder packets at the transport layer.\n' +
      '- **Diagnostic Difference:** You can verify an open TCP port directly by completing a 3-way handshake, whereas a UDP port usually stays silent unless you send a valid application-layer request (such as a DNS query).';
    const nextStep = 'Ask to list active connections or test a specific TCP port whenever you want to inspect live traffic.';
    return {
      topic: 'TCP vs. UDP (Layer 4 Transport Protocols)',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}`
    };
  }

  if ((lower.includes('refused') && lower.includes('timeout')) || lower.includes('econnrefused') || lower.includes('etimedout')) {
    const result = 'No — `Connection Refused (ECONNREFUSED)` and `Connection Timeout (ETIMEDOUT)` mean two very different things on the wire.';
    const meaning =
      '- **Connection Refused (`ECONNREFUSED` / `TCP RST`):** Your SYN packet reached the target host across the network, and the target OS kernel actively replied with a `TCP RST` (Reset) packet because **no process is listening** on that port (or an inline firewall rule explicitly rejected it). This proves the host is online and routable.\n' +
      '- **Connection Timeout (`ETIMEDOUT`):** Your machine sent `TCP SYN` packets and heard nothing back before the deadline expired. This usually means a firewall is silently dropping the packets, a routing blackhole exists along the path, or the target host is offline.';
    const nextStep = 'If you are seeing one of these errors on a host, share the hostname and port and we can test it.';
    return {
      topic: 'Connection Refused (ECONNREFUSED) vs. Connection Timeout (ETIMEDOUT)',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}`
    };
  }

  if (lower.includes('powershell') || lower.includes('get-net') || lower.includes('test-netconnection') || lower.includes('command do')) {
    const result = 'Network diagnostic commands either read the operating system kernel’s networking tables (interfaces, routes, sockets) or send active packets onto the wire.';
    const meaning =
      '- **`Get-NetTCPConnection` / `ss -tunap` / `netstat -ano`:** Lists active TCP/UDP sockets, local and remote IP:port pairs, connection states (`ESTABLISHED`, `LISTENING`, `TIME_WAIT`), and the owning process IDs.\n' +
      '- **`Get-NetIPConfiguration` / `ip addr` & `ip route`:** Displays interface IPv4/IPv6 addresses, subnet prefixes, configured DNS servers, and the default gateway route.\n' +
      '- **`Test-NetConnection -ComputerName <host> -Port <port>`:** Resolves DNS and attempts a live TCP 3-way handshake to verify whether the port is open.';
    const nextStep = 'You can ask me in plain English to run any of those checks on this environment.';
    return {
      topic: 'Command & Shell Diagnostic Explanation',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}`
    };
  }

  if (lower.includes('checklist')) {
    const result = 'A structured network troubleshooting checklist isolates faults layer by layer so you do not guess at the cause.';
    const meaning =
      '1. **Local Interface & Route:** Confirm the host has a valid IP address and a verified default gateway.\n' +
      '2. **DNS Resolution:** Check that the target hostname resolves to the expected IPv4/IPv6 address without `NXDOMAIN`, `SERVFAIL`, or resolver timeouts.\n' +
      '3. **Layer 3 Reachability:** Test ICMP ping or traceroute, keeping in mind that many cloud firewalls block ICMP while allowing TCP.\n' +
      '4. **Layer 4 TCP Transport:** Test the specific service port to distinguish `OPEN` (`SYN-ACK`), `CLOSED` (`TCP RST` / no listener), and `FILTERED` (silent timeout).\n' +
      '5. **Layer 6/7 TLS & HTTP:** Verify TLS certificate validity, SNI negotiation, and the HTTP response status code (`200`, `301/302`, `4xx`, `5xx`).';
    const nextStep = 'Share a hostname, IP, or URL whenever you want to run a targeted check.';
    return {
      topic: 'Layered Network & Service Troubleshooting Checklist',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}`
    };
  }

  const result = 'In network troubleshooting, separating each protocol layer—local interface, routing, DNS name resolution, TCP transport, TLS encryption, and HTTP application response—lets us pinpoint the exact failure from observed evidence rather than guesswork.';
  const meaning =
    '- **DNS** maps a hostname to an IP address; if it fails, no connection attempt can start.\n' +
    '- **ICMP & Routing** test hop-by-hop packet delivery, though firewalls often filter ICMP echo requests.\n' +
    '- **TCP Handshakes** show whether a service port is actively listening (`OPEN`), rejecting connections (`CLOSED` / `RST`), or silently filtered (`TIMEOUT`).\n' +
    '- **TLS & HTTP** confirm whether the application itself has valid certificates and is returning healthy responses.';
  const nextStep = 'Let me know what concept or live system you would like to explore.';
  return {
    topic: 'Infrastructure & Network Engineering Concept',
    result,
    meaning,
    nextStep,
    naturalReply: `${result}\n\n${meaning}`
  };
}

module.exports = {
  UNAMBIGUOUS_TLD_TYPO_MAP,
  KNOWN_HOST_TYPO_MAP,
  WELL_KNOWN_BRAND_DOMAINS,
  classifyDomainTypo,
  detectDomainTypo,
  hasNegativeExecutionConstraint,
  extractBrandHostnameShorthand,
  classifyConversationalTurn,
  isGreetingPrompt,
  isInformationalTechnicalQuestion,
  answerInformationalQuestion
};
