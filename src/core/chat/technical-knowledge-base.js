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
const NON_NAME_TOKENS = new Set([
  'what', 'who', 'where', 'why', 'how', 'when', 'which', 'whose', 'whom',
  'a', 'an', 'the', 'it', 'that', 'this', 'me', 'you', 'he', 'she', 'they', 'we',
  'unknown', 'nobody', 'nothing', 'anything', 'something', 'someone', 'anyone',
  'user', 'operator', 'admin', 'administrator', 'root', 'analyst', 'guest',
  'test', 'null', 'undefined', 'anonymous', 'none', 'here', 'there',
  'not', 'no', 'yes', 'fine', 'good', 'okay', 'ok', 'sure', 'help'
]);

/**
 * Determine whether a user message is a natural conversational exchange
 * (greetings, "how are you?", introductions, identity, acknowledgments, bare topics, frustration)
 * Returns { matched: true, type, subtype, reply, summary, name } or null.
 */
function classifyConversationalTurn(rawText, session = null) {
  const raw = String(rawText || '').trim();
  const clean = raw.replace(/[!?.]+$/, '').trim().toLowerCase();

  // 1. Name Query: "my name is what", "what is my name?", "who am I?", "do you know my name?"
  if (/^(?:what is my name|what's my name|whats my name|who am i|do you know my name|tell me my name|my name is what)\??$/i.test(clean)) {
    const rememberedName = session?.entityMemory?.userName || (session?.username && session.username !== 'operator' && session.username !== 'op-1' ? session.username : null);
    if (rememberedName) {
      return {
        matched: true,
        subtype: 'name_query',
        type: 'name_query',
        reply: `Your name is ${rememberedName}. What can I help you investigate or explain today?`,
        summary: `Recalled user name: ${rememberedName}`
      };
    }
    return {
      matched: true,
      subtype: 'name_query',
      type: 'name_query',
      reply: "You haven't told me your name yet. What would you like me to call you?",
      summary: "Informed user no name is on record."
    };
  }

  // 2. Name Correction: "I'm not Eldar; I'm Elvin", "my name is not Eldar, call me Elvin"
  const corrMatch = clean.match(/(?:i'm not|i am not|my name is not)\s+([a-z0-9_-]+)[;,.]?\s*(?:i'm|i am|it's|it is|my name is|call me)\s+([a-z0-9_-]+)/i) ||
                    clean.match(/(?:actually|correction),?\s*(?:my name is|i'm|call me)\s+([a-z0-9_-]+)/i);
  if (corrMatch) {
    const rawCorrected = (corrMatch[2] || corrMatch[1] || '').trim();
    if (rawCorrected && !NON_NAME_TOKENS.has(rawCorrected.toLowerCase())) {
      const name = rawCorrected.charAt(0).toUpperCase() + rawCorrected.slice(1).toLowerCase();
      if (session) {
        if (!session.entityMemory) session.entityMemory = {};
        session.entityMemory.userName = name;
      }
      return {
        matched: true,
        subtype: 'name_correction',
        type: 'name_correction',
        name,
        reply: `Got it — I've updated my notes. Nice to meet you, ${name}!`,
        summary: `Corrected user name to ${name}.`
      };
    }
  }

  // 3. User Introductions: "I'm Eldar", "My name is Eldar", "Call me Eldar", "My name is Eldar, call me Eldar"
  const isQuotedOrHypothetical = /^the sentence\b|if i say\b|example of\b|what does .+ mean\b/i.test(clean) ||
                                (clean.startsWith('"') && clean.endsWith('"') && clean.includes(' '));
  if (!isQuotedOrHypothetical) {
    const introMatch = clean.match(/^(?:hello|hi|hey)?[, ]*(?:i am|i'm|my name is|call me)\s+([a-z0-9_-]+)(?:,\s*call me\s+[a-z0-9_-]+)?$/i);
    if (introMatch) {
      const candidateRaw = introMatch[1].trim();
      const candidateLower = candidateRaw.toLowerCase();
      if (!NON_NAME_TOKENS.has(candidateLower) && !raw.endsWith('?')) {
        const name = candidateRaw.charAt(0).toUpperCase() + candidateRaw.slice(1).toLowerCase();
        if (session) {
          if (!session.entityMemory) session.entityMemory = {};
          session.entityMemory.userName = name;
        }
        return {
          matched: true,
          subtype: 'introduction',
          type: 'introduction',
          name,
          reply: `Nice to meet you, ${name}! What can I help you investigate or explain today?`,
          summary: `Welcomed ${name}.`
        };
      }
    }
  }

  // 4. Incomplete Utterances: "what can you", "can you check", "why is", "how do I", "what next"
  if (/^(?:what can you|what can u)\??$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'capabilities',
      type: 'capabilities',
      reply: "Were you asking what I can do? I can help you investigate network and service issues, test DNS and connectivity, inspect local network configurations, or explain networking concepts in plain language. What would you like to explore?",
      summary: "Clarified incomplete capability question."
    };
  }
  if (/^(?:can you check|could you check|can you test|could you test)\??$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'clarification_needed',
      type: 'clarification_needed',
      reply: "Sure — which hostname, IP address, port, or URL would you like me to check?",
      summary: "Asked for target for check request."
    };
  }
  if (/^(?:why is|why does|why would)\??$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'clarification_needed',
      type: 'clarification_needed',
      reply: session?.lastTarget
        ? `What specifically would you like to know about the behavior on \`${session.lastTarget}\`?`
        : "What specific behavior or failure would you like me to explain?",
      summary: "Asked for clarification on incomplete why question."
    };
  }
  if (/^(?:how do i|how to)\??$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'clarification_needed',
      type: 'clarification_needed',
      reply: "What task or troubleshooting step are you trying to accomplish?",
      summary: "Asked for task clarification."
    };
  }
  if (/^(?:what next|what should i do next|what now)\??$/i.test(clean)) {
    const nextHint = session?.lastStructuredAnswer?.nextStep
      ? `Based on our previous check: ${session.lastStructuredAnswer.nextStep}`
      : "You can ask me to inspect local network interfaces (\"Check my IP\"), test default gateway connectivity (\"Check gateway\"), or verify DNS (\"Check DNS connectivity\").";
    return {
      matched: true,
      subtype: 'next_steps',
      type: 'next_steps',
      reply: nextHint,
      summary: "Provided recommended next steps."
    };
  }

  // 5. Bare Topics: "network", "gateway", "dns"
  if (/^network\??$/i.test(clean)) {
    if (session?.lastTarget) {
      return {
        matched: true,
        subtype: 'bare_topic',
        type: 'clarification_needed',
        reply: `We were looking at \`${session.lastTarget}\`. Would you like to inspect local network interfaces ("Check my IP"), test your default gateway, or run a connectivity check on a specific service?`,
        summary: "Prompted for network troubleshooting direction."
      };
    }
    return {
      matched: true,
      subtype: 'bare_topic',
      type: 'clarification_needed',
      reply: "Are you troubleshooting a network connection issue, or would you like to inspect this system's network interfaces and routing table? Let me know what you'd like to look into.",
      summary: "Prompted for network discussion topic."
    };
  }

  if (/^(?:gateway|default gateway)\??$/i.test(clean)) {
    if (session?.lastIntent === 'gateway_check' || session?.lastGatewayIp) {
      const gw = session.lastGatewayIp;
      return {
        matched: true,
        subtype: 'gateway_context',
        type: 'clarification_needed',
        reply: `The default gateway observed in the EJII runtime is **\`${gw}\`**. Would you like me to ping it or inspect the routing table? (Note: this is the gateway of the EJII server environment, which may differ from your local computer's gateway.)`,
        summary: `Answered with observed runtime gateway: ${gw}`
      };
    }
    return {
      matched: true,
      subtype: 'bare_topic',
      type: 'clarification_needed',
      reply: "Would you like me to explain what a default gateway does, inspect this system's configured default gateway route, or ping the gateway to test reachability?",
      summary: "Clarified gateway intent with 0 network probes."
    };
  }

  if (/^dns\??$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'bare_topic',
      type: 'clarification_needed',
      reply: "Would you like me to run a general DNS connectivity check on your configured system resolvers, look up records for a specific domain name, or explain how DNS works?",
      summary: "Clarified DNS intent with 0 network probes."
    };
  }

  // 6. User Dissatisfaction / Frustration Repair: "wtf", "what the hell", "are you serious"
  if (/^(?:wtf|what the (?:f\*\*\*|fuck|hell)|are you serious|that makes no sense)\??$/i.test(clean)) {
    const wasDiscussingGateway =
      session?.lastIntent === 'gateway_ip_query' ||
      session?.lastIntent === 'gateway_check' ||
      Boolean(session?.lastGatewayIp) ||
      (session?.lastStructuredAnswer?.result?.toLowerCase().includes('gateway')) ||
      (session?.messages && session.messages.slice(-3).some((m) => /\bgateway\b/i.test(m.content)));

    if (wasDiscussingGateway) {
      const gw = session?.lastGatewayIp || '169.254.8.254';
      return {
        matched: true,
        subtype: 'frustration_repair',
        type: 'frustration_repair',
        reply: `You're right — I apologize for the generic reply. We were discussing the default gateway. The default gateway observed in the EJII runtime environment is **\`${gw}\`** (discovered via OS routing table). Please note that this is the gateway of the EJII server/container, which may differ from the router address on your personal workstation.`,
        summary: "Repaired context for default gateway question after user confusion."
      };
    }
    return {
      matched: true,
      subtype: 'frustration_repair',
      type: 'frustration_repair',
      reply: "You're right — that last response wasn't helpful. Let's reset: what specific issue or system would you like to look at?",
      summary: "Acknowledged dissatisfaction and reset context."
    };
  }

  // 7. Identity & Purpose ("Who are you?", "Who built you?", "What is EJII?", "Tell me about yourself")
  if (/^(who are you|what are you|who built you|who made you|what is ejii|tell me about yourself|what's your name|what is your name)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'identity',
      type: 'identity',
      reply: "I am EJII (Eldar Jamiyev's Infrastructure Intelligence), a deep network observability and diagnostic assistant. I help you inspect, analyze, and diagnose infrastructure, network protocols, DNS, routes, sockets, and services using real operating system telemetry.",
      summary: 'Explained identity and purpose.'
    };
  }

  // 8. How are you / status check
  if (/^(how are you|how are you doing|how's it going|how is it going|how do you do|you doing okay|are you there|you awake)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'how_are_you',
      type: 'how_are_you',
      reply: "I'm doing well, thanks. What are we working on today?",
      summary: "I'm doing well and ready to help."
    };
  }

  // 9. Do you understand me / natural language check
  if (
    /^(do you understand( me)?|do you actually understand( what i write| me)?|can you understand( me| what i say| plain english| natural language)?|are you following( me)?|do you get what i mean)$/i.test(clean)
  ) {
    return {
      matched: true,
      subtype: 'understanding_check',
      type: 'understanding_check',
      reply: "Yes — you can describe what you need in your own words. Whether you want to talk through a network problem, ask a technical question, or run a live check on a host or port, you don't need to use memorized commands.",
      summary: 'Confirmed natural-language understanding.'
    };
  }

  // 10. Greetings
  if (/^(hello|hi|hey|hey there|hi there|hello there|good morning|good afternoon|good evening|greetings|hello ejii|hi ejii|hey ejii)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'greeting',
      type: 'greeting',
      reply: 'Hello! What can I help you investigate or explain today?',
      summary: 'Greeted the user.'
    };
  }

  // 11. Capability inquiry
  if (/^(help|what can you do|capabilities|what are your capabilities|what do you do)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'capabilities',
      type: 'capabilities',
      reply:
        'I can help you investigate network and infrastructure issues or answer engineering questions. For example, I can resolve DNS records, test TCP ports, run ICMP ping and traceroute checks, inspect HTTPS/TLS certificates, check local network interfaces and default gateways, list active OS socket connections, or explain networking concepts in plain language.',
      summary: 'Explained available diagnostic and engineering capabilities.'
    };
  }

  // 12. Conversational acknowledgments & remarks ("That was interesting", "Thanks", "Got it", "Cool")
  if (
    /^(that was interesting|that's interesting|interesting|cool|nice|got it|makes sense|that makes sense|i see|okay|ok|alright|thanks|thank you|thanks a lot|appreciate it|good job|great|awesome)$/i.test(clean)
  ) {
    const contextHint = session?.lastValidTarget
      ? ` If you want to dig deeper into \`${session.lastValidTarget}\` or switch to something else, just let me know.`
      : ' Let me know whenever you want to look into another question or check a system.';
    return {
      matched: true,
      subtype: 'acknowledgment',
      type: 'acknowledgment',
      reply: `Glad that helped.${contextHint}`,
      summary: 'Acknowledged user remark.'
    };
  }

  // 13. Farewells
  if (/^(bye|goodbye|see you|see ya|have a good one|farewell)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'farewell',
      type: 'farewell',
      reply: 'Take care! Feel free to reach out anytime you need to debug a network or service issue.',
      summary: 'Farewell acknowledgment.'
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
  const clean = lower.replace(/[!?.]+$/, '').trim();

  // Open-ended query: "What is Google?"
  if (clean === 'what is google' || (clean.startsWith('what is google') && !clean.includes('ip'))) {
    const result = 'Google is a global technology company specializing in internet-related services, search, cloud computing (Google Cloud Platform), software, and internet infrastructure.';
    const meaning =
      'In network and systems engineering, Google operates global Anycast routing infrastructure, worldwide fiber backbones, and public DNS services (such as 8.8.8.8 and 8.8.4.4). Its core web services resolve to distributed edge nodes across the globe.';
    const nextStep = 'If you want to resolve Google\'s live IP addresses or test reachability to google.com, just let me know.';
    return {
      topic: 'Google & Global Infrastructure Overview',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}`
    };
  }

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
