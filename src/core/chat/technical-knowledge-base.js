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

// Well-known conversational brand shorthand ("What's Google's IP?", "Resolve Google for me", "port ping for youtube")
const WELL_KNOWN_BRAND_DOMAINS = Object.freeze({
  google: 'google.com',
  youtube: 'youtube.com',
  cloudflare: 'cloudflare.com',
  github: 'github.com',
  microsoft: 'microsoft.com',
  amazon: 'amazon.com',
  aws: 'aws.amazon.com',
  apple: 'apple.com',
  example: 'example.com',
  wikipedia: 'wikipedia.org',
  npm: 'npmjs.com',
  nodejs: 'nodejs.org',
  gmail: 'gmail.com',
  outlook: 'outlook.office365.com',
  yahoo: 'yahoo.com',
  netflix: 'netflix.com',
  reddit: 'reddit.com',
  discord: 'discord.com',
  slack: 'slack.com',
  openai: 'openai.com',
  anthropic: 'anthropic.com',
  docker: 'docker.com'
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
 * Detect user language (English 'en', Azerbaijani 'az', Turkish 'tr', Russian 'ru')
 * based on script characteristics and unambiguous vocabulary tokens.
 */
function detectLanguage(rawText) {
  if (!rawText || typeof rawText !== 'string') return 'en';
  const lower = rawText.toLowerCase();

  // Russian / Cyrillic script
  if (/[\u0400-\u04FF]/.test(rawText)) {
    return 'ru';
  }

  // Azerbaijani specific letters or characteristic vocabulary
  if (
    /[əğıöşü]/i.test(rawText) ||
    /\b(salam|necəsən|necesen|necəsiniz|necesiz|oglan|oğlan|qız|qiz|harada|haradadır|haradasan|kimdir|kimsən|kimsen|nədir|nedir|nə\s+var|ne\s+var|çox\s+sağ\s+ol|cox\s+sag\s+ol|təşəkkür|tesekkur|hələlik|helelik|bəli|xeyr|yox|müəllim|yaxşıyam|yaxsiyam|bu\s+gün|baki|bakı|paytaxtı)\b/i.test(lower)
  ) {
    return 'az';
  }

  // Turkish specific vocabulary
  if (
    /\b(merhaba|selam|nasılsın|nasilsin|nasılsınız|nasilsiniz|nerede|neredesin|kimdir|kimsin|erkek|kız|kiz|teşekkürler|tesekkurler|sağol|sagol|hoşçakal|hoscakal|günaydın|gunaydin|iyi\s+günler|iyi\s+aksamlar|evet|hayır|hayir|başkenti)\b/i.test(lower)
  ) {
    return 'tr';
  }

  return 'en';
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

  // 1. Identity & Name Query: "who am I?", "what is my name?", "do you know my name?"
  if (/^(?:who am i|what is my identity)\??$/i.test(clean)) {
    const personalName = session?.entityMemory?.userName || session?.userName || session?.displayName || null;
    const accountUser = session?.username || 'admin';
    const roleStr = session?.role ? ` (role: ${session.role})` : '';
    if (personalName) {
      return {
        matched: true,
        subtype: 'identity_query',
        type: 'identity_query',
        reply: `You are ${personalName}. You are authenticated as \`${accountUser}\`${roleStr}.`,
        summary: `Identified user as ${personalName} (account: ${accountUser}).`
      };
    }
    return {
      matched: true,
      subtype: 'identity_query',
      type: 'identity_query',
      reply: `You are signed in as \`${accountUser}\` (account username${roleStr}). You haven't shared your personal display name in this conversation.`,
      summary: `Identified account username as ${accountUser}; personal name unknown.`
    };
  }

  if (/^(?:what is my name|what's my name|whats my name|do you know my name|tell me my name|my name is what)\??$/i.test(clean)) {
    const personalName = session?.entityMemory?.userName || session?.userName || session?.displayName || null;
    if (personalName) {
      return {
        matched: true,
        subtype: 'name_query',
        type: 'name_query',
        reply: `Your name is ${personalName}. What can I help you investigate or explain today?`,
        summary: `Recalled user personal name: ${personalName}`
      };
    }
    return {
      matched: true,
      subtype: 'name_query',
      type: 'name_query',
      reply: "You haven't told me your personal name yet in this session. What would you like me to call you?",
      summary: "Informed user no personal name is on record."
    };
  }

  // 2. Name Correction: "I'm not Eldar; I'm Elvin", "my name is not Eldar, call me Elvin", "actually my name is Elvin", "my name is Elvin"
  const corrMatch = clean.match(/(?:i'm not|i am not|my name is not)\s+([a-z0-9_-]+)[;,.]?\s*(?:i'm|i am|it's|it is|my name is|call me)\s+([a-z0-9_-]+)/i) ||
                    clean.match(/(?:actually|correction|wait|no),?\s*(?:my name is|i'm|call me)\s+([a-z0-9_-]+)/i);
  if (corrMatch) {
    const rawCorrected = (corrMatch[2] || corrMatch[1] || '').trim();
    if (rawCorrected && !NON_NAME_TOKENS.has(rawCorrected.toLowerCase())) {
      const name = rawCorrected.charAt(0).toUpperCase() + rawCorrected.slice(1).toLowerCase();
      if (session) {
        if (!session.entityMemory) session.entityMemory = {};
        session.entityMemory.userName = name;
        session.userName = name;
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
          session.userName = name;
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
      if (session?.lastGatewayIp) {
        return {
          matched: true,
          subtype: 'frustration_repair',
          type: 'frustration_repair',
          reply: `You're right — I apologize for the generic reply. We were discussing the default gateway. The default gateway observed in the EJII runtime environment is **\`${session.lastGatewayIp}\`** (discovered via OS routing table). Please note that this is the gateway of the EJII server/container, which may differ from the router address on your personal workstation.`,
          summary: "Repaired context for default gateway question after user confusion."
        };
      }
      return {
        matched: true,
        subtype: 'frustration_repair',
        type: 'frustration_repair',
        reply: "You're right — I apologize for the generic reply. We were discussing the default gateway. In this environment, no verified 0.0.0.0/0 default route was observed in the server routing table. To find the default gateway on your personal machine, run `ipconfig` (Windows) or `ip route show default` (Linux/macOS).",
        summary: "Repaired context for default gateway question with honest route status."
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

  // 14. Ambiguous Person / Third-Party Entity Inquiry
  // e.g. "is muhammed oglan?", "məhəmməd oğlandır?", "is john a boy?", "who is muhammed?", "кто такой Мухаммед?", "Ali kimdir?"
  const lang = detectLanguage(raw);

  const personQueryMatch =
    clean.match(/^(?:is\s+)?([a-z0-9_\u00C0-\u024F\u0400-\u04FF]+)\s+(?:a\s+)?(boy|girl|man|woman|person|oglan|oğlan|qız|qiz|erkek|kız|kişi|kisi|мальчик|девочка|парень|мужчина|женщина|he|she|here|coming|alive|online)\??$/i) ||
    clean.match(/^([a-z0-9_\u00C0-\u024F\u0400-\u04FF]+)\s+(?:oğlandır|oglandir|qızdır|qizdir|erkek\s+mi|erkek\s+midir|kız\s+mı|kiz\s+mi|мальчик|девочка)\??$/i) ||
    clean.match(/^(?:who\s+is|who's|whos)\s+([a-z0-9_\u00C0-\u024F\u0400-\u04FF]+)\??$/i) ||
    clean.match(/^([a-z0-9_\u00C0-\u024F\u0400-\u04FF]+)\s+(?:kimdir|kim)\??$/i) ||
    clean.match(/^(?:кто\s+такой|кто\s+такая)\s+([a-z0-9_\u00C0-\u024F\u0400-\u04FF]+)\??$/i);

  if (personQueryMatch) {
    const rawCandidate = personQueryMatch[1].trim();
    const candidateLower = rawCandidate.toLowerCase();
    if (
      !NON_NAME_TOKENS.has(candidateLower) &&
      !WELL_KNOWN_BRAND_DOMAINS[candidateLower] &&
      !['dns', 'tcp', 'udp', 'icmp', 'bgp', 'ip', 'http', 'https', 'tls', 'ssl', 'ssh', 'dhcp', 'arp', 'snmp', 'ftp', 'smtp'].includes(candidateLower)
    ) {
      const name = rawCandidate.charAt(0).toUpperCase() + rawCandidate.slice(1);

      if (candidateLower === 'eldar' || candidateLower === 'eldar jamiyev') {
        return {
          matched: true,
          subtype: 'system_creator_identity',
          type: 'identity_query',
          reply: "Eldar Jamiyev is the creator and lead software architect of EJII (Eldar Jamiyev's Infrastructure Intelligence).",
          summary: "Identified platform author Eldar Jamiyev."
        };
      }

      const knownUserName = session?.entityMemory?.userName || session?.userName;
      if (knownUserName && knownUserName.toLowerCase() === candidateLower) {
        return {
          matched: true,
          subtype: 'known_user_inquiry',
          type: 'conversational_question',
          reply: `That's you! You are authenticated as \`${session.username || 'operator'}\` in this session.`,
          summary: `Identified user as ${name}.`
        };
      }

      let clarificationReply;
      if (lang === 'az') {
        clarificationReply = `Hansı ${name} haqqında soruşursunuz? Kimi nəzərdə tutduğunuzu dəqiqləşdirsəniz, sizə dəqiq cavab verə bilərəm.`;
      } else if (lang === 'tr') {
        clarificationReply = `Hangi ${name} hakkında soruyorsunuz? Kimi kastettiğinizi biraz daha açabilir misiniz?`;
      } else if (lang === 'ru') {
        clarificationReply = `Какого именно ${name} вы имеете в виду? Уточните, пожалуйста, о ком идет речь.`;
      } else {
        clarificationReply = `Which ${name} are you referring to? Could you clarify who you mean so I can answer accurately?`;
      }

      return {
        matched: true,
        subtype: 'ambiguous_person_query',
        type: 'clarification_needed',
        subjectPerson: name,
        reply: clarificationReply,
        summary: `Requested clarification on ambiguous person reference: ${name}.`
      };
    }
  }

  // 15. Multilingual Greetings (Azerbaijani, Turkish, Russian)
  if (/^(salam|salam\s+aleykum|salam\s+əleykum|salam\s+aleykum|hər\s+vaxtınız\s+xeyir|her\s+vaxtiniz\s+xeyir|sabahınız\s+xeyir|sabahiniz\s+xeyir|axşamınız\s+xeyir|axsaminiz\s+xeyir)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'greeting',
      type: 'greeting',
      reply: 'Salam! Sizə infrastruktur diaqnostikası və ya şəbəkə suallarında necə kömək edə bilərəm?',
      summary: 'Greeted user in Azerbaijani.'
    };
  }
  if (/^(merhaba|selam|selamlar|günaydın|gunaydin|iyi\s+günler|iyi\s+gunler|iyi\s+akşamlar|iyi\s+aksamlar)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'greeting',
      type: 'greeting',
      reply: 'Merhaba! Ağ teşhisi, sunucu kontrolü veya teknik konularda size nasıl yardımcı olabilirim?',
      summary: 'Greeted user in Turkish.'
    };
  }
  if (/^(привет|здравствуйте|здравствуй|добрый\s+день|доброе\s+утро|добрый\s+вечер|салют)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'greeting',
      type: 'greeting',
      reply: 'Здравствуйте! Чем я могу помочь вам в диагностике сети или решении технических вопросов?',
      summary: 'Greeted user in Russian.'
    };
  }

  // 16. Multilingual "How are you?" / Status
  if (/^(necəsən|necesen|necəsiniz|necesiz|nə\s+var\s+nə\s+yox|ne\s+var\s+ne\s+yox|işlər\s+necədir|isler\s+necedir)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'how_are_you',
      type: 'casual_conversation',
      reply: 'Çox sağ olun, hər şey qaydasındadır! İnfrastruktur və şəbəkə monitorinqinə hazıram. Bu gün hansı məsələni yoxlayırıq?',
      summary: 'Responded to how are you in Azerbaijani.'
    };
  }
  if (/^(nasılsın|nasilsin|nasılsınız|nasilsiniz|ne\s+haber|naber|ne\s+var\s+ne\s+yok)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'how_are_you',
      type: 'casual_conversation',
      reply: 'Teşekkürler, gayet iyiyim! Ağ ve altyapı teşhisine hazırım. Bugün ne üzerinde çalışıyoruz?',
      summary: 'Responded to how are you in Turkish.'
    };
  }
  if (/^(как\s+дела|как\s+поживаешь|как\s+жизнь|как\s+успехи|что\s+нового)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'how_are_you',
      type: 'casual_conversation',
      reply: 'Спасибо, все отлично! Готов к мониторингу и диагностике сетевой инфраструктуры. Какую задачу проверим сегодня?',
      summary: 'Responded to how are you in Russian.'
    };
  }

  // 17. Weather inquiries
  if (/^(what(?:'s|\s+is)\s+(?:the\s+)?weather(?:\s+today|\s+like)?|how(?:'s|\s+is)\s+(?:the\s+)?weather(?:\s+today)?|weather\s+today|hava\s+necədir|hava\s+necedir|bu\s+gün\s+hava\s+necədir|bugün\s+hava\s+nasıl|hava\s+nasıl|какая\s+погода(?:\s+сегодня)?|погода\s+сегодня)\??$/i.test(clean)) {
    let wReply;
    if (lang === 'az') {
      wReply = "Mən canlı hava məlumatı sensorlarına çıxışa malik deyiləm. Əsas ixtisasım şəbəkə protokolları, serverlər və infrastruktur diaqnostikasıdır. Şəbəkə ilə bağlı hansısa məsələni araşdırmaq istərdiniz?";
    } else if (lang === 'tr') {
      wReply = "Canlı hava durumu verilerine erişimim bulunmuyor. Ağ protokolleri, sunucu teşhisi ve altyapı analitiği konusunda uzmanım. İncelemek istediğiniz bir ağ konusu var mı?";
    } else if (lang === 'ru') {
      wReply = "У меня нет доступа к текущим данным метеорологических датчиков. Моя специализация — диагностика сетевой инфраструктуры, протоколов и серверов. Хотите проверить сетевое соединение или узел?";
    } else {
      wReply = "I don't have access to live meteorological sensors or current weather telemetry. I specialize in computer networking, infrastructure diagnostics, and protocol analysis. What network or service would you like to inspect?";
    }
    return {
      matched: true,
      subtype: 'weather_inquiry',
      type: 'casual_conversation',
      reply: wReply,
      summary: 'Responded to weather inquiry.'
    };
  }

  // 18. Multilingual Thanks & Farewells
  if (/^(çox\s+sağ\s+ol|cox\s+sag\s+ol|sağ\s+ol|sag\s+ol|təşəkkür\s+edirəm|tesekkur\s+edirem|təşəkkürlər|tesekkurlar|minnətdaram)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'acknowledgment',
      type: 'casual_conversation',
      reply: 'Dəyməz! Nə zaman şəbəkə və ya infrastrukturla bağlı kömək lazım olsa, buradayam.',
      summary: 'Acknowledged thanks in Azerbaijani.'
    };
  }
  if (/^(teşekkürler|tesekkurler|teşekkür\s+ederim|tesekkur\s+ederim|sağol|sagol|çok\s+sağol|cok\s+sagol|eyvallah)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'acknowledgment',
      type: 'casual_conversation',
      reply: 'Rica ederim! Altyapı ve ağ kontrolleri için her zaman buradayım.',
      summary: 'Acknowledged thanks in Turkish.'
    };
  }
  if (/^(спасибо|большое\s+спасибо|благодарю|отлично|понял|ясно|хорошо)$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'acknowledgment',
      type: 'casual_conversation',
      reply: 'Пожалуйста! Обращайтесь в любое время, если потребуется проверить сетевой узел или диагностику сервиса.',
      summary: 'Acknowledged thanks in Russian.'
    };
  }
  if (/^(hələlik|helelik|sağ\s+olun|sag\s+olun|görüşənədək|gorusenedek|hoşçakal|hoscakal|görüşürüz|gorusuruz|до\s+свидания|пока|до\s+встречи)$/i.test(clean)) {
    let fReply;
    if (lang === 'az') fReply = "Xudahafiz! Şəbəkə diaqnostikası üçün istənilən vaxt müraciət edə bilərsiniz.";
    else if (lang === 'tr') fReply = "Görüşmek üzere! Altyapı veya sunucu kontrolleri için her zaman buradayım.";
    else if (lang === 'ru') fReply = "До свидания! Обращайтесь, когда потребуется проверить сеть или работу сервисов.";
    else fReply = "Take care! Feel free to reach out anytime you need to debug a network or service issue.";
    return {
      matched: true,
      subtype: 'farewell',
      type: 'farewell',
      reply: fReply,
      summary: 'Farewell acknowledgment.'
    };
  }

  // 19. General Knowledge & Factual Queries
  const capitalMatch =
    clean.match(/^(?:what\s+is\s+the\s+capital\s+of|capital\s+of)\s+([a-z\s]+)\??$/i) ||
    clean.match(/^([a-z\s]+)(?:'s)?\s+paytaxtı\s+haradır\??$/i) ||
    clean.match(/^([a-z\s]+)(?:'s)?\s+başkenti\s+neresidir\??$/i) ||
    clean.match(/^какая\s+столица\s+([a-zа-яё\s]+)\??$/i);

  if (capitalMatch) {
    const country = capitalMatch[1].trim().toLowerCase();
    const capitals = {
      'azerbaijan': { en: 'Baku (Bakı)', az: 'Bakı', tr: 'Bakü', ru: 'Баку' },
      'azərbaycan': { en: 'Baku (Bakı)', az: 'Bakı', tr: 'Bakü', ru: 'Баку' },
      'азербайджана': { en: 'Baku (Bakı)', az: 'Bakı', tr: 'Bakü', ru: 'Баку' },
      'азербайджан': { en: 'Baku (Bakı)', az: 'Bakı', tr: 'Bakü', ru: 'Баку' },
      'turkey': { en: 'Ankara', az: 'Ankara', tr: 'Ankara', ru: 'Анкара' },
      'türkiyə': { en: 'Ankara', az: 'Ankara', tr: 'Ankara', ru: 'Анкара' },
      'türkiye': { en: 'Ankara', az: 'Ankara', tr: 'Ankara', ru: 'Анкара' },
      'турции': { en: 'Ankara', az: 'Ankara', tr: 'Ankara', ru: 'Анкара' },
      'united states': { en: 'Washington, D.C.', az: 'Vaşinqton', tr: 'Washington, D.C.', ru: 'Вашингтон' },
      'usa': { en: 'Washington, D.C.', az: 'Vaşinqton', tr: 'Washington, D.C.', ru: 'Вашингтон' },
      'сша': { en: 'Washington, D.C.', az: 'Vaşinqton', tr: 'Washington, D.C.', ru: 'Вашингтон' },
      'france': { en: 'Paris', az: 'Paris', tr: 'Paris', ru: 'Париж' },
      'франции': { en: 'Paris', az: 'Paris', tr: 'Paris', ru: 'Париж' },
      'germany': { en: 'Berlin', az: 'Berlin', tr: 'Berlin', ru: 'Берлин' },
      'германии': { en: 'Berlin', az: 'Berlin', tr: 'Berlin', ru: 'Берлин' },
      'united kingdom': { en: 'London', az: 'London', tr: 'Londra', ru: 'Лондон' },
      'uk': { en: 'London', az: 'London', tr: 'Londra', ru: 'Лондон' },
      'великобритании': { en: 'London', az: 'London', tr: 'Лондон' }
    };
    if (capitals[country]) {
      const cap = capitals[country][lang] || capitals[country].en;
      let reply;
      if (lang === 'az') reply = `${capitalMatch[1].trim()} dövlətinin paytaxtı ${cap} şəhəridir.`;
      else if (lang === 'tr') reply = `${capitalMatch[1].trim()} ülkesinin başkenti ${cap}'dır.`;
      else if (lang === 'ru') reply = `Столицей государства ${capitalMatch[1].trim()} является ${cap}.`;
      else reply = `The capital of ${capitalMatch[1].trim()} is ${cap}.`;
      return {
        matched: true,
        subtype: 'geography_capital',
        type: 'general_knowledge',
        reply,
        summary: `Answered capital query: ${cap}`
      };
    }
  }

  if (/^(what\s+is\s+the\s+speed\s+of\s+light|speed\s+of\s+light|işığın\s+sürəti|isigin\s+sureti|скорость\s+света)\??$/i.test(clean)) {
    let reply;
    if (lang === 'az') reply = "Vakuumda işığın sürəti saniyədə təxminən 299,792,458 metrdir (təxminən 300,000 km/san).";
    else if (lang === 'tr') reply = "Vakumda ışık hızı saniyede yaklaşık 299.792.458 metredir (yaklaşık 300.000 km/s).";
    else if (lang === 'ru') reply = "Скорость света в вакууме составляет точно 299 792 458 метров в секунду (около 300 000 км/с).";
    else reply = "The speed of light in a vacuum is exactly 299,792,458 meters per second (approximately 300,000 km/s).";
    return {
      matched: true,
      subtype: 'physics_fact',
      type: 'general_knowledge',
      reply,
      summary: "Answered speed of light query."
    };
  }

  if (/^(what\s+is\s+photosynthesis|fotosintez\s+nədir|fotosintez\s+nedir|что\s+такое\s+фотосинтез)\??$/i.test(clean)) {
    let reply;
    if (lang === 'az') reply = "Fotosintez — yaşıl bitkilərin, yosunların və bəzi bakteriyaların günəş işığı enerjisindən istifadə edərək karbon qazı və sudan üzvi maddələr (qlükoza) və oksigen sintez etməsi prosesidir.";
    else if (lang === 'ru') reply = "Фотосинтез — это процесс образования органических веществ из углекислого газа и воды на свету при участии хлорофилла.";
    else reply = "Photosynthesis is the biological process used by plants, algae, and certain bacteria to convert light energy into chemical energy, synthesizing glucose and oxygen from carbon dioxide and water.";
    return {
      matched: true,
      subtype: 'biology_fact',
      type: 'general_knowledge',
      reply,
      summary: "Answered photosynthesis query."
    };
  }

  if (/^(what\s+is\s+the\s+highest\s+mountain|dünyanın\s+ən\s+hündür\s+dağı|dünyanın\s+en\s+yüksek\s+dağı|самая\s+высокая\s+гора)\??$/i.test(clean)) {
    let reply;
    if (lang === 'az') reply = "Dünyanın ən hündür zirvəsi Himalay dağlarında yerləşən Everest (Comolunqma) dağıdır. Hündürlüyü 8,848.86 metrdir.";
    else if (lang === 'ru') reply = "Самой высокой горой в мире является Эверест (Джомолунгма) в Гималаях, его высота составляет 8848,86 метров.";
    else reply = "The highest mountain above sea level is Mount Everest (Chomolungma) in the Himalayas, with an elevation of 8,848.86 meters (29,031.7 ft).";
    return {
      matched: true,
      subtype: 'geography_mountain',
      type: 'general_knowledge',
      reply,
      summary: "Answered highest mountain query."
    };
  }

  // 20. Identity & System Author Inquiries in EN, AZ, TR, RU
  if (/^(who\s+created\s+you|who\s+made\s+you|who\s+built\s+you|səni\s+kim\s+yaradıb|seni\s+kim\s+yaptı|кто\s+тебя\s+создал)\??$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'creator_inquiry',
      type: 'identity',
      reply: "I am EJII (Eldar Jamiyev's Infrastructure Intelligence), designed and built by Eldar Jamiyev as a dedicated deep infrastructure intelligence and protocol diagnostic system.",
      summary: "Identified platform author Eldar Jamiyev."
    };
  }

  if (/^(who\s+is\s+eldar(?:\s+jamiyev)?|eldar\s+jamiyev\s+kimdir|eldar\s+kimdir|кто\s+такой\s+эльдар(?:\s+джамиев)?)\??$/i.test(clean)) {
    return {
      matched: true,
      subtype: 'system_creator_identity',
      type: 'identity',
      reply: "Eldar Jamiyev is the creator and lead software architect of EJII (Eldar Jamiyev's Infrastructure Intelligence).",
      summary: "Identified platform author Eldar Jamiyev."
    };
  }

  // Jokes
  if (/^(tell\s+me\s+a\s+joke|joke|zarafat\s+et|mənə\s+bir\s+zarafat\s+de|bir\s+fıkra\s+anlat|расскажи\s+шутку|расскажи\s+анекдот)\??$/i.test(clean)) {
    let jReply;
    if (lang === 'az') {
      jReply = "Deyirlər dünyada yalnız 10 cür insan var: ikilik say sistemini (binary) başa düşənlər və düşməyənlər!";
    } else if (lang === 'tr') {
      jReply = "Dünyada sadece 10 tür insan vardır: İkilik sistemi (binary) anlayanlar ve anlamayanlar!";
    } else if (lang === 'ru') {
      jReply = "В мире есть 10 категорий людей: те, кто понимает двоичный код, и те, кто его не понимает.";
    } else {
      jReply = "Why do programmers prefer dark mode? Because light attracts bugs!";
    }
    return {
      matched: true,
      subtype: 'humor',
      type: 'casual_conversation',
      reply: jReply,
      summary: 'Shared a technical joke.'
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

  // Conversational turns (greetings, casual conversation, ambiguous entity queries, general knowledge) are handled by the conversational layer
  const conv = classifyConversationalTurn(rawText);
  if (conv && conv.matched) {
    return false;
  }

  // Explicit negative constraint ("Explain why this happens, but don't run anything yet")
  if (hasNegativeExecutionConstraint(clean)) {
    return true;
  }

  // Operational requests for specific system configuration values or multi-layer checks
  if (
    /\b(dhcp server ip|ip of dhcp|assigned my (?:ip|address)|my dhcp|my gateway ip|gateway ip|layer by layer|layer-by-layer|gateway and isp|router reachable)\b/i.test(lower) ||
    /\b(what is my|what's my|find the ip of|which server assigned)\s+(?:dhcp|gateway)\b/i.test(lower)
  ) {
    return false;
  }

  // If the user explicitly asks for a specific brand or domain's live IP ("What's Google's IP?", "IP of google.com"), that's a DNS lookup, not conceptual
  if (/\b(what's|what is|find|show|get)\s+(?:the\s+)?(?:ip|address)\s+(?:of|for)\b/i.test(lower) || /\b[a-z0-9-]+\.[a-z]{2,}\b/i.test(lower) && /\b(ip|resolve|lookup)\b/i.test(lower)) {
    return false;
  }
  if (/\b[a-z0-9]+(?:'s)\s+ip\b/i.test(lower)) {
    return false;
  }

  // Conceptual questions about whether an open TCP port / socket proves Layer 7 application health
  if (
    (/\b(open|responsive)\b/i.test(lower) && /\b(tcp|socket|port)\b/i.test(lower) && /\b(application layer|application is healthy|definitively declare|prove|guarantee|mean (?:the )?(?:app|application|service) is healthy)\b/i.test(lower)) ||
    /\b(can we definitively declare|does an open (?:tcp )?(?:port|socket) (?:mean|prove|guarantee)|if (?:a )?(?:tcp )?port (?:\d+ )?is open,? (?:is|does)|open tcp socket.*application layer)\b/i.test(lower)
  ) {
    return true;
  }

  // Conceptual questions about why ping works while a port fails (e.g. "Why can a server respond to ping but reject port 443?")
  if (
    /\b(why (?:can|does|would|might) (?:a |an |the )?(?:server|host|machine|device) (?:respond|reply) to ping|respond to ping but (?:reject|refuse|block|fail|drop)|ping works? but port|ping succeeds? but (?:tcp|port|http|https))\b/i.test(lower)
  ) {
    return true;
  }

  // Conceptual questions about DNS, gateway, DHCP, TCP/UDP, timeout vs refused, commands, checklists, or conversational phrases resembling commands
  if (
    /\b(what (?:exactly )?is a default gateway|what is default gateway|what (?:exactly )?is dhcp|what does dhcp do|difference between tcp and udp|tcp vs\.? udp|difference between (?:a )?connection refused and (?:a )?timeout|is a timeout the same(?: thing)? as connection refused|timeout vs\.? connection refused|connection refused vs\.? timeout|what does (?:this|the) (?:powershell|bash|linux|ss|netstat|ipconfig) command do|prepare a troubleshooting checklist|troubleshooting checklist for|can you explain what dns (?:actually )?does|what does dns (?:actually )?do|how does (?:dns|tls|https|arp|nat|traceroute|icmp|tcp handshake|dhcp) work|tell me how (?:dns|tls|https|arp|nat|traceroute|icmp|tcp|dhcp) works|what is (?:nat|arp|dns|icmp|tls|ssl|mtu|cidr|subnet mask|loopback|localhost|econnrefused|etimedout|nxdomain|apipa|bgp|ospf|quic)|ping spike.*what (?:usually )?causes|what (?:usually )?causes (?:a )?(?:ping|latency|packet loss|dns) spike|why do ping spikes happen|when should i use (?:traceroute|ping|mtr|tcp))\b/i.test(lower)
  ) {
    return true;
  }

  // If the user explicitly commands a live check ("check my ip", "ping ...", "check dns for ...", "test port ...", "show active connections"), it is operational
  if (/^(check|test|ping|resolve|nslookup|dig|traceroute|trace|scan|investigate|show|list|find|inspect|verify|flush|heal|repair)\b/i.test(lower)) {
    return false;
  }

  if (
    /^(what is|what are|what exactly is|can you explain|explain|how does|how do|describe|define|is a |why can a |why does a |why do |since our |if a port is open|does an open|tell me how|when should i)\b/i.test(lower) &&
    !/\b(my name|your name|who am i|who are you|my identity|my ip|my gateway|my network|my dns|my dhcp|active connections|running applications|talking to|what happened|what changed|previous test|previous result|last check|same host|that host|google's ip)\b/i.test(lower)
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

  // Conversational question mentioning ping/latency spikes ("We had a ping spike yesterday, what usually causes that?")
  if (/\b(ping spike|latency spike|why do ping spikes happen|what (?:usually )?causes (?:a )?(?:ping|latency) spike)\b/i.test(lower)) {
    const result = 'Transient ping (ICMP RTT) spikes are most commonly caused by bufferbloat/queue congestion, Wi-Fi radio airtime contention, ISP transit routing shifts, or router CPU control-plane rate-limiting.';
    const meaning =
      '- **Bufferbloat & Queue Congestion (Layer 2/3):** Bulk uploads or downloads saturate egress queues on the local gateway or ISP CPE, forcing small ICMP echo packets to wait behind large MTU frames.\n' +
      '- **Wi-Fi CSMA/CA & Channel Scanning (Layer 1/2):** Wireless interfaces periodically scan off-channel for roaming (BGScan) or experience co-channel interference, causing sudden 40–250ms RTT jumps on Hop 1.\n' +
      '- **Control-Plane ICMP Deprioritization (Layer 3):** Transit routers forward hardware-switched data traffic at line rate in ASICs while punting ICMP TTL/echo processing to a rate-limited CPU.\n' +
      '- **Asymmetric Route Flap or BGP Reconvergence:** Upstream path changes temporarily shift traffic onto a higher-latency backup link.';
    const nextStep = 'To isolate whether a spike originates on your local LAN or upstream ISP, compare simultaneous ICMP RTT to your default gateway (Hop 1) against an external anycast target such as `1.1.1.1`.';
    return {
      topic: 'Root Causes of Transient Ping & Latency Spikes',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}\n\n${nextStep}`
    };
  }

  // Conceptual question: Does an open TCP socket (e.g. port 3000) prove the L7 application layer is healthy?
  if (
    (/\b(open|responsive)\b/i.test(lower) && /\b(tcp|socket|port)\b/i.test(lower) && /\b(application layer|application is healthy|definitively declare|prove|guarantee|mean (?:the )?(?:app|application|service) is healthy)\b/i.test(lower)) ||
    /\b(can we definitively declare|does an open (?:tcp )?(?:port|socket) (?:mean|prove|guarantee)|if (?:a )?(?:tcp )?port (?:\d+ )?is open,? (?:is|does)|open tcp socket.*application layer)\b/i.test(lower)
  ) {
    const result = 'No — an open and responsive TCP socket on port 3000 only proves Layer 4 (Transport) reachability and kernel socket binding; it does **not** prove that the Layer 7 (Application) service is healthy.';
    const meaning =
      '- **What an Open TCP Socket Actually Proves (OSI Layer 4):** When a TCP check succeeds, the operating system kernel\'s network stack completed the 3-way handshake (`SYN` → `SYN-ACK` → `ACK`) because a process has bound the socket in `LISTEN` state and the kernel listen backlog is not full.\n' +
      '- **Why the Application Layer Can Still Be Unhealthy (OSI Layer 7):**\n' +
      '  1. **Event-Loop Starvation or Worker Deadlock:** The OS kernel will continue completing TCP 3-way handshakes in the listen queue even if the Node.js/Python/Java worker thread is completely deadlocked or frozen and never calls `accept()` or reads from the socket.\n' +
      '  2. **HTTP 5xx Application Failures:** The server may accept the TCP connection and immediately return `500 Internal Server Error`, `502 Bad Gateway`, or `503 Service Unavailable`.\n' +
      '  3. **Downstream Dependency Failure:** The web server process may be running, but its database connection pool, Redis cache, or upstream microservice is offline.\n' +
      '  4. **TLS / Protocol Mismatch:** If TLS is expected, an expired certificate or cipher mismatch at Layer 6 will fail after the TCP handshake completes.';
    const nextStep = 'To confirm true Layer 7 application health, perform an HTTP/HTTPS health-endpoint request (e.g., checking status code `200 OK`, response latency, and payload validity on `http://localhost:3000`).';
    return {
      topic: 'Layer 4 TCP Socket State vs. Layer 7 Application Health',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}\n\n${nextStep}`
    };
  }

  // Conceptual question about DHCP
  if (clean === 'what is dhcp' || clean === 'what is dhcp?' || /\b(what (?:exactly )?is dhcp|how does dhcp work|what does dhcp do|explain dhcp)\b/i.test(lower)) {
    const result = 'DHCP (Dynamic Host Configuration Protocol) is a network management protocol that automatically assigns IP addresses and network configuration parameters to client devices on a local subnet.';
    const meaning =
      'When a computer connects to a network, it broadcasts a DHCP DISCOVER message. A DHCP server replies with an OFFER (IP address, subnet mask, default gateway, and DNS servers). The client issues a REQUEST for that lease, and the server returns an ACK (Acknowledgment). This 4-step "DORA" handshake eliminates manual static IP configuration and avoids duplicate address collisions.';
    const nextStep = 'If you want to discover the DHCP server that assigned this system\'s lease, ask "What is my DHCP server IP?".';
    return {
      topic: 'DHCP (Dynamic Host Configuration Protocol)',
      result,
      meaning,
      nextStep,
      naturalReply: `${result}\n\n${meaning}`
    };
  }

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
  detectLanguage,
  classifyDomainTypo,
  detectDomainTypo,
  hasNegativeExecutionConstraint,
  extractBrandHostnameShorthand,
  classifyConversationalTurn,
  isGreetingPrompt,
  isInformationalTechnicalQuestion,
  answerInformationalQuestion
};
