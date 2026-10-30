/**
 * EJII Production Semantic AI Interpreter
 *
 * Brain-First Cognitive Request Lifecycle:
 * User Message → AI Semantic Interpretation → Context Resolution → Action Decision →
 * Trusted Backend Validation/RBAC → Authorized Tool Execution (if needed) → Evidence Analysis → Natural Response
 *
 * Bridges incoming user utterances to structured intent, context resolution, and tool planning.
 * Operates with fail-closed bounds, strict latency timeouts, and Bayesian semantic grounding.
 */

'use strict';

const { aiModelOrchestrator } = require('../ai-model-orchestrator');
const {
  classifyConversationalTurn,
  isInformationalTechnicalQuestion,
  answerInformationalQuestion,
  extractBrandHostnameShorthand
} = require('./technical-knowledge-base');
const {
  isEpistemicOrSovereignFabricQuestion,
  buildApplicationEpistemicContext,
  mapFunctionCallToExecutionPlan
} = require('./conversational-brain');

let totalInvocations = 0;
let successfulInterpretations = 0;
let deterministicFastPathCount = 0;
let fallbackCount = 0;
let modelInvocationsAttempted = 0;
let modelInvocationsSucceeded = 0;
let realModelInvocationsSucceeded = 0;
let mockModelInvocationsCount = 0;
let modelInvocationsFailed = 0;
let lastModelProvider = null;
let lastModelStatus = null;

const VALID_INTENTS = new Set([
  'ping',
  'port_check',
  'dns',
  'website_check',
  'traceroute',
  'local_ip_config',
  'gateway_check',
  'gateway_ip_query',
  'dhcp_check',
  'local_path_diagnostic',
  'epistemic_fabric_query',
  'mail_troubleshooting_intake',
  'informational_question',
  'greeting',
  'clarification_needed',
  'remediation',
  'host_health',
  'active_connections',
  'follow_up_explanation'
]);

/**
 * Extract explicit DNS record type (MX, AAAA, TXT, NS, CNAME, SOA, PTR, SRV, A) from prompt
 */
function extractDnsRecordType(rawText) {
  const lower = String(rawText || '').toLowerCase();
  if (/\bmx\b|\bmail exchange\b/i.test(lower)) return 'MX';
  if (/\baaaa\b|\bipv6\s+(?:record|address|dns)\b/i.test(lower)) return 'AAAA';
  if (/\btxt\b|\bspf\b|\bdmarc\b|\bdkim\b/i.test(lower)) return 'TXT';
  if (/\bcname\b|\bcanonical name\b/i.test(lower)) return 'CNAME';
  if (/\bns\s+records?\b|\bnameservers?\b|\bns\s+lookup\b|\bdns\s+ns\b/i.test(lower)) return 'NS';
  if (/\bsoa\b|\bstart of authority\b/i.test(lower)) return 'SOA';
  if (/\bptr\b|\breverse dns\b|\brdns\b/i.test(lower)) return 'PTR';
  if (/\bsrv\b/i.test(lower)) return 'SRV';
  return null;
}

/**
 * Semantic AI Interpreter function called by ChatOperatorService
 * @param {string} promptText
 * @param {Object} context { lastTarget, targetHistory, lastIntent, lastPorts, pendingTask, defaultPlan, forceModelInterpretation, allowCloudFallback }
 * @returns {Promise<Object|null>} Override plan object or null to retain default plan
 */
async function semanticAiInterpreter(promptText, context = {}) {
  totalInvocations++;
  const raw = String(promptText || '').trim();
  if (!raw) return null;

  const lower = raw.toLowerCase();
  const clean = lower.replace(/[!?.]+$/, '').trim();
  const isCustomProviderHook = Object.prototype.hasOwnProperty.call(aiModelOrchestrator, 'invokeModelProvider');

  try {
    // 0. If pending mail task continuation was already validated by ChatOperatorService, preserve it directly
    if (context.defaultPlan?.isMailTaskContinuation || context.defaultPlan?.prohibitIcmp) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return null;
    }

    // 0B. Sovereign Fabric v6 / Bayesian Truth Matrix / Shannon Information-Gain / Epistemic Queries (0 hostname prompts)
    if (isEpistemicOrSovereignFabricQuestion(raw)) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'epistemic_fabric_query',
        mode: 'informational',
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true
      };
    }

    // 1. Technical Informational & Conceptual Questions (0 live probes — checked BEFORE greetings & operational plans!)
    if (isInformationalTechnicalQuestion(raw)) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'informational_question',
        mode: 'informational',
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true
      };
    }

    // 1B. Office Email / Mail Symptom Problem Intake ("Users in our office cannot send or receive emails")
    if (
      /\b(cannot send or receive emails?|can'?t send or receive emails?|unable to send or receive emails?|office email (?:problem|issue|outage)|emails? (?:are )?not (?:sending|receiving|working)|users (?:in our office )?can'?t (?:send|receive) email|email is down)\b/i.test(lower) &&
      !context.defaultPlan?.explicitTarget
    ) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'mail_troubleshooting_intake',
        mode: 'conversational',
        target: null,
        explicitTarget: null,
        ports: [25, 465, 587, 993],
        preserveContextOnly: true
      };
    }

    // 2. Natural Conversational Exchanges (Greetings, Introductions, Identity, Status, Thanks)
    const conv = classifyConversationalTurn(raw, context);
    if (conv && conv.matched) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      if (conv.type === 'clarification_needed' || conv.subtype === 'bare_topic') {
        return {
          intent: 'clarification_needed',
          mode: 'conversational',
          clarificationReason: 'BARE_TOPIC',
          clarificationPrompt: conv.reply,
          target: null,
          explicitTarget: null,
          ports: [],
          preserveContextOnly: true
        };
      }
      return {
        intent: 'greeting',
        mode: 'conversational',
        conversationalType: conv.type || conv.subtype,
        target: context.lastTarget || null,
        explicitTarget: null,
        ports: context.lastPorts || [],
        preserveContextOnly: true
      };
    }

    // 3. Ambiguous bare "DNS" / "DNS?" (always clarification_needed, never inherits priorTarget)
    if (/^dns\??$/i.test(clean)) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'clarification_needed',
        mode: 'conversational',
        clarificationReason: 'AMBIGUOUS_DNS_PROMPT',
        clarificationPrompt:
          'Would you like me to test overall DNS connectivity and system resolvers, look up records for a specific domain name, or explain how DNS works?',
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true
      };
    }

    // 3B. Ambiguous bare "gateway" or "network"
    if (/^(?:gateway|default gateway)\??$/i.test(clean)) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'clarification_needed',
        mode: 'conversational',
        clarificationReason: 'AMBIGUOUS_GATEWAY_PROMPT',
        clarificationPrompt:
          'Would you like me to inspect your default gateway configuration, ping the default gateway to test Layer 3 reachability, or explain what a default gateway does?',
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true
      };
    }
    if (/^(?:network|networking)\??$/i.test(clean)) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'clarification_needed',
        mode: 'conversational',
        clarificationReason: 'BARE_TOPIC',
        clarificationPrompt:
          'Are you troubleshooting a local network issue, looking for an explanation of networking fundamentals, or looking to test a specific IP or service?',
        target: null,
        explicitTarget: null,
        ports: [],
        preserveContextOnly: true
      };
    }

    // 4. Mail server check without domain
    if (
      /\b(check (?:the |my )?mail server|ping (?:the |my )?mail server|test (?:the |my )?mail server|mail server connection|email server|smtp server)\b/i.test(lower) &&
      !context.defaultPlan?.explicitTarget
    ) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'clarification_needed',
        mode: 'conversational',
        clarificationReason: 'MISSING_MAIL_DOMAIN',
        clarificationPrompt:
          'Which mail domain (e.g., example.com) or mail server hostname (e.g., mail.example.com / smtp.example.com) would you like me to check? I can look up its MX records and test SMTP (port 25/587) or IMAP/POP3 ports.',
        target: null,
        explicitTarget: null,
        ports: [25, 587],
        preserveContextOnly: true
      };
    }

    // 5. Semantic brand shorthand ("What's Google's IP?", "DNS MX lookup for Google", "Resolve google for me")
    const brand = extractBrandHostnameShorthand(raw);
    if (brand && /\b(ip|address|resolve|resolves|dns|lookup|records?|mx|aaaa|txt|cname|ns|soa|ptr)\b/i.test(lower) && !/\b(port|tcp)\b/i.test(lower)) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      const requestedRecordType = extractDnsRecordType(raw) || context?.defaultPlan?.recordType || 'A';
      return {
        intent: 'dns',
        mode: 'operational',
        target: brand,
        explicitTarget: brand,
        ports: [],
        recordType: requestedRecordType
      };
    }

    // 5B. Semantic brand shorthand for TCP port checks ("port ping for youtube", "ping port youtube 443", "check port 443 on youtube")
    if (brand && /\b(port|tcp)\b/i.test(lower)) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      const portMatches = raw.match(/\b(\d{2,5})\b/g);
      const explicitPorts = portMatches
        ? portMatches.map(Number).filter((p) => p >= 1 && p <= 65535)
        : [80, 443];
      return {
        intent: 'port_check',
        mode: 'operational',
        target: brand,
        explicitTarget: brand,
        ports: explicitPorts.length > 0 ? explicitPorts : [80, 443]
      };
    }

    // 6. Local IP config / routing
    if (/\b(check my ip|what is my ip|what's my ip|whats my ip|my network interfaces|show my ip)\b/i.test(lower)) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'local_ip_config',
        mode: 'operational',
        target: 'local_host_interfaces',
        explicitTarget: null,
        asksForPublicIp: /\b(public ip|external ip|wan ip)\b/i.test(lower),
        ports: [],
        preserveLastRemoteTarget: true
      };
    }

    // 7. Gateway check
    if (/\b(ping (?:my |the )?default gateway|ping (?:my |the )?gateway|check (?:my |the )?default gateway|check (?:my |the )?gateway)\b/i.test(lower)) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'gateway_check',
        mode: 'operational',
        target: 'default_gateway',
        explicitTarget: null,
        ports: [],
        preserveLastRemoteTarget: true
      };
    }

    // 7B. Gateway IP Query ("okay what ip", "what ip is default gateway in my network", "what is the default gateway ip")
    if (
      /\b(what is (?:the |my )?(?:default )?gateway(?:'s)? ip|what's (?:the |my )?(?:default )?gateway(?:'s)? ip|whats (?:the |my )?(?:default )?gateway(?:'s)? ip|which ip is (?:the |my )?(?:default )?gateway|ip (?:address )?of (?:the |my )?(?:default )?gateway|default gateway ip)\b/i.test(lower) ||
      (/\b(what ip|which ip|what is the ip|whats the ip|what address|which address)\b/i.test(lower) &&
        (/\b(gateway|default route|router|local network|my network)\b/i.test(lower) ||
          context.lastIntent === 'gateway_check' ||
          context.lastIntent === 'gateway_ip_query' ||
          Boolean(context.lastGatewayIp))) ||
      (/^(?:okay |ok )?(?:what ip|which ip|what is the ip|what address)\??$/i.test(clean) &&
        (context.lastIntent === 'gateway_check' || context.lastIntent === 'gateway_ip_query' || Boolean(context.lastGatewayIp)))
    ) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'gateway_ip_query',
        mode: 'informational',
        target: 'default_gateway',
        explicitTarget: null,
        ports: [],
        preserveLastRemoteTarget: true
      };
    }

    // 8. DHCP Server IP Discovery and Status (Read configuration/leases, NEVER probe ports 67/68)
    if (
      /\b(what is my dhcp server ip|what's my dhcp server ip|whats my dhcp server ip|find the ip of dhcp|which dhcp server assigned my (?:ip|address)|where is my dhcp server|which server gave me this address|dhcp server ip|ip of dhcp)\b/i.test(lower) ||
      /\b(check (?:the |my )?dhcp(?: server)?(?: connection| connectivity)?|test (?:the |my )?dhcp(?: server)?|is dhcp working|dhcp status|dhcp server connection)\b/i.test(lower)
    ) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'dhcp_check',
        mode: 'operational',
        target: 'local_dhcp_service',
        explicitTarget: null,
        ports: [],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 8B. DHCP Follow-Up ("find out", "how can I find out", "how can I check", "is it static or dhcp") when lastIntent === 'dhcp_check'
    if (
      context.lastIntent === 'dhcp_check' &&
      (/^(?:find out|can you find out|how can i find out|how do i find out|how can i check|how do i check|check if it'?s static|is it static or dhcp|why not|check it)\??$/i.test(clean) ||
        /\b(find out|whether (?:this|my) (?:ip|address|interface) is dhcp or static|is my ip static or dhcp)\b/i.test(lower))
    ) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'dhcp_check',
        mode: 'operational',
        target: 'local_dhcp_service',
        explicitTarget: null,
        ports: [],
        isDhcpFollowUp: true,
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // 9. Composite Local-Path / Layer-by-Layer Gateway & ISP Diagnostic (Never asks for a hostname)
    if (
      /\b(check (?:layer by layer|layer-by-layer|hop by hop|hop-by-hop|step by step)|check (?:my )?connection layer by layer|is (?:my )?(?:router|gateway) reachable and can i reach the internet|connection to gateway and isp|gateway to isp|local connection and internet path|network adapter through the gateway to the internet|where my connection fails,? from (?:the )?local interface to (?:the )?isp)\b/i.test(lower)
    ) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return {
        intent: 'local_path_diagnostic',
        mode: 'operational',
        target: 'local_path_gateway_isp',
        explicitTarget: null,
        ports: [53, 443],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    // Check if context.defaultPlan already resolved a concrete operational/follow-up command
    const dp = context.defaultPlan;
    const isUnhandledOrNovel =
      Boolean(context.forceModelInterpretation) ||
      isCustomProviderHook ||
      !dp ||
      (dp.intent === 'greeting' && dp.conversationalType === 'general_conversation');

    if (!isUnhandledOrNovel) {
      deterministicFastPathCount++;
      successfulInterpretations++;
      return null;
    }

    // 10. Actual Configured LLM Brain Invocation for novel / unhandled natural-language queries
    const provider = aiModelOrchestrator.preferredProvider || 'OLLAMA';
    modelInvocationsAttempted++;
    lastModelProvider = provider;

    let epistemicSummary = null;
    try {
      const epCtx = await buildApplicationEpistemicContext(context);
      epistemicSummary = {
        environmentScope: epCtx.observedEvidence.environmentScopeCategory,
        defaultGateway: epCtx.observedEvidence.defaultGateway,
        dhcpAddressing: epCtx.observedEvidence.dhcpAddressing,
        shannonEntropyBits: epCtx.sovereignFabricV6TruthMatrix.shannonEntropyBits,
        topRecommendedProbe: epCtx.shannonInformationGainRecommendations[0]
      };
    } catch (_) {}

    const promptForModel = `You are EJII Semantic Brain (Project Falcon), a senior network and infrastructure engineering assistant.
The user said: "${raw}".
Session Context: ${JSON.stringify({
      lastTarget: context.lastTarget || null,
      lastIntent: context.lastIntent || null,
      lastPorts: context.lastPorts || [],
      pendingTask: context.pendingTask || null,
      epistemicState: epistemicSummary
    })}
Classify the user's intent from this exact allowed list:
[ping, port_check, dns, website_check, traceroute, local_ip_config, gateway_check, gateway_ip_query, dhcp_check, local_path_diagnostic, epistemic_fabric_query, mail_troubleshooting_intake, informational_question, greeting, clarification_needed]
Rules:
- Never invent a hostname or IP address that the user did not state or reference from session context.
- If the user is asking a conceptual or networking question (e.g., whether an open TCP port proves L7 application health), set intent to "informational_question", set target to null, and provide a clear, accurate "naturalReply".
- If the user asks about the Sovereign Fabric v6 truth matrix, Bayesian hypotheses, or highest information-gain next probe, set intent to "epistemic_fabric_query" and target to null.
- If the user specifies a DNS record type (MX, AAAA, TXT, NS, CNAME, SOA, PTR, SRV), preserve it in "recordType".
- If the user is chatting or greeting, set intent to "greeting" and provide a natural, helpful "naturalReply".
- If a diagnostic action needs a target hostname/IP that is missing, set intent to "clarification_needed" and provide a specific "clarificationPrompt".
- Output JSON ONLY:
{"intent": "intent_name", "target": "hostname_or_null", "recordType": "A_or_MX_or_AAAA_or_TXT_or_NS", "ports": [], "clarificationPrompt": "string_or_null", "naturalReply": "string_or_null"}`;

    try {
      const modelRes = await aiModelOrchestrator.invokeWithBoundedRetry(provider, promptForModel, {
        model: 'gemini-3.8-flash',
        timeoutMs: 4000,
        maxRetries: 1,
        allowRedactedCloudFallback: Boolean(context.allowCloudFallback || !aiModelOrchestrator.localOnlyPolicy)
      });

      if (modelRes && modelRes.liveResponse) {
        // Support native Gemini functionCalls if returned
        if (Array.isArray(modelRes.functionCalls) && modelRes.functionCalls.length > 0) {
          const fcPlan = mapFunctionCallToExecutionPlan(modelRes.functionCalls[0]);
          if (fcPlan) {
            modelInvocationsSucceeded++;
            realModelInvocationsSucceeded++;
            successfulInterpretations++;
            lastModelStatus = 'LIVE_SUCCESS';
            lastModelProvider = modelRes.provider || provider;
            return {
              intent: fcPlan.intent === 'dns_check' ? 'dns' : fcPlan.intent,
              mode: fcPlan.intent === 'epistemic_fabric_query' ? 'informational' : 'operational',
              target: fcPlan.target || context.lastTarget || null,
              explicitTarget: fcPlan.target || null,
              recordType: fcPlan.recordType || 'A',
              ports: fcPlan.ports || [],
              modelInterpreted: true,
              modelProvider: modelRes.provider || provider,
              isMockModel: false
            };
          }
        }

        if (modelRes.text) {
          let jsonStr = String(modelRes.text).trim();
          const jsonMatch = jsonStr.match(/\{[\s\S]*\}/);
          if (jsonMatch) jsonStr = jsonMatch[0];
          const parsed = JSON.parse(jsonStr);

          if (parsed && typeof parsed === 'object' && VALID_INTENTS.has(parsed.intent)) {
            const validatedPorts = Array.isArray(parsed.ports)
              ? parsed.ports.map(Number).filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535)
              : [];
            const rawTarget = parsed.target && typeof parsed.target === 'string' && parsed.target !== 'null'
              ? parsed.target.trim()
              : null;

            // Safety check: if operational intent requires a remote target and neither rawTarget nor context.lastTarget exists, require clarification
            const remoteIntents = new Set(['ping', 'port_check', 'dns', 'website_check', 'traceroute']);
            if (remoteIntents.has(parsed.intent) && !rawTarget && !context.lastTarget) {
              modelInvocationsSucceeded++;
              if (modelRes.isMock || isCustomProviderHook) mockModelInvocationsCount++;
              else realModelInvocationsSucceeded++;
              successfulInterpretations++;
              lastModelStatus = modelRes.isMock || isCustomProviderHook ? 'MOCK_SUCCESS' : 'LIVE_SUCCESS';
              return {
                intent: 'clarification_needed',
                mode: 'conversational',
                clarificationReason: 'MISSING_TARGET_CONTEXT',
                clarificationPrompt:
                  parsed.clarificationPrompt || 'Which hostname, IP address, or URL would you like me to check?',
                target: null,
                explicitTarget: null,
                ports: validatedPorts,
                preserveContextOnly: true,
                modelInterpreted: true,
                modelProvider: modelRes.provider || provider,
                isMockModel: Boolean(modelRes.isMock || isCustomProviderHook)
              };
            }

            modelInvocationsSucceeded++;
            if (modelRes.isMock || isCustomProviderHook) {
              mockModelInvocationsCount++;
              lastModelStatus = 'MOCK_SUCCESS';
            } else {
              realModelInvocationsSucceeded++;
              lastModelStatus = 'LIVE_SUCCESS';
            }
            successfulInterpretations++;
            lastModelProvider = modelRes.provider || provider;

            const isConversational = parsed.intent === 'greeting' || parsed.intent === 'clarification_needed' || parsed.intent === 'mail_troubleshooting_intake';
            const isInformational = parsed.intent === 'informational_question' || parsed.intent === 'epistemic_fabric_query';

            return {
              intent: parsed.intent,
              mode: isConversational ? 'conversational' : (isInformational ? 'informational' : 'operational'),
              target: isInformational ? null : (rawTarget || context.lastTarget || null),
              explicitTarget: isInformational ? null : (rawTarget || null),
              recordType: parsed.recordType || extractDnsRecordType(raw) || 'A',
              ports: validatedPorts,
              clarificationPrompt: parsed.clarificationPrompt || null,
              naturalReply: parsed.naturalReply || null,
              preserveContextOnly: isConversational || isInformational,
              modelInterpreted: true,
              modelProvider: modelRes.provider || provider,
              isMockModel: Boolean(modelRes.isMock || isCustomProviderHook)
            };
          }
        }
      }

      modelInvocationsFailed++;
      lastModelStatus = modelRes?.status || (modelRes?.reason ? `OFFLINE_${modelRes.reason}` : 'OFFLINE');
    } catch (_) {
      modelInvocationsFailed++;
      lastModelStatus = 'ERROR';
    }

    // Fail-safe: When model is offline or unparsable, do NOT invent arbitrary targets
    fallbackCount++;
    return null;
  } catch (err) {
    fallbackCount++;
    return null;
  }
}

function getSemanticInterpreterMetrics() {
  return {
    totalInvocations,
    interpreterHookCalls: totalInvocations,
    deterministicFastPathCount,
    successfulInterpretations,
    fallbackCount,
    modelInvocationsAttempted,
    modelInvocationsSucceeded,
    realModelInvocationsSucceeded,
    mockModelInvocationsCount,
    modelInvocationsFailed,
    lastModelProvider,
    lastModelStatus,
    orchestratorStatus: aiModelOrchestrator.getStatus()
  };
}

function resetSemanticInterpreterMetrics() {
  totalInvocations = 0;
  successfulInterpretations = 0;
  deterministicFastPathCount = 0;
  fallbackCount = 0;
  modelInvocationsAttempted = 0;
  modelInvocationsSucceeded = 0;
  realModelInvocationsSucceeded = 0;
  mockModelInvocationsCount = 0;
  modelInvocationsFailed = 0;
  lastModelProvider = null;
  lastModelStatus = null;
}

module.exports = {
  semanticAiInterpreter,
  extractDnsRecordType,
  getSemanticInterpreterMetrics,
  resetSemanticInterpreterMetrics
};
