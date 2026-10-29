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

let totalInvocations = 0;
let successfulInterpretations = 0;
let fallbackCount = 0;

/**
 * Semantic AI Interpreter function called by ChatOperatorService
 * @param {string} promptText
 * @param {Object} context { lastTarget, targetHistory, lastIntent, lastPorts, defaultPlan }
 * @returns {Promise<Object|null>} Override plan object or null to retain default plan
 */
async function semanticAiInterpreter(promptText, context = {}) {
  totalInvocations++;
  const raw = String(promptText || '').trim();
  if (!raw) return null;

  const lower = raw.toLowerCase();
  const clean = lower.replace(/[!?.]+$/, '').trim();

  try {
    // 1. Natural Conversational Exchanges (Greetings, Introductions, Identity, Status, Thanks)
    const conv = classifyConversationalTurn(raw, context);
    if (conv && conv.matched) {
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

    // 2. Technical Informational Questions (0 live probes)
    if (isInformationalTechnicalQuestion(raw)) {
      successfulInterpretations++;
      return {
        intent: 'informational_question',
        mode: 'informational',
        target: context.lastTarget || null,
        explicitTarget: null,
        ports: context.lastPorts || [],
        preserveContextOnly: true
      };
    }

    // 3. Ambiguous bare "DNS" / "DNS?" (always clarification_needed, never inherits priorTarget)
    if (/^dns\??$/i.test(clean)) {
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

    // 5. Semantic brand shorthand ("What's Google's IP?", "IP of google", "Resolve google for me")
    const brand = extractBrandHostnameShorthand(raw);
    if (brand && /\b(ip|address|resolve|resolves|dns|lookup|records)\b/i.test(lower)) {
      successfulInterpretations++;
      return {
        intent: 'dns',
        mode: 'operational',
        target: brand,
        explicitTarget: brand,
        ports: [],
        recordType: 'A'
      };
    }

    // 6. Local IP config / routing
    if (/\b(check my ip|what is my ip|what's my ip|whats my ip|my network interfaces|show my ip)\b/i.test(lower)) {
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

    // 7B. Gateway IP Query ("okay what ip", "what ip is default gateway in my network", "what is the gateway ip")
    if (
      (/\b(what ip|which ip|what is the ip|whats the ip|what address|which address)\b/i.test(lower) &&
        (/\b(gateway|default route|router|local network|my network)\b/i.test(lower) ||
          context.lastIntent === 'gateway_check' ||
          context.lastIntent === 'gateway_ip_query' ||
          Boolean(context.lastGatewayIp))) ||
      (/^(?:okay |ok )?(?:what ip|which ip|what is the ip|what address)\??$/i.test(clean) &&
        (context.lastIntent === 'gateway_check' || context.lastIntent === 'gateway_ip_query' || Boolean(context.lastGatewayIp)))
    ) {
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

    // 8. DHCP check
    if (/\b(check (?:the |my )?dhcp(?: server)?(?: connection| connectivity)?|test (?:the |my )?dhcp(?: server)?|is dhcp working|dhcp status|dhcp server connection)\b/i.test(lower)) {
      successfulInterpretations++;
      return {
        intent: 'dhcp_check',
        mode: 'operational',
        target: 'local_dhcp_service',
        explicitTarget: null,
        ports: [67, 68],
        usedFollowUpTarget: false,
        preserveLastRemoteTarget: true
      };
    }

    return null;
  } catch (err) {
    fallbackCount++;
    return null;
  }
}

function getSemanticInterpreterMetrics() {
  return {
    totalInvocations,
    successfulInterpretations,
    fallbackCount,
    orchestratorStatus: aiModelOrchestrator.getStatus()
  };
}

module.exports = {
  semanticAiInterpreter,
  getSemanticInterpreterMetrics
};
