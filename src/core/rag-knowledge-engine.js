/**
 * EJII Local Infrastructure Knowledge & Runbook RAG Engine (BM25 / TF-IDF)
 * Indexes local operational runbooks (runbooks/), security policies (policies/),
 * authoritative RFC protocol specifications, and verified historical incident fixes.
 * Provides deterministic, citation-backed context retrieval for the AI Brain without
 * external vector-database dependencies.
 */

const fs = require('fs');
const path = require('path');

const BUILTIN_RFC_AND_RUNBOOK_CORPUS = [
  {
    docId: 'RFC-793-TCP-RST',
    title: 'RFC 793 Section 3.4 — Transmission Control Protocol Reset (RST) Generation',
    source: 'IETF RFC 793 / Standard',
    category: 'TRANSPORT_LAYER',
    content: 'A TCP RST (Reset) segment is transmitted immediately when a connection request (SYN) arrives for a TCP port on which no application process is listening, or when an existing connection is aborted. Receiving an explicit TCP RST (OS kernel ECONNREFUSED / WSAECONNREFUSED) mathematically proves that L2 switching, L3 IP routing, and the destination host OS kernel are online and reachable, isolating the fault strictly to the target application service or local port binding.'
  },
  {
    docId: 'RFC-1122-KEEPALIVE',
    title: 'RFC 1122 Section 4.2.3.6 — TCP Keep-Alive Probes and Idle Session Verification',
    source: 'IETF RFC 1122 / Host Requirements',
    category: 'TRANSPORT_LAYER',
    content: 'TCP Keep-Alive probes are sent on idle connections using sequence number SND.NXT - 1 with 0 or 1 garbage octets of payload and PSH=0. The remote peer responds with a 0-length ACK containing ACK = SND.NXT. Keep-Alive probes and their ACKs are normal session maintenance heartbeats and must never be misclassified as packet loss retransmissions or duplicate ACKs.'
  },
  {
    docId: 'RFC-2979-FIREWALL-DROP',
    title: 'RFC 2979 — Stateful Firewall Silent Packet Drop vs. Explicit ICMP/TCP Rejection',
    source: 'IETF RFC 2979 / Perimeter Security',
    category: 'NETWORK_SECURITY',
    content: 'Stateful perimeter firewalls and cloud security groups typically discard unauthorized incoming TCP SYN packets silently without transmitting an ICMP Destination Unreachable or TCP RST response. This manifests on the client as an L4 socket timeout (ETIMEDOUT / WSAETIMEDOUT) and repeated exponential-backoff TCP SYN retransmissions while the local default gateway remains reachable via ICMP Echo.'
  },
  {
    docId: 'RFC-1035-DNS-DIAG',
    title: 'RFC 1035 — Domain Name System Resolution Failures (NXDOMAIN, SERVFAIL, REFUSED)',
    source: 'IETF RFC 1035 / Naming Services',
    category: 'APPLICATION_LAYER',
    content: 'DNS RCODE 3 (NXDOMAIN / ENOTFOUND) indicates the queried domain name does not exist in the authoritative zone. RCODE 2 (SERVFAIL / ESERVFAIL) indicates the recursive resolver failed to reach upstream authoritative nameservers or encountered DNSSEC validation failure. Always verify UDP/TCP port 53 reachability to the configured recursive resolver (default gateway or enterprise DNS) before diagnosing L4/L7 application timeouts.'
  },
  {
    docId: 'RFC-8446-TLS13',
    title: 'RFC 8446 — TLS 1.3 Cryptographic Handshake, SNI Cleartext Boundary & AEAD Opacity',
    source: 'IETF RFC 8446 / Cryptographic Transport',
    category: 'SECURITY_LAYER',
    content: 'In TLS 1.3, the ClientHello message exposes the target Server Name Indication (SNI) and supported cipher suites in cleartext unless ECH is used. Immediately following ServerHello, all handshake certificates and application data records (ContentType 23) are encrypted under AEAD ciphers (such as TLS_AES_256_GCM_SHA384). Passive wire dissectors can observe record lengths, timing, and alert codes, but cannot inspect HTTP paths, headers, or payloads inside encrypted ApplicationData records without session keys.'
  },
  {
    docId: 'RUNBOOK-WIN-PNP-DEGRADED',
    title: 'EJII Runbook RB-04 — Remediating Degraded Windows PnP Devices & Virtual Adapters',
    source: 'runbooks/windows-pnp-remediation.md',
    category: 'HOST_DIAGNOSTICS',
    content: 'When Windows Device Manager (Win32_PnPEntity) reports ConfigManagerErrorCode != 0 (such as ErrorCode 22 Disabled or ErrorCode 10/43 Failed to Start on virtual or physical adapters), verify whether the adapter is intentionally disabled (e.g., unused VPN virtual NIC) or requires a non-disruptive hardware PnP rescan (pnputil /scan-devices) via the rescan_pnp_devices remediation recipe.'
  },
  {
    docId: 'RUNBOOK-UNKNOWN-APP-ENDPOINT',
    title: 'EJII Runbook RB-09 — Discovering Unknown Application Server IPs and Ports',
    source: 'runbooks/unknown-app-endpoint-discovery.md',
    category: 'ENDPOINT_DISCOVERY',
    content: 'To discover which remote server IP and port an unknown local application connects to: (1) Open Wireshark Sniffer -> App Finder mode, (2) Filter by the executable name or PID and enable Watch Application Connections while reproducing the application action, (3) Correlate OS kernel TCP/UDP socket tables (Get-NetTCPConnection) with passive DNS A/AAAA responses and TLS ClientHello SNI, and (4) Execute the 5-Stage Endpoint Troubleshooter against the discovered Destination IP:Port.'
  }
];

function tokenizeText(text) {
  if (!text || typeof text !== 'string') return [];
  return text
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, ' ')
    .split(/\s+/)
    .filter((tok) => tok.length >= 2);
}

class RAGKnowledgeEngine {
  constructor(options = {}) {
    this.rootDir = options.rootDir || path.resolve(__dirname, '../..');
    this.documents = new Map();
    this.invertedIndex = new Map(); // token -> Set(docId)
    this.docLengths = new Map();
    this.avgDocLength = 1;
    this.lastIndexedAt = null;

    this.rebuildIndex();
  }

  /**
   * Indexes built-in RFC/Runbook entries, markdown/json files in runbooks/ and policies/,
   * and verified historical incidents.
   */
  rebuildIndex(extraDocuments = []) {
    this.documents.clear();
    this.invertedIndex.clear();
    this.docLengths.clear();

    for (const doc of BUILTIN_RFC_AND_RUNBOOK_CORPUS) {
      this._addDocumentToCorpus(doc);
    }

    // Scan runbooks/ and policies/ directories if present
    const foldersToScan = [
      { dir: path.join(this.rootDir, 'runbooks'), category: 'OPERATIONAL_RUNBOOK' },
      { dir: path.join(this.rootDir, 'policies'), category: 'SECURITY_POLICY' }
    ];

    for (const { dir, category } of foldersToScan) {
      try {
        if (fs.existsSync(dir)) {
          const files = fs.readdirSync(dir);
          for (const file of files) {
            if (!/\.(md|txt|json)$/i.test(file)) continue;
            const fullPath = path.join(dir, file);
            const stat = fs.statSync(fullPath);
            if (!stat.isFile() || stat.size > 256 * 1024) continue;
            const rawContent = fs.readFileSync(fullPath, 'utf8');
            this._addDocumentToCorpus({
              docId: `FILE:${path.basename(dir)}/${file}`,
              title: `${category}: ${file}`,
              source: `${path.basename(dir)}/${file}`,
              category,
              content: rawContent.slice(0, 4000)
            });
          }
        }
      } catch (_) {}
    }

    // Index autonomous remediation recipes
    try {
      const { autonomousRemediationEngine } = require('../systems/remediation/autonomous-remediation-engine');
      if (autonomousRemediationEngine && typeof autonomousRemediationEngine.getRecipeCatalog === 'function') {
        const recipes = autonomousRemediationEngine.getRecipeCatalog();
        for (const recipe of recipes) {
          this._addDocumentToCorpus({
            docId: `RECIPE:${recipe.id}`,
            title: `Remediation Recipe: ${recipe.name || recipe.title || recipe.id}`,
            source: 'src/systems/remediation/autonomous-remediation-engine.js',
            category: 'REMEDIATION_RECIPE',
            content: `${recipe.description || ''} Parameters: ${JSON.stringify(recipe.parameters || {})} Risk: ${recipe.riskLevel || 'TIER_1'} RequiredRole: ${recipe.requiredRole || 'OPERATOR'}`
          });
        }
      }
    } catch (_) {}

    // Index local PC automation scripts
    try {
      const { SCRIPT_CATALOG } = require('../tools/script-automation');
      if (Array.isArray(SCRIPT_CATALOG)) {
        for (const script of SCRIPT_CATALOG) {
          this._addDocumentToCorpus({
            docId: `SCRIPT:${script.filename}`,
            title: `Host Automation Script: ${script.name || script.filename}`,
            source: `scripts/${script.filename}`,
            category: 'HOST_AUTOMATION_SCRIPT',
            content: `${script.description || ''} Category: ${script.category || 'General'} Risk: ${script.risk || 'LOW'} Impact: ${script.impact || ''}`
          });
        }
      }
    } catch (_) {}

    if (Array.isArray(extraDocuments)) {
      for (const doc of extraDocuments) {
        if (doc && doc.docId && doc.content) {
          this._addDocumentToCorpus(doc);
        }
      }
    }

    let totalLen = 0;
    for (const len of this.docLengths.values()) totalLen += len;
    this.avgDocLength = this.documents.size > 0 ? totalLen / this.documents.size : 1;
    this.lastIndexedAt = new Date().toISOString();

    return {
      documentsIndexed: this.documents.size,
      vocabularySize: this.invertedIndex.size,
      lastIndexedAt: this.lastIndexedAt
    };
  }

  _addDocumentToCorpus(doc) {
    const tokens = tokenizeText(`${doc.docId || ''} ${doc.source || ''} ${doc.title || ''} ${doc.category || ''} ${doc.content || ''}`);
    const termFreq = new Map();
    for (const tok of tokens) {
      termFreq.set(tok, (termFreq.get(tok) || 0) + 1);
      if (!this.invertedIndex.has(tok)) {
        this.invertedIndex.set(tok, new Set());
      }
      this.invertedIndex.get(tok).add(doc.docId);
    }

    this.documents.set(doc.docId, {
      ...doc,
      termFreq,
      tokenCount: tokens.length
    });
    this.docLengths.set(doc.docId, Math.max(1, tokens.length));
  }

  /**
   * Indexes a verified incident resolution or operator feedback record into RAG memory.
   */
  ingestVerifiedIncident({ incidentKey, incidentType, target, confirmedHypothesisId, notes = '' }) {
    if (!incidentKey) return;
    const docId = `INCIDENT:${incidentKey}`;
    this._addDocumentToCorpus({
      docId,
      title: `Verified Incident Resolution ${incidentKey} (${incidentType || 'NETWORK_ANOMALY'})`,
      source: 'data/brain_memory.json',
      category: 'VERIFIED_INCIDENT_MEMORY',
      content: `Target: ${target || 'unknown'} | IncidentType: ${incidentType || 'unknown'} | Confirmed Root Cause: ${confirmedHypothesisId || 'unknown'} | Operator Notes: ${notes}`
    });
  }

  /**
   * Retrieves top-K relevant knowledge records using Okapi BM25 ranking.
   */
  retrieveRelevantContext(queryText, { topK = 3, minScore = 0.1 } = {}) {
    const queryTokens = tokenizeText(queryText);
    if (queryTokens.length === 0 || this.documents.size === 0) {
      return [];
    }

    const N = this.documents.size;
    const k1 = 1.5;
    const b = 0.75;
    const scores = [];

    for (const [docId, doc] of this.documents.entries()) {
      let score = 0;
      const docLen = this.docLengths.get(docId) || 1;

      for (const qTok of queryTokens) {
        const tf = doc.termFreq.get(qTok) || 0;
        if (tf === 0) continue;
        const df = this.invertedIndex.get(qTok)?.size || 0;
        const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));
        const numerator = tf * (k1 + 1);
        const denominator = tf + k1 * (1 - b + b * (docLen / this.avgDocLength));
        score += idf * (numerator / denominator);
      }

      if (score >= minScore) {
        scores.push({
          docId: doc.docId,
          title: doc.title,
          source: doc.source,
          category: doc.category,
          excerpt: doc.content.slice(0, 600),
          relevanceScore: Number(score.toFixed(4))
        });
      }
    }

    scores.sort((a, b) => b.relevanceScore - a.relevanceScore);
    return scores.slice(0, topK);
  }
}

const ragKnowledgeEngine = new RAGKnowledgeEngine();

module.exports = {
  RAGKnowledgeEngine,
  ragKnowledgeEngine,
  BUILTIN_RFC_AND_RUNBOOK_CORPUS
};
