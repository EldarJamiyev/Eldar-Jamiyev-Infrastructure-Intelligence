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

function extractCharacterTrigrams(text) {
  if (!text || typeof text !== 'string') return [];
  const clean = text.toLowerCase().replace(/[^a-z0-9_.-]+/g, ' ').trim();
  const trigrams = [];
  for (let i = 0; i < clean.length - 2; i++) {
    trigrams.push(clean.substring(i, i + 3));
  }
  return trigrams;
}


/**
 * Ontological GraphRAG Knowledge Engine
 * In-memory heterogeneous graph linking Protocols <-> Faults <-> RFCs <-> Runbooks <-> Policies.
 * Executes Personalized PageRank (PPR) multi-hop path extraction and fuses with BM25 and N-gram cosine.
 */
class OntologicalKnowledgeGraph {
  constructor() {
    this.nodes = new Map();
    this.edges = new Map(); // fromId -> [{ toId, relation, weight }]
    this.incomingEdges = new Map(); // toId -> [{ fromId, relation, weight }]
    this._initializeOntology();
  }

  addNode(id, type, label, metadata = {}) {
    this.nodes.set(id, { id, type, label, ...metadata });
    if (!this.edges.has(id)) this.edges.set(id, []);
    if (!this.incomingEdges.has(id)) this.incomingEdges.set(id, []);
  }

  addEdge(fromId, toId, relation, weight = 1.0) {
    if (!this.nodes.has(fromId)) this.addNode(fromId, 'CONCEPT', fromId);
    if (!this.nodes.has(toId)) this.addNode(toId, 'CONCEPT', toId);

    const outList = this.edges.get(fromId) || [];
    outList.push({ toId, relation, weight });
    this.edges.set(fromId, outList);

    const inList = this.incomingEdges.get(toId) || [];
    inList.push({ fromId, relation, weight });
    this.incomingEdges.set(toId, inList);
  }

  _initializeOntology() {
    // Protocols
    this.addNode('PROTO_TCP', 'PROTOCOL', 'TCP Transport Layer (RFC 793)');
    this.addNode('PROTO_UDP', 'PROTOCOL', 'UDP Datagram Transport (RFC 768)');
    this.addNode('PROTO_ICMP', 'PROTOCOL', 'ICMP Control Protocol (RFC 792)');
    this.addNode('PROTO_DNS', 'PROTOCOL', 'DNS Domain Name System (RFC 1035)');
    this.addNode('PROTO_TLS', 'PROTOCOL', 'TLS Cryptographic Handshake (RFC 8446)');
    this.addNode('PROTO_ARP', 'PROTOCOL', 'ARP Address Resolution (RFC 826)');
    this.addNode('PROTO_DHCP', 'PROTOCOL', 'DHCP Dynamic Host Configuration (RFC 2131)');

    // Fault Signatures
    this.addNode('FAULT_SYN_TIMEOUT', 'FAULT', 'TCP SYN Silent Drop Timeout');
    this.addNode('FAULT_RST_REJECT', 'FAULT', 'TCP Connection Reset (RST) Rejection');
    this.addNode('FAULT_SERVFAIL', 'FAULT', 'DNS Resolution SERVFAIL / NXDOMAIN');
    this.addNode('FAULT_PMTU_BLACKHOLE', 'FAULT', 'Path MTU Discovery Blackhole');
    this.addNode('FAULT_CERT_EXPIRED', 'FAULT', 'TLS Handshake Certificate Expired or Untrusted');
    this.addNode('FAULT_APIPA_FALLBACK', 'FAULT', 'APIPA 169.254.x.x Link-Local Fallback');

    // Documents / Standards
    this.addNode('RFC-793-TCP-RST', 'DOCUMENT', 'RFC 793 Section 3.4 RST Generation');
    this.addNode('RFC-1122-KEEPALIVE', 'DOCUMENT', 'RFC 1122 Section 4.2.3.6 Keep-Alives');
    this.addNode('RFC-2979-FIREWALL-DROP', 'DOCUMENT', 'RFC 2979 Stateful Firewall Silent Drop');
    this.addNode('RFC-1035-DNS-DIAG', 'DOCUMENT', 'RFC 1035 DNS Diagnosis');
    this.addNode('RFC-8446-TLS13', 'DOCUMENT', 'RFC 8446 TLS 1.3 Handshake');
    this.addNode('RUNBOOK-WIN-PNP-DEGRADED', 'DOCUMENT', 'RB-04 Windows PnP Remediation');
    this.addNode('RUNBOOK-UNKNOWN-APP-ENDPOINT', 'DOCUMENT', 'RB-09 Endpoint Discovery');

    // Runbooks & Policies
    this.addNode('RUNBOOK_FLUSH_DNS', 'RUNBOOK', 'Flush DNS Cache & Rebuild Resolver State');
    this.addNode('RUNBOOK_RESTART_SERVICE', 'RUNBOOK', 'Restart Target Application Service Daemon');
    this.addNode('RUNBOOK_FIREWALL_RULE', 'RUNBOOK', 'Inspect Perimeter Firewall Security Group Rules');
    this.addNode('RUNBOOK_RENEW_DHCP', 'RUNBOOK', 'Release and Renew DHCP Lease');
    this.addNode('POLICY_SSRF_GUARD', 'POLICY', 'Strict Target Canonicalization & SSRF Defense');
    this.addNode('POLICY_RBAC_RULE', 'POLICY', 'Role-Based Access Control Sandboxing');

    // Directed Relationships
    this.addEdge('PROTO_TCP', 'FAULT_SYN_TIMEOUT', 'CAUSES', 1.0);
    this.addEdge('PROTO_TCP', 'FAULT_RST_REJECT', 'CAUSES', 1.0);
    this.addEdge('PROTO_DNS', 'FAULT_SERVFAIL', 'CAUSES', 1.0);
    this.addEdge('PROTO_TLS', 'FAULT_CERT_EXPIRED', 'CAUSES', 1.0);
    this.addEdge('PROTO_DHCP', 'FAULT_APIPA_FALLBACK', 'CAUSES', 1.0);

    this.addEdge('FAULT_SYN_TIMEOUT', 'RFC-2979-FIREWALL-DROP', 'INDICATES', 1.0);
    this.addEdge('FAULT_SYN_TIMEOUT', 'RUNBOOK_FIREWALL_RULE', 'REMEDIATED_BY', 0.95);
    this.addEdge('FAULT_RST_REJECT', 'RFC-793-TCP-RST', 'INDICATES', 1.0);
    this.addEdge('FAULT_RST_REJECT', 'RUNBOOK_RESTART_SERVICE', 'REMEDIATED_BY', 0.95);
    this.addEdge('FAULT_SERVFAIL', 'RFC-1035-DNS-DIAG', 'INDICATES', 1.0);
    this.addEdge('FAULT_SERVFAIL', 'RUNBOOK_FLUSH_DNS', 'REMEDIATED_BY', 0.95);
    this.addEdge('FAULT_CERT_EXPIRED', 'RFC-8446-TLS13', 'INDICATES', 1.0);
    this.addEdge('FAULT_APIPA_FALLBACK', 'RUNBOOK_RENEW_DHCP', 'REMEDIATED_BY', 0.95);

    this.addEdge('PROTO_TCP', 'RFC-1122-KEEPALIVE', 'DEFINES', 0.9);
    this.addEdge('RUNBOOK_FIREWALL_RULE', 'POLICY_RBAC_RULE', 'GOVERNED_BY', 0.85);
    this.addEdge('RUNBOOK_FLUSH_DNS', 'POLICY_SSRF_GUARD', 'GOVERNED_BY', 0.85);
  }

  computePPR(seedIds = [], { alpha = 0.85, maxIterations = 20 } = {}) {
    const nodeCount = this.nodes.size;
    if (nodeCount === 0 || !Array.isArray(seedIds) || seedIds.length === 0) {
      return new Map();
    }

    const validSeeds = seedIds.filter(id => this.nodes.has(id));
    if (validSeeds.length === 0) return new Map();

    // Preference vector p0
    const p0 = new Map();
    const seedWeight = 1.0 / validSeeds.length;
    for (const id of validSeeds) {
      p0.set(id, seedWeight);
    }

    // Initialize probability distribution
    let p = new Map(p0);

    for (let it = 0; it < maxIterations; it++) {
      const nextP = new Map();
      for (const [nodeId] of this.nodes) {
        nextP.set(nodeId, (1 - alpha) * (p0.get(nodeId) || 0));
      }

      for (const [fromId, outEdges] of this.edges.entries()) {
        const fromProb = p.get(fromId) || 0;
        if (fromProb <= 0 || outEdges.length === 0) continue;

        let totalOutWeight = 0;
        for (const e of outEdges) totalOutWeight += e.weight;
        if (totalOutWeight <= 0) totalOutWeight = 1;

        for (const e of outEdges) {
          const contrib = alpha * fromProb * (e.weight / totalOutWeight);
          nextP.set(e.toId, (nextP.get(e.toId) || 0) + contrib);
        }
      }

      p = nextP;
    }

    return p;
  }

  extractExplainingPath(seedId, targetDocId) {
    if (!seedId || !targetDocId || !this.nodes.has(seedId) || !this.nodes.has(targetDocId)) {
      return null;
    }
    if (seedId === targetDocId) return [seedId];

    // Simple BFS for shortest explaining chain
    const queue = [[seedId]];
    const visited = new Set([seedId]);

    while (queue.length > 0) {
      const path = queue.shift();
      const current = path[path.length - 1];

      if (current === targetDocId) {
        return path;
      }

      const outEdges = this.edges.get(current) || [];
      for (const e of outEdges) {
        if (!visited.has(e.toId)) {
          visited.add(e.toId);
          queue.push([...path, e.toId]);
        }
      }
    }

    return null;
  }
}

class RAGKnowledgeEngine {
  constructor(options = {}) {
    this.rootDir = options.rootDir || path.resolve(__dirname, '../..');
    this.documents = new Map();
    this.invertedIndex = new Map(); // token -> Set(docId)
    this.docLengths = new Map();
    this.avgDocLength = 1;
    this.lastIndexedAt = null;

    this.knowledgeGraph = new OntologicalKnowledgeGraph();
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
    const fullText = `${doc.docId || ''} ${doc.source || ''} ${doc.title || ''} ${doc.category || ''} ${doc.content || ''}`;
    const tokens = tokenizeText(fullText);
    const termFreq = new Map();
    for (const tok of tokens) {
      termFreq.set(tok, (termFreq.get(tok) || 0) + 1);
      if (!this.invertedIndex.has(tok)) {
        this.invertedIndex.set(tok, new Set());
      }
      this.invertedIndex.get(tok).add(doc.docId);
    }

    // Character 3-grams for morphological and sub-token fuzzy vector matching
    const trigrams = extractCharacterTrigrams(fullText);
    const trigramFreq = new Map();
    let trigramNormSq = 0;
    for (const tri of trigrams) {
      const c = (trigramFreq.get(tri) || 0) + 1;
      trigramFreq.set(tri, c);
    }
    for (const c of trigramFreq.values()) {
      trigramNormSq += c * c;
    }

    this.documents.set(doc.docId, {
      ...doc,
      termFreq,
      tokenCount: tokens.length,
      trigramFreq,
      trigramNorm: Math.sqrt(trigramNormSq) || 1
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
   * Retrieves top-K relevant knowledge records using Hybrid Okapi BM25 +
   * Character Trigram Cosine Similarity with Reciprocal Rank Fusion (RRF, k=60).
   */
  retrieveRelevantContext(queryText, { topK = 3, minScore = 0.08 } = {}) {
    const queryTokens = tokenizeText(queryText);
    const queryTrigrams = extractCharacterTrigrams(queryText);
    if ((queryTokens.length === 0 && queryTrigrams.length === 0) || this.documents.size === 0) {
      return [];
    }

    // Compute query trigram frequencies and norm
    const qTriFreq = new Map();
    let qTriNormSq = 0;
    for (const tri of queryTrigrams) {
      const c = (qTriFreq.get(tri) || 0) + 1;
      qTriFreq.set(tri, c);
    }
    for (const c of qTriFreq.values()) {
      qTriNormSq += c * c;
    }
    const qTriNorm = Math.sqrt(qTriNormSq) || 1;

    const N = this.documents.size;
    const k1 = 1.5;
    const b = 0.75;

    // Step 1: Compute BM25 scores
    const bm25Map = new Map();
    for (const [docId, doc] of this.documents.entries()) {
      let bm25 = 0;
      const docLen = this.docLengths.get(docId) || 1;
      for (const qTok of queryTokens) {
        const tf = doc.termFreq.get(qTok) || 0;
        if (tf === 0) continue;
        const df = this.invertedIndex.get(qTok)?.size || 0;
        const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));
        const numerator = tf * (k1 + 1);
        const denominator = tf + k1 * (1 - b + b * (docLen / this.avgDocLength));
        bm25 += idf * (numerator / denominator);
      }
      bm25Map.set(docId, bm25);
    }

    // Step 2: Compute N-gram Cosine Similarity
    const cosineMap = new Map();
    for (const [docId, doc] of this.documents.entries()) {
      let dotProduct = 0;
      if (doc.trigramFreq) {
        for (const [tri, qCount] of qTriFreq.entries()) {
          const dCount = doc.trigramFreq.get(tri) || 0;
          dotProduct += qCount * dCount;
        }
      }
      const cosine = dotProduct / (qTriNorm * (doc.trigramNorm || 1));
      cosineMap.set(docId, cosine);
    }

    // Step 3: Compute Ranks for Reciprocal Rank Fusion (k = 60)
    const sortedByBm25 = Array.from(bm25Map.entries()).sort((a, b) => b[1] - a[1]);
    const sortedByCosine = Array.from(cosineMap.entries()).sort((a, b) => b[1] - a[1]);

    const bm25RankMap = new Map();
    sortedByBm25.forEach(([docId], idx) => bm25RankMap.set(docId, idx + 1));

    const cosineRankMap = new Map();
    sortedByCosine.forEach(([docId], idx) => cosineRankMap.set(docId, idx + 1));

    // Step 2.5: Map query tokens to Ontological Knowledge Graph seeds & compute PPR
    const querySeeds = [];
    const lowerQuery = queryText.toLowerCase();
    if (lowerQuery.includes('tcp') || lowerQuery.includes('rst') || lowerQuery.includes('syn')) querySeeds.push('PROTO_TCP');
    if (lowerQuery.includes('udp')) querySeeds.push('PROTO_UDP');
    if (lowerQuery.includes('icmp') || lowerQuery.includes('ping')) querySeeds.push('PROTO_ICMP');
    if (lowerQuery.includes('dns') || lowerQuery.includes('servfail') || lowerQuery.includes('nxdomain')) querySeeds.push('PROTO_DNS');
    if (lowerQuery.includes('tls') || lowerQuery.includes('ssl') || lowerQuery.includes('cert')) querySeeds.push('PROTO_TLS');
    if (lowerQuery.includes('dhcp') || lowerQuery.includes('apipa')) querySeeds.push('PROTO_DHCP');
    if (lowerQuery.includes('rst') || lowerQuery.includes('refused')) querySeeds.push('FAULT_RST_REJECT');
    if (lowerQuery.includes('timeout') || lowerQuery.includes('drop')) querySeeds.push('FAULT_SYN_TIMEOUT');

    const pprMap = this.knowledgeGraph.computePPR(querySeeds);
    const sortedByPpr = Array.from(pprMap.entries()).sort((a, b) => b[1] - a[1]);
    const pprRankMap = new Map();
    sortedByPpr.forEach(([nodeId], idx) => pprRankMap.set(nodeId, idx + 1));

    const kRrf = 60;
    const results = [];

    for (const [docId, doc] of this.documents.entries()) {
      const bm25Score = bm25Map.get(docId) || 0;
      const cosineSim = cosineMap.get(docId) || 0;

      if (bm25Score === 0 && cosineSim < 0.04) continue;

      const rBm25 = bm25RankMap.get(docId) || 1000;
      const rCosine = cosineRankMap.get(docId) || 1000;

      // Step 2b: GraphRAG PPR Score & Multi-Hop Path Extraction
      const pprScore = pprMap.get(docId) || 0;
      const rPpr = pprRankMap.get(docId) || 1000;
      const rrfScore = (1 / (kRrf + rBm25)) + (1 / (kRrf + rCosine)) + (1 / (kRrf + rPpr));

      // Composite relevance score: ensures compatibility with existing BM25 thresholds (> 0.5)
      // while incorporating character n-gram cosine boost and GraphRAG topological proximity
      const relevanceScore = bm25Score > 0
        ? bm25Score + (cosineSim * 2.5) + (pprScore * 1.5)
        : (cosineSim * 3.5) + (pprScore * 2.0);

      // Extract multi-hop explaining path from active seeds to this document
      let explainingPath = null;
      for (const seed of querySeeds) {
        explainingPath = this.knowledgeGraph.extractExplainingPath(seed, docId);
        if (explainingPath) break;
      }

      if (relevanceScore >= minScore) {
        results.push({
          docId: doc.docId,
          title: doc.title,
          source: doc.source,
          category: doc.category,
          excerpt: doc.content.slice(0, 600),
          relevanceScore: Number(relevanceScore.toFixed(4)),
          bm25Score: Number(bm25Score.toFixed(4)),
          cosineSimilarity: Number(cosineSim.toFixed(4)),
          pprScore: Number(pprScore.toFixed(4)),
          rrfScore: Number(rrfScore.toFixed(6)),
          graphRagPath: explainingPath,
          knowledgeGraphSummary: explainingPath ? explainingPath.join(' -> ') : null
        });
      }
    }

    results.sort((a, b) => b.relevanceScore - a.relevanceScore);
    return results.slice(0, topK);
  }

  queryKnowledge(queryText, options = {}) {
    return this.retrieveRelevantContext(queryText, options);
  }
}

const ragKnowledgeEngine = new RAGKnowledgeEngine();

module.exports = {
  OntologicalKnowledgeGraph,
  RAGKnowledgeEngine,
  ragKnowledgeEngine,
  BUILTIN_RFC_AND_RUNBOOK_CORPUS
};
