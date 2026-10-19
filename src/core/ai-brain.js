/**
 * EJII Continuous Adaptive & Self-Updating AI Brain Engine
 * Orchestrates real-time telemetry ingestion, continuous Bayesian reasoning,
 * adaptive Welford baseline learning, persistent diagnostic memory, and
 * a sandboxed, schema-validated Self-Updating Configuration Harness with
 * automatic circuit-breaker rollback.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const dns = require('dns');
const tls = require('tls');
const http = require('http');
const https = require('https');
const { execFile, spawnSync } = require('child_process');
const { reasoningEngine } = require('./reasoning-engine');
const { incidentBriefingProvider } = require('./llm-provider');
const { aiModelOrchestrator, FlowStateCompressor } = require('./ai-model-orchestrator');
const { getPhysicalNetworkInfo } = require('../network/routing/physical-network-detector');
const { DATA_DIR } = require('../config');
const {
  DEFAULT_BRAIN_CONFIG,
  parseBrainConfig,
  safeParseBrainConfig,
  hashBrainConfig
} = require('./brain-config-schema');
const { generateOptimizedBrainConfig } = require('./brain-optimizer-agent');

let auditLogger = null;
try {
  auditLogger = require('./audit-logger');
} catch (_) {}

const { brainPersistenceRepository } = require('../db/brain-persistence-repository');
const notificationDispatcher = require('../integrations/notifications/notification-dispatcher');

/**
 * Crash-atomic file write via temporary sibling file + rename.
 */
function writeFileAtomicSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmpPath, content, { encoding: 'utf8', flag: 'w' });
  fs.renameSync(tmpPath, targetPath);
}

/**
 * Helper to validate an IPv4 32-bit unsigned integer against SSRF / non-routable ranges.
 * Preserves RFC 1918 (10/8, 172.16/12, 192.168/16) and Loopback (127/8) for NOC diagnostics.
 */
function isAllowedIPv4Int(ipInt) {
  const unsigned = ipInt >>> 0;
  const b1 = (unsigned >>> 24) & 0xff;
  const b2 = (unsigned >>> 16) & 0xff;

  // Block 0.0.0.0/8 ("this" network)
  if (b1 === 0) return false;
  // Block 169.254.0.0/16 (RFC 3927 Link-Local & Cloud Metadata 169.254.169.254)
  if (b1 === 169 && b2 === 254) return false;
  // Block 224.0.0.0/4 (Multicast) and 240.0.0.0/4 (Reserved / Broadcast 255.255.255.255)
  if (b1 >= 224) return false;

  return true;
}

/**
 * Parses standard dotted-quad IPv4 string into a 32-bit unsigned integer, or returns null.
 * Rejects leading-zero octal octets (e.g., 0251.0372.0251.0372).
 */
function parseStrictIPv4ToInt(ipv4Str) {
  const parts = ipv4Str.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null; // Reject octal notation
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) return null;
    result = ((result << 8) | num) >>> 0;
  }
  return result >>> 0;
}

/**
 * Rigorous Target Canonicalization & Cloud Metadata SSRF Defense.
 * Blocks command injection, decimal dword IPs, hex/octal IPs, cloud metadata hostnames,
 * IPv4 link-local (169.254.0.0/16), IPv6 link-local (fe80::/10), AWS IPv6 metadata (fd00:ec2::254),
 * and IPv4-mapped/compatible IPv6 addresses (::ffff:169.254.169.254, ::ffff:a9fe:a9fe).
 * Strictly preserves RFC 1918 private subnets and loopback (127.0.0.1, ::1).
 */
function isSafeNetworkTarget(rawTarget) {
  if (typeof rawTarget !== 'string') return false;
  const trimmed = rawTarget.trim();
  if (trimmed.length === 0 || trimmed.length > 253) return false;

  // 1. Block shell metacharacters, whitespace, path traversal, and control chars
  if (/[;&|`$><\n\r\0\\'"(){}\s]|\.\./.test(trimmed)) return false;

  // Strip optional IPv6 brackets for inspection
  const unbracketed = trimmed.startsWith('[') && trimmed.endsWith(']')
    ? trimmed.slice(1, -1)
    : trimmed;
  if (unbracketed.includes('[') || unbracketed.includes(']')) return false;

  const lower = unbracketed.toLowerCase();

  // 2. Block pure integer / dword IPs (e.g. 2852039166) and hex literals (e.g. 0xa9fea9fe)
  if (/^\d+$/.test(lower) || /^0x[0-9a-f]+$/i.test(lower)) return false;

  // 3. Block cloud metadata hostnames
  const blockedHostnames = new Set([
    'metadata',
    'instance-data',
    'metadata.google.internal',
    'metadata.goog',
    '169.254.169.254.nip.io',
    '169.254.169.254.xip.io'
  ]);
  if (blockedHostnames.has(lower) || lower.endsWith('.metadata.google.internal') || lower.endsWith('.internal.cloudapp.net')) {
    return false;
  }

  // 4. If it looks like a dotted-quad (all segments numeric/hex/octal), validate strictly as IPv4
  if (/^[0-9a-fx.]+$/i.test(lower) && lower.includes('.')) {
    const ipInt = parseStrictIPv4ToInt(lower);
    if (ipInt === null) return false;
    return isAllowedIPv4Int(ipInt);
  }

  // 5. Check IPv6 addresses (including IPv4-mapped and IPv4-compatible IPv6)
  const ipVersion = net.isIP(unbracketed);
  if (ipVersion === 4) {
    const ipInt = parseStrictIPv4ToInt(unbracketed);
    return ipInt !== null && isAllowedIPv4Int(ipInt);
  }

  if (ipVersion === 6) {
    // Allow IPv6 loopback ::1
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
    // Block unspecified ::
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return false;
    // Block AWS IPv6 IMDS (fd00:ec2::254)
    if (lower.startsWith('fd00:ec2:') || lower === 'fd00:ec2::254') return false;
    // Block IPv6 link-local (fe80::/10 -> fe80..febf) and multicast (ff00::/8)
    if (/^fe[89ab][0-9a-f]:/.test(lower) || lower.startsWith('fe80:') || lower.startsWith('ff')) return false;

    // Extract embedded IPv4 from ::ffff:w.x.y.z or ::w.x.y.z
    const lastColonIdx = lower.lastIndexOf(':');
    const tail = lower.slice(lastColonIdx + 1);
    if (tail.includes('.')) {
      const embeddedInt = parseStrictIPv4ToInt(tail);
      if (embeddedInt === null || !isAllowedIPv4Int(embeddedInt)) return false;
    }

    // Extract hex-encoded IPv4 from ::ffff:a9fe:a9fe or 0:0:0:0:0:ffff:a9fe:a9fe
    const hexMappedMatch = lower.match(/(?:^|:)ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hexMappedMatch) {
      const high16 = parseInt(hexMappedMatch[1], 16);
      const low16 = parseInt(hexMappedMatch[2], 16);
      const mappedInt = (((high16 << 16) | low16) >>> 0);
      if (!isAllowedIPv4Int(mappedInt)) return false;
    }

    return true;
  }

  // 6. Validate as strict RFC-1123 hostname
  if (unbracketed.includes(':')) return false;
  const labels = lower.split('.');
  for (const label of labels) {
    if (!label || label.length > 63) return false;
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) return false;
  }
  // Reject if TLD is purely numeric (prevents partial IPv4 shorthand like 169.254.43518)
  if (/^\d+$/.test(labels[labels.length - 1])) return false;

  return true;
}

/**
 * Resolves a target hostname or IP and verifies that all resolved IPv4/IPv6 addresses
 * pass isSafeNetworkTarget(), defeating DNS Rebinding attacks against 169.254.169.254.
 */
async function resolveAndValidateTarget(rawTarget) {
  if (!isSafeNetworkTarget(rawTarget)) {
    throw new Error(`SECURITY_VIOLATION: Target "${rawTarget}" rejected by SSRF defense policy.`);
  }
  const clean = rawTarget.trim().replace(/^\[|\]$/g, '');
  if (net.isIP(clean) !== 0) {
    return { safeTarget: clean, resolvedIps: [clean], isIpLiteral: true };
  }

  const dnsPromises = dns.promises;
  const resolvedIps = [];

  if (clean.toLowerCase() === 'localhost') {
    resolvedIps.push('127.0.0.1', '::1');
  } else {
    try {
      const v4 = await dnsPromises.resolve4(clean).catch(() => []);
      const v6 = await dnsPromises.resolve6(clean).catch(() => []);
      resolvedIps.push(...v4, ...v6);
    } catch (_) {}

    // Fallback to getaddrinfo lookup if resolve4/resolve6 yielded empty
    if (resolvedIps.length === 0) {
      try {
        const lookups = await dnsPromises.lookup(clean, { all: true }).catch(() => []);
        if (Array.isArray(lookups)) {
          for (const l of lookups) {
            if (l && l.address && !resolvedIps.includes(l.address)) {
              resolvedIps.push(l.address);
            }
          }
        }
      } catch (_) {}
    }
  }

  for (const ip of resolvedIps) {
    if (!isSafeNetworkTarget(ip)) {
      throw new Error(
        `SECURITY_VIOLATION: Hostname "${clean}" resolved to forbidden address "${ip}" (DNS Rebinding SSRF blocked).`
      );
    }
  }

  return { safeTarget: clean, resolvedIps, isIpLiteral: false };
}

class AIBrain {
  constructor(options = {}) {
    const isTestEnv = process.env.NODE_ENV === 'test' || Boolean(options.isSimulationEnv);
    const defaultFilename = isTestEnv ? 'brain_memory.test.json' : 'brain_memory.json';
    const activeDataDir = process.env.EJII_DATA_DIR || DATA_DIR;

    this.dataDir = options.dataDir || activeDataDir;
    this.memoryFilePath = options.memoryFilePath || path.join(this.dataDir, defaultFilename);
    this.configFilePath = options.configFilePath || path.join(
      this.dataDir,
      isTestEnv ? 'brain-config.test.json' : 'brain-config.json'
    );
    this.isSimulationEnv = Boolean(options.isSimulationEnv);

    // Load and validate dynamic configuration
    this.dynamicConfig = { ...DEFAULT_BRAIN_CONFIG };
    this.loadDynamicConfig(options.initialConfig);

    this.isRunning = false;
    this.activeIncidents = new Map();
    this.recentEventsBuffer = [];
    this.maxEvents = this.dynamicConfig.maxEvents;
    this.baselineMetrics = new Map();
    this.incidentHistory = [];
    this.maxHistory = this.dynamicConfig.maxHistory;
    this.brainTickInterval = null;
    this.broadcastHandler = null;
    this.currentSubnet = null;
    this.subnetProfiles = {};
    this.lastLearningUpdate = new Date().toISOString();
    this._saveTimeout = null;

    // Self-Updating Harness State & Circuit Breaker Tracking
    this.selfUpdateHistory = [];
    this.lastStableConfig = { ...this.dynamicConfig };
    this.lastSelfUpdateAt = 0;
    this.isSelfUpdating = false;
    this.consecutiveRollbacks = 0;
    this.circuitBreakerTripped = false;
    this.runtimeErrorCount = 0;
    this._watchdogTimer = null;
    this.dispatchedNotifications = [];

    // Operator Feedback & Bounded Calibration Weights
    this.hypothesisCalibration = {};
    this.feedbackHistory = [];

    // Cross-Layer Host Telemetry Context Snapshot
    this.lastHostHealthSnapshot = null;

    // Multi-Model AI Orchestrator & Flow State Compressor
    this.aiModelOrchestrator = aiModelOrchestrator;
    this.flowStateCompressor = aiModelOrchestrator.flowStateCompressor;

    // Load persisted memory from disk
    this._loadMemory();

    // Start continuous autonomous reasoning cycle (unless disabled for isolated sandbox check)
    if (options.autoStart !== false) {
      this.startContinuousReasoning();
    }
  }

  /**
   * Loads and validates dynamic parameters from brain-config.json (or falls back safely to defaults).
   */
  loadDynamicConfig(overrideConfig = null) {
    try {
      if (overrideConfig && typeof overrideConfig === 'object') {
        this.dynamicConfig = parseBrainConfig(overrideConfig);
      } else if (fs.existsSync(this.configFilePath)) {
        const raw = fs.readFileSync(this.configFilePath, 'utf8');
        const parsed = JSON.parse(raw);
        this.dynamicConfig = parseBrainConfig(parsed);
      } else {
        this.dynamicConfig = { ...DEFAULT_BRAIN_CONFIG };
        if (!this.isSimulationEnv) {
          writeFileAtomicSync(this.configFilePath, JSON.stringify(this.dynamicConfig, null, 2));
        }
      }
    } catch (_) {
      this.dynamicConfig = { ...DEFAULT_BRAIN_CONFIG };
    }
    this.maxEvents = this.dynamicConfig.maxEvents;
    this.maxHistory = this.dynamicConfig.maxHistory;
    return this.dynamicConfig;
  }

  /**
   * Returns current validated dynamic config and its SHA-256 fingerprint.
   */
  getDynamicConfig() {
    return {
      config: { ...this.dynamicConfig },
      configHash: hashBrainConfig(this.dynamicConfig),
      circuitBreakerTripped: this.circuitBreakerTripped,
      consecutiveRollbacks: this.consecutiveRollbacks,
      lastSelfUpdateAt: this.lastSelfUpdateAt ? new Date(this.lastSelfUpdateAt).toISOString() : null,
      historyCount: this.selfUpdateHistory.length
    };
  }

  /**
   * Resets dynamic configuration and calibration weights back to deterministic factory defaults.
   */
  resetToDefaultConfig() {
    this.dynamicConfig = { ...DEFAULT_BRAIN_CONFIG };
    this.maxEvents = this.dynamicConfig.maxEvents;
    this.maxHistory = this.dynamicConfig.maxHistory;
    this.lastStableConfig = { ...this.dynamicConfig };
    this.consecutiveRollbacks = 0;
    this.circuitBreakerTripped = false;
    this.runtimeErrorCount = 0;
    this.lastHostHealthSnapshot = null;
    return this.dynamicConfig;
  }

  /**
   * Set custom memory file path (ensures complete test runner isolation of both memory and config)
   */
  setMemoryFilePath(customPath) {
    if (customPath) {
      this.memoryFilePath = customPath;
      this.configFilePath = path.join(path.dirname(customPath), 'brain-config.isolated.json');
      this.baselineMetrics.clear();
      this.incidentHistory = [];
      this.activeIncidents.clear();
      this.recentEventsBuffer = [];
      this.hypothesisCalibration = {};
      this.feedbackHistory = [];
      this.lastHostHealthSnapshot = null;
      this.resetToDefaultConfig();
      this._loadMemory();
    }
  }

  /**
   * Extracts a normalized host resource & NIC health context from the 4-pillar host audit
   * so network wire anomalies can be correlated against local workstation saturation.
   */
  _extractHostContext(hostAudit = {}) {
    const anomalies = Array.isArray(hostAudit.anomalies) ? hostAudit.anomalies : [];
    const cpuPercent = Number(hostAudit.pillars?.resources?.cpu?.loadPercent ?? hostAudit.cpuLoadPercent ?? hostAudit.resources?.cpuUsagePercent ?? hostAudit.cpuPercent ?? 0);
    const memPercent = Number(hostAudit.pillars?.resources?.memory?.usedPercent ?? hostAudit.memoryUsedPercent ?? hostAudit.resources?.memoryUsagePercent ?? hostAudit.memPercent ?? 0);
    const diskQueue = Number(hostAudit.pillars?.storage?.diskQueueLength ?? hostAudit.resources?.diskQueueLength ?? hostAudit.diskQueue ?? 0);
    const hasNicError = Boolean(hostAudit.network?.localNicDegraded) || Boolean(hostAudit.localNicDegraded) || anomalies.some(a => /network|adapter|nic|driver|ndis|drop/i.test(`${a.title || ''} ${a.plainEnglish || ''}`));
    const hasCpuOrMemCritical = Boolean(hostAudit.network?.localHostSaturated) || Boolean(hostAudit.localHostSaturated) || cpuPercent >= 90 || memPercent >= 92 || anomalies.some(a => a.severity === 'CRITICAL' && /cpu|memory|ram|resource/i.test(a.title || ''));

    return {
      overallStatus: hostAudit.overallStatus || 'HEALTHY',
      cpuPercent,
      memPercent,
      diskQueue,
      localHostSaturated: Boolean(hasCpuOrMemCritical),
      localNicDegraded: Boolean(hasNicError),
      activeHostAnomaliesCount: anomalies.length,
      capturedAt: new Date().toISOString()
    };
  }

  /**
   * Ingest host telemetry snapshot into memory for cross-layer correlation
   */
  ingestHostTelemetrySnapshot(hostAudit = {}) {
    this.lastHostHealthSnapshot = this._extractHostContext(hostAudit);
    return this.lastHostHealthSnapshot;
  }

  /**
   * Set external broadcast callback for WebSocket real-time event distribution
   */
  setBroadcastHandler(fn) {
    this.broadcastHandler = fn;
  }

  /**
   * Broadcast diagnostic update to connected UI operators
   */
  _notifyDiagnosticUpdate(payload) {
    if (typeof this.broadcastHandler === 'function') {
      try {
        this.broadcastHandler('AI_BRAIN_DIAGNOSTIC_UPDATE', payload);
      } catch (_) {}
    }
  }

  /**
   * Load persisted network brain memory from data/brain_memory.json
   */
  _loadMemory() {
    try {
      if (fs.existsSync(this.memoryFilePath)) {
        const raw = fs.readFileSync(this.memoryFilePath, 'utf8');
        const data = JSON.parse(raw);
        if (data.baselineMetrics) {
          for (const [k, v] of Object.entries(data.baselineMetrics)) {
            this.baselineMetrics.set(k, v);
          }
        }
        if (Array.isArray(data.incidentHistory)) {
          this.incidentHistory = data.incidentHistory.slice(-this.maxHistory);
        }
        if (data.subnetProfiles) {
          this.subnetProfiles = data.subnetProfiles;
        }
        if (Array.isArray(data.selfUpdateHistory)) {
          this.selfUpdateHistory = data.selfUpdateHistory.slice(-50);
        }
        if (data.hypothesisCalibration && typeof data.hypothesisCalibration === 'object') {
          this.hypothesisCalibration = data.hypothesisCalibration;
        }
        if (Array.isArray(data.feedbackHistory)) {
          this.feedbackHistory = data.feedbackHistory.slice(-100);
        }
        if (data.lastUpdated) {
          this.lastLearningUpdate = data.lastUpdated;
        }
      } else {
        this._saveMemory();
      }
    } catch (_) {
      this._saveMemory();
    }
  }

  /**
   * Debounced memory persistence to avoid disk thrashing during wire capture
   */
  _debouncedSaveMemory() {
    if (this._saveTimeout) return;
    this._saveTimeout = setTimeout(() => {
      this._saveTimeout = null;
      this._saveMemory();
    }, 1500);
    if (this._saveTimeout && typeof this._saveTimeout.unref === 'function') {
      this._saveTimeout.unref();
    }
  }

  /**
   * Persist brain memory atomically to data/brain_memory.json
   */
  _saveMemory() {
    if (this.isSimulationEnv) return;
    try {
      const serializableBaselines = {};
      for (const [k, v] of this.baselineMetrics.entries()) {
        serializableBaselines[k] = v;
      }

      const payload = {
        version: '2.2.0',
        lastUpdated: new Date().toISOString(),
        configHash: hashBrainConfig(this.dynamicConfig),
        baselinesCount: this.baselineMetrics.size,
        incidentsRecorded: this.incidentHistory.length,
        currentSubnet: this.currentSubnet,
        subnetProfiles: this.subnetProfiles,
        baselineMetrics: serializableBaselines,
        incidentHistory: this.incidentHistory.slice(-this.maxHistory),
        selfUpdateHistory: this.selfUpdateHistory.slice(-25),
        hypothesisCalibration: this.hypothesisCalibration,
        feedbackHistory: this.feedbackHistory.slice(-100)
      };

      writeFileAtomicSync(this.memoryFilePath, JSON.stringify(payload, null, 2));

      if (brainPersistenceRepository) {
        for (const [k, v] of this.baselineMetrics.entries()) {
          brainPersistenceRepository.saveBaseline(k, v, this.currentSubnet);
        }
        for (const incType of Object.keys(this.hypothesisCalibration || {})) {
          for (const hypId of Object.keys(this.hypothesisCalibration[incType] || {})) {
            brainPersistenceRepository.saveCalibration(incType, hypId, this.hypothesisCalibration[incType][hypId]);
          }
        }
      }
    } catch (_) {}
  }

  /**
   * Start continuous autonomous reasoning loop using dynamic brainTickIntervalMs
   */
  startContinuousReasoning() {
    if (this.isRunning) return;
    this.isRunning = true;

    const intervalMs = this.dynamicConfig.brainTickIntervalMs || 5000;
    this.brainTickInterval = setInterval(() => {
      this._continuousTick();
    }, intervalMs);
    if (this.brainTickInterval && typeof this.brainTickInterval.unref === 'function') {
      this.brainTickInterval.unref();
    }
  }

  /**
   * Stop continuous reasoning loop and clear pending timers
   */
  stopContinuousReasoning() {
    this.isRunning = false;
    if (this.brainTickInterval) {
      clearInterval(this.brainTickInterval);
      this.brainTickInterval = null;
    }
    if (this._saveTimeout) {
      clearTimeout(this._saveTimeout);
      this._saveTimeout = null;
    }
    if (this._watchdogTimer) {
      clearTimeout(this._watchdogTimer);
      this._watchdogTimer = null;
    }
    this._saveMemory();
  }

  /**
   * Internal autonomous background maintenance & self-modification check tick
   */
  _continuousTick() {
    const now = Date.now();
    const pruneTimeoutMs = this.dynamicConfig.incidentPruneTimeoutMs || 300000;

    for (const [key, incident] of this.activeIncidents.entries()) {
      if (now - new Date(incident.updatedAt).getTime() > pruneTimeoutMs) {
        this.activeIncidents.delete(key);
      }
    }

    // Evaluate whether unclassified drift or anomaly density warrants self-optimization
    if (!this.isSimulationEnv) {
      this.triggerSelfModificationCheck().catch(() => {});
    }
  }

  /**
   * Monitors live unclassified anomalies and drift ratios to determine if the
   * AI Brain should autonomously run a self-optimization cycle.
   */
  async triggerSelfModificationCheck() {
    if (this.isSelfUpdating || this.circuitBreakerTripped) {
      return { triggered: false, reason: this.circuitBreakerTripped ? 'CIRCUIT_BREAKER_TRIPPED' : 'UPDATE_IN_PROGRESS' };
    }

    const now = Date.now();
    if (now - this.lastSelfUpdateAt < this.dynamicConfig.selfUpdateCooldownMs) {
      return { triggered: false, reason: 'COOLDOWN_ACTIVE' };
    }

    if (this.recentEventsBuffer.length < this.dynamicConfig.minEventsForSelfUpdate) {
      return { triggered: false, reason: 'INSUFFICIENT_EVENT_SAMPLES' };
    }

    let driftCount = 0;
    for (const evt of this.recentEventsBuffer) {
      if (evt.isAnomaly || evt.isRetransmission || evt.isRst) {
        driftCount++;
      }
    }

    for (const inc of this.activeIncidents.values()) {
      if (inc.topHypothesis?.category === 'UNKNOWN' || (inc.topHypothesis?.confidence || 0) < 40) {
        driftCount += 2;
      }
    }

    const driftRatio = driftCount / Math.max(1, this.recentEventsBuffer.length);
    if (driftRatio >= this.dynamicConfig.anomalyDriftTriggerRatio) {
      return await this.optimizeBrainParameters({ triggerSource: 'AUTONOMOUS_DRIFT_DETECTOR', driftRatio });
    }

    return { triggered: false, reason: 'DRIFT_BELOW_THRESHOLD', driftRatio: Number(driftRatio.toFixed(4)) };
  }

  /**
   * Runs the Optimizer Agent to synthesize a new configuration from live telemetry
   * and routes it through the deterministic sandbox gatekeeper.
   */
  async optimizeBrainParameters(options = {}) {
    if (this.isSelfUpdating) {
      return { success: false, status: 'BUSY', message: 'Self-optimization cycle already in progress.' };
    }
    if (this.circuitBreakerTripped && !options.forceResetCircuitBreaker) {
      return {
        success: false,
        status: 'CIRCUIT_BREAKER_OPEN',
        message: 'Circuit breaker is open due to repeated rollbacks. Manual reset required.'
      };
    }

    if (options.forceResetCircuitBreaker) {
      this.circuitBreakerTripped = false;
      this.consecutiveRollbacks = 0;
    }

    this.isSelfUpdating = true;
    try {
      const optimization = await generateOptimizedBrainConfig({
        currentConfig: this.dynamicConfig,
        recentEvents: this.recentEventsBuffer,
        baselinesMap: this.baselineMetrics,
        activeIncidentsMap: this.activeIncidents,
        incidentHistory: this.incidentHistory,
        llmProvider: incidentBriefingProvider
      });

      const targetConfig = options.proposedConfigOverride || optimization.proposedConfig;
      const result = await this.testAndApplyNewConfig(targetConfig, {
        triggerSource: options.triggerSource || 'MANUAL_OR_API',
        rationale: optimization.rationale,
        optimizerSource: optimization.source,
        telemetrySnapshot: optimization.telemetrySnapshot
      });

      return result;
    } catch (err) {
      return {
        success: false,
        status: 'OPTIMIZATION_FAILED',
        error: err.message
      };
    } finally {
      this.isSelfUpdating = false;
    }
  }

  /**
   * Deterministic Gatekeeper:
   * 1. Validates schema via parseBrainConfig().
   * 2. Writes candidate to isolated brain-config.sandbox.json.
   * 3. Spawns an isolated child process to verify AIBrain operational invariants under load.
   * 4. Atomically writes brain-config.json and hot-swaps memory & intervals.
   * 5. Arms a post-deployment Watchdog Circuit Breaker.
   */
  async testAndApplyNewConfig(candidateConfig, metadata = {}) {
    const previousConfig = { ...this.dynamicConfig };
    const previousHash = hashBrainConfig(previousConfig);

    // Step 1: Strict Schema Validation
    const validatedConfig = parseBrainConfig(candidateConfig);
    const candidateHash = hashBrainConfig(validatedConfig);

    // Step 2: Write to isolated sandbox file (never overwrite production config before testing!)
    const sandboxConfigPath = path.join(this.dataDir, `brain-config.sandbox.${process.pid}.${Date.now()}.json`);
    writeFileAtomicSync(sandboxConfigPath, JSON.stringify(validatedConfig, null, 2));

    try {
      // Step 3: Execute isolated child-process verification gate using forward slashes for Windows safety
      const cleanFilename = __filename.replace(/\\/g, '/');
      const cleanSandboxPath = sandboxConfigPath.replace(/\\/g, '/');

      const verificationScript = [
        "const assert = require('assert');",
        "const fs = require('fs');",
        `const { AIBrain } = require(${JSON.stringify(cleanFilename)});`,
        `const sandboxCfg = JSON.parse(fs.readFileSync(${JSON.stringify(cleanSandboxPath)}, 'utf8'));`,
        "const simBrain = new AIBrain({",
        "  isSimulationEnv: true,",
        "  autoStart: false,",
        "  initialConfig: sandboxCfg",
        "});",
        "for (let i = 0; i < 10; i++) {",
        "  simBrain.ingestWireFrame({",
        "    srcIp: '192.168.31.89',",
        "    dstIp: '192.168.31.1',",
        "    dstPort: 443,",
        "    tcpAnalysis: { handshakeRttMs: 12 + (i % 4) }",
        "  });",
        "}",
        "simBrain.ingestWireFrame({",
        "  srcIp: '192.168.31.89',",
        "  dstIp: '192.168.31.1',",
        "  dstPort: 443,",
        "  tcpAnalysis: { handshakeRttMs: 650, isRetransmission: true },",
        "  tcp: { flags: { rst: true } }",
        "});",
        "const status = simBrain.getStatus();",
        "assert.strictEqual(status.status, 'OPERATIONAL', 'Sandbox brain must remain OPERATIONAL');",
        "assert.ok(status.activeIncidentsCount >= 1, 'Sandbox brain must detect synthetic wire anomaly');",
        "const live = simBrain.getLiveState();",
        "assert.ok(Array.isArray(live.rankedHypotheses) && live.rankedHypotheses.length > 0, 'Must rank hypotheses');",
        "const totalProb = live.rankedHypotheses.reduce((acc, h) => acc + (h.confidence || 0), 0);",
        "assert.ok(Math.abs(totalProb - 100) <= 1.5, 'Bayesian probabilities must normalize to ~100%');",
        "console.log('SANDBOX_VERIFICATION_PASSED');"
      ].join('\n');

      const childRes = spawnSync(process.execPath, ['-e', verificationScript], {
        cwd: path.resolve(__dirname, '../..'),
        env: { ...process.env, NODE_ENV: 'test', EJII_DATA_DIR: this.dataDir },
        timeout: 10000,
        encoding: 'utf8',
        windowsHide: true
      });

      if (childRes.status !== 0 || !(childRes.stdout || '').includes('SANDBOX_VERIFICATION_PASSED')) {
        throw new Error(
          `Sandbox verification gate rejected config: ${(childRes.stderr || childRes.stdout || 'Unknown error').trim()}`
        );
      }

      // Clean up temporary sandbox file
      if (fs.existsSync(sandboxConfigPath)) {
        try { fs.unlinkSync(sandboxConfigPath); } catch (_) {}
      }

      // Step 4: Atomic production persistence & live hot-swap
      this.lastStableConfig = previousConfig;
      if (!this.isSimulationEnv) {
        writeFileAtomicSync(this.configFilePath, JSON.stringify(validatedConfig, null, 2));
      }

      this.dynamicConfig = validatedConfig;
      this.maxEvents = validatedConfig.maxEvents;
      this.maxHistory = validatedConfig.maxHistory;
      this.lastSelfUpdateAt = Date.now();
      this.runtimeErrorCount = 0;

      // Trim buffers if max bounds were reduced
      if (this.recentEventsBuffer.length > this.maxEvents) {
        this.recentEventsBuffer = this.recentEventsBuffer.slice(-this.maxEvents);
      }
      if (this.incidentHistory.length > this.maxHistory) {
        this.incidentHistory = this.incidentHistory.slice(-this.maxHistory);
      }

      // Hot-swap continuous tick timer if interval changed
      if (this.isRunning && previousConfig.brainTickIntervalMs !== validatedConfig.brainTickIntervalMs) {
        if (this.brainTickInterval) clearInterval(this.brainTickInterval);
        this.brainTickInterval = setInterval(() => {
          this._continuousTick();
        }, validatedConfig.brainTickIntervalMs);
        if (this.brainTickInterval && typeof this.brainTickInterval.unref === 'function') {
          this.brainTickInterval.unref();
        }
      }

      const updateRecord = {
        updateId: `UPD-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
        timestamp: new Date().toISOString(),
        status: 'APPLIED_AND_VERIFIED',
        triggerSource: metadata.triggerSource || 'MANUAL',
        optimizerSource: metadata.optimizerSource || 'DIRECT',
        rationale: metadata.rationale || 'Configuration validated and applied via sandbox gate.',
        previousHash,
        newHash: candidateHash,
        previousConfig,
        appliedConfig: validatedConfig
      };

      this.selfUpdateHistory.push(updateRecord);
      if (this.selfUpdateHistory.length > 50) this.selfUpdateHistory.shift();
      this._debouncedSaveMemory();

      if (auditLogger && typeof auditLogger.logAction === 'function' && !this.isSimulationEnv) {
        try {
          auditLogger.logAction({
            userId: 'AI_BRAIN_AUTONOMOUS_HARNESS',
            action: 'BRAIN_SELF_MODIFICATION_COMMITTED',
            resource: 'src/core/ai-brain.js',
            details: {
              updateId: updateRecord.updateId,
              previousHash,
              newHash: candidateHash,
              triggerSource: updateRecord.triggerSource,
              rationale: updateRecord.rationale
            }
          });
        } catch (_) {}
      }

      this._notifyDiagnosticUpdate({
        type: 'BRAIN_CONFIG_HOT_SWAPPED',
        updateRecord
      });

      // Step 5: Arm Post-Deployment Watchdog Circuit Breaker
      this._armWatchdogCircuitBreaker(previousConfig, updateRecord.updateId);

      return {
        success: true,
        status: 'APPLIED_AND_VERIFIED',
        updateRecord
      };
    } catch (error) {
      if (fs.existsSync(sandboxConfigPath)) {
        try { fs.unlinkSync(sandboxConfigPath); } catch (_) {}
      }
      throw error;
    }
  }

  /**
   * Alias for commitSelfModification to support direct programmatic callers.
   */
  async commitSelfModification(newConfig, metadata = {}) {
    return this.testAndApplyNewConfig(newConfig, metadata);
  }

  /**
   * Arms a post-deployment watchdog timer that monitors runtime stability
   * and automatically rolls back to the prior stable config if exceptions spike.
   */
  _armWatchdogCircuitBreaker(backupConfig, updateId) {
    if (this._watchdogTimer) {
      clearTimeout(this._watchdogTimer);
    }
    const windowMs = this.dynamicConfig.watchdogWindowMs || 30000;
    this._watchdogTimer = setTimeout(() => {
      this._watchdogTimer = null;
      if (this.runtimeErrorCount > 0) {
        this.rollbackToStable(backupConfig, `Watchdog detected ${this.runtimeErrorCount} runtime error(s) after ${updateId}`);
      } else {
        this.consecutiveRollbacks = 0;
      }
    }, windowMs);
    if (this._watchdogTimer && typeof this._watchdogTimer.unref === 'function') {
      this._watchdogTimer.unref();
    }
  }

  /**
   * Emergency Circuit Breaker Rollback Routine:
   * Immediately restores the last known-good configuration in memory and on disk.
   */
  rollbackToStable(stableConfig = null, reason = 'Manual or watchdog rollback triggered') {
    const targetRestore = safeParseBrainConfig(stableConfig || this.lastStableConfig || DEFAULT_BRAIN_CONFIG).success
      ? parseBrainConfig(stableConfig || this.lastStableConfig || DEFAULT_BRAIN_CONFIG)
      : { ...DEFAULT_BRAIN_CONFIG };

    const failedConfig = { ...this.dynamicConfig };
    this.dynamicConfig = targetRestore;
    this.maxEvents = targetRestore.maxEvents;
    this.maxHistory = targetRestore.maxHistory;
    this.runtimeErrorCount = 0;
    this.consecutiveRollbacks++;

    if (this.consecutiveRollbacks >= (targetRestore.maxConsecutiveRollbacks || 3)) {
      this.circuitBreakerTripped = true;
    }

    if (!this.isSimulationEnv) {
      try {
        writeFileAtomicSync(this.configFilePath, JSON.stringify(targetRestore, null, 2));
      } catch (_) {}
    }

    if (this.isRunning) {
      if (this.brainTickInterval) clearInterval(this.brainTickInterval);
      this.brainTickInterval = setInterval(() => {
        this._continuousTick();
      }, targetRestore.brainTickIntervalMs);
      if (this.brainTickInterval && typeof this.brainTickInterval.unref === 'function') {
        this.brainTickInterval.unref();
      }
    }

    const rollbackRecord = {
      updateId: `RBK-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      status: 'ROLLED_BACK',
      reason,
      restoredHash: hashBrainConfig(targetRestore),
      failedConfig,
      restoredConfig: targetRestore,
      circuitBreakerTripped: this.circuitBreakerTripped
    };

    this.selfUpdateHistory.push(rollbackRecord);
    this._debouncedSaveMemory();

    if (auditLogger && typeof auditLogger.logAction === 'function' && !this.isSimulationEnv) {
      try {
        auditLogger.logAction({
          userId: 'AI_BRAIN_WATCHDOG',
          action: 'BRAIN_SELF_MODIFICATION_ROLLBACK',
          resource: 'src/core/ai-brain.js',
          details: rollbackRecord
        });
      } catch (_) {}
    }

    this._notifyDiagnosticUpdate({
      type: 'BRAIN_CONFIG_ROLLED_BACK',
      rollbackRecord
    });

    return {
      success: true,
      status: 'ROLLED_BACK',
      rollbackRecord
    };
  }

  /**
   * Reports an internal runtime fault to the watchdog circuit breaker.
   * If a watchdog window is active, immediately triggers rollbackToStable().
   */
  recordRuntimeFault(errorMessage = 'Unspecified runtime fault') {
    this.runtimeErrorCount++;
    if (this._watchdogTimer) {
      clearTimeout(this._watchdogTimer);
      this._watchdogTimer = null;
      return this.rollbackToStable(this.lastStableConfig, `Immediate watchdog trip: ${errorMessage}`);
    }
    return { faultRecorded: true, runtimeErrorCount: this.runtimeErrorCount };
  }

  /**
   * Returns full self-updating harness telemetry for API & UI inspection.
   */
  getSelfUpdateStatus() {
    return {
      enabled: true,
      isSelfUpdating: this.isSelfUpdating,
      circuitBreakerTripped: this.circuitBreakerTripped,
      consecutiveRollbacks: this.consecutiveRollbacks,
      watchdogActive: Boolean(this._watchdogTimer),
      currentConfig: { ...this.dynamicConfig },
      currentConfigHash: hashBrainConfig(this.dynamicConfig),
      lastStableConfigHash: hashBrainConfig(this.lastStableConfig),
      lastSelfUpdateAt: this.lastSelfUpdateAt ? new Date(this.lastSelfUpdateAt).toISOString() : null,
      history: this.selfUpdateHistory.slice(-20).reverse()
    };
  }

  /**
   * Records explicit operator feedback on an incident root cause hypothesis.
   * Adjusts empirical calibration weights within strict bounds [0.50, 2.00]
   * and re-evaluates the incident via the Bayesian Reasoning Engine.
   */
  recordOperatorFeedback({ incidentKey, verdict, confirmedHypothesisId, operatorNotes = '', userId = 'operator' } = {}) {
    if (!incidentKey || typeof incidentKey !== 'string') {
      throw new Error('Invalid parameter: incidentKey is required.');
    }
    const cleanVerdict = String(verdict || '').toUpperCase().trim();
    if (cleanVerdict !== 'CONFIRMED' && cleanVerdict !== 'REJECTED') {
      throw new Error("Invalid parameter: verdict must be 'CONFIRMED' or 'REJECTED'.");
    }
    if (!confirmedHypothesisId || typeof confirmedHypothesisId !== 'string') {
      throw new Error('Invalid parameter: confirmedHypothesisId is required.');
    }

    // Lookup incident in activeIncidents or incidentHistory
    let incident = this.activeIncidents.get(incidentKey);
    if (!incident) {
      incident = this.incidentHistory.find(i => i.id === incidentKey || i.incidentKey === incidentKey);
    }

    const incidentType = incident?.type || incident?.incidentType || incident?.evaluation?.telemetry?.incidentType || 'TCP_SYN_TIMEOUT';
    if (!this.hypothesisCalibration[incidentType]) {
      this.hypothesisCalibration[incidentType] = {};
    }

    const prevMultiplier = Number(this.hypothesisCalibration[incidentType][confirmedHypothesisId]) || 1.0;
    const factor = cleanVerdict === 'CONFIRMED' ? 1.12 : 0.88;
    const newMultiplier = Math.min(2.0, Math.max(0.5, Number((prevMultiplier * factor).toFixed(4))));
    this.hypothesisCalibration[incidentType][confirmedHypothesisId] = newMultiplier;

    // Prior telemetry for re-evaluation
    const telemetry = incident?.evaluation?.telemetry || incident?.telemetry || {
      incidentType,
      destIp: incident?.target || incident?.destIp || '127.0.0.1',
      destPort: incident?.port || incident?.destPort || 443
    };

    const revisedEvaluation = reasoningEngine.evaluateIncident({
      ...telemetry,
      calibrationWeights: this.hypothesisCalibration[incidentType]
    });

    if (incident) {
      incident.evaluation = revisedEvaluation;
      incident.updatedAt = new Date().toISOString();
    }

    const feedbackRecord = {
      feedbackId: `FBK-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      incidentKey,
      incidentType,
      userId,
      verdict: cleanVerdict,
      confirmedHypothesisId,
      previousWeight: prevMultiplier,
      newWeight: newMultiplier,
      operatorNotes: String(operatorNotes || '').trim().slice(0, 500)
    };

    this.feedbackHistory.push(feedbackRecord);
    if (this.feedbackHistory.length > 100) this.feedbackHistory.shift();

    this._saveMemory();

    try {
      if (brainPersistenceRepository) {
        brainPersistenceRepository.saveCalibration(incidentType, confirmedHypothesisId, newMultiplier, feedbackRecord);
      }
    } catch (_) {}

    if (auditLogger && typeof auditLogger.logAction === 'function' && !this.isSimulationEnv) {
      try {
        auditLogger.logAction({
          userId,
          action: 'OPERATOR_HYPOTHESIS_FEEDBACK_RECORDED',
          resource: 'src/core/ai-brain.js',
          details: {
            feedbackId: feedbackRecord.feedbackId,
            incidentKey,
            verdict: cleanVerdict,
            confirmedHypothesisId,
            previousWeight: prevMultiplier,
            newWeight: newMultiplier
          }
        });
      } catch (_) {}
    }

    this._notifyDiagnosticUpdate({
      type: 'OPERATOR_FEEDBACK_PROCESSED',
      feedbackRecord,
      revisedEvaluation
    });

    return {
      success: true,
      incidentKey,
      verdict: cleanVerdict,
      confirmedHypothesisId,
      calibrationWeight: newMultiplier,
      revisedEvaluation,
      feedbackRecord
    };
  }

  /**
   * Ingest a live wire frame from Npcap packet streamer or socket telemetry.
   */
  ingestWireFrame(frame) {
    if (!frame) return;

    // Track flow state and suppress redundant monotonous frames
    if (this.flowStateCompressor) {
      this.flowStateCompressor.ingestPacket({
        srcIp: frame.srcIp,
        srcPort: frame.srcPort,
        dstIp: frame.dstIp,
        dstPort: frame.dstPort,
        protocol: frame.protocol || 'TCP',
        flags: frame.tcp?.flags ? Object.keys(frame.tcp.flags).filter(k => frame.tcp.flags[k]).join('|') : '',
        length: frame.length || 0,
        isRetrans: Boolean(frame.tcpAnalysis?.isRetransmission),
        isZeroWindow: Boolean(frame.tcpAnalysis?.isZeroWindow)
      });
    }

    const netInfo = getPhysicalNetworkInfo();
    const activeGateway = netInfo?.gatewayIp || '192.168.31.1';
    if (!this.currentSubnet) {
      this.currentSubnet = activeGateway;
    } else if (this.currentSubnet !== activeGateway) {
      this._handleSubnetSwitch(activeGateway);
    }

    const targetIp = frame.dstIp || frame.srcIp;
    let latencyMs = null;

    if (frame.tcpAnalysis && typeof frame.tcpAnalysis.handshakeRttMs === 'number' && frame.tcpAnalysis.handshakeRttMs > 0) {
      latencyMs = frame.tcpAnalysis.handshakeRttMs;
    } else if (frame.tcpAnalysis && typeof frame.tcpAnalysis.rttMs === 'number' && frame.tcpAnalysis.rttMs > 0) {
      latencyMs = frame.tcpAnalysis.rttMs;
    } else if (typeof frame.ttfbMs === 'number' && frame.ttfbMs > 0) {
      latencyMs = frame.ttfbMs;
    } else if (typeof frame.icmpLatencyMs === 'number' && frame.icmpLatencyMs > 0) {
      latencyMs = frame.icmpLatencyMs;
    }

    if (targetIp && latencyMs !== null && latencyMs > 0) {
      this._updateBaseline(targetIp, latencyMs);

      const base = this.baselineMetrics.get(targetIp);
      const minSamples = this.dynamicConfig.minBaselineSamples || 3;
      const multiplier = this.dynamicConfig.adaptiveLatencyMultiplier || 3.0;
      const floorMs = this.dynamicConfig.minimumLatencyFloorMs || 100;

      if (base && base.sampleCount >= minSamples && latencyMs > base.avgRtt * multiplier && latencyMs > floorMs) {
        this.ingestTelemetry({
          target: targetIp,
          destIp: targetIp,
          destPort: frame.dstPort || 443,
          incidentType: 'HIGH_HANDSHAKE_VS_APP_LATENCY',
          handshakeLatencyMs: base.avgRtt,
          appLatencyMs: latencyMs,
          isAnomaly: true,
          rttMs: latencyMs
        });
      }
    }

    const isRst = Boolean(frame.tcp && frame.tcp.flags && frame.tcp.flags.rst);
    const isRetrans = Boolean(frame.tcpAnalysis && frame.tcpAnalysis.isRetransmission);
    if (isRst || isRetrans) {
      this.ingestTelemetry({
        target: targetIp,
        destIp: targetIp,
        destPort: frame.dstPort || 443,
        isRst,
        isRetransmission: isRetrans,
        incidentType: isRst ? 'TCP_RST_REJECT' : 'TCP_SYN_TIMEOUT',
        isAnomaly: true
      });
    }
  }

  /**
   * Handle physical network subnet change (e.g. Wi-Fi roaming or interface switch)
   */
  _handleSubnetSwitch(newSubnet) {
    if (!this.subnetProfiles) this.subnetProfiles = {};
    if (this.currentSubnet) {
      this.subnetProfiles[this.currentSubnet] = {
        baselines: Object.fromEntries(this.baselineMetrics),
        savedAt: new Date().toISOString()
      };
    }
    this.currentSubnet = newSubnet;
    if (this.subnetProfiles[newSubnet]) {
      this.baselineMetrics.clear();
      for (const [k, v] of Object.entries(this.subnetProfiles[newSubnet].baselines)) {
        this.baselineMetrics.set(k, v);
      }
    }
    this._saveMemory();
  }

  /**
   * Continuous Telemetry Ingestion
   */
  ingestTelemetry(event = {}) {
    const timestamp = new Date().toISOString();
    const enrichedEvent = {
      ...event,
      timestamp,
      eventId: `EVT-${Date.now()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`
    };

    this.recentEventsBuffer.push(enrichedEvent);
    if (this.recentEventsBuffer.length > this.maxEvents) {
      this.recentEventsBuffer.shift();
    }

    if (event.target && typeof event.rttMs === 'number' && event.rttMs > 0) {
      this._updateBaseline(event.target, event.rttMs);
    }

    if (event.isAnomaly || event.incidentType || event.isRetransmission || event.isRst) {
      return this._handleAnomalyEvent(enrichedEvent);
    }

    return { ingested: true, eventId: enrichedEvent.eventId };
  }

  /**
   * Update learned target latency baseline in memory using Welford's algorithm
   */
  _updateBaseline(target, rttMs) {
    const current = this.baselineMetrics.get(target) || {
      minRtt: rttMs,
      maxRtt: rttMs,
      avgRtt: rttMs,
      variance: 0,
      stddev: 0,
      m2: 0,
      sampleCount: 0,
      status: 'PROVISIONAL_INSUFFICIENT_SAMPLES',
      firstObserved: new Date().toISOString(),
      lastObserved: new Date().toISOString()
    };

    current.minRtt = Math.min(current.minRtt, rttMs);
    current.maxRtt = Math.max(current.maxRtt, rttMs);
    current.sampleCount++;

    const delta = rttMs - current.avgRtt;
    current.avgRtt = Number((current.avgRtt + delta / current.sampleCount).toFixed(2));
    const delta2 = rttMs - current.avgRtt;
    current.m2 = (current.m2 || 0) + delta * delta2;

    if (current.sampleCount >= 2) {
      current.variance = Number((current.m2 / (current.sampleCount - 1)).toFixed(2));
      current.stddev = Number(Math.sqrt(current.variance).toFixed(2));
    } else {
      current.variance = 0;
      current.stddev = 0;
    }

    const establishedThreshold = this.dynamicConfig.establishedSampleThreshold || 5;
    current.status = current.sampleCount < establishedThreshold ? 'PROVISIONAL_INSUFFICIENT_SAMPLES' : 'ESTABLISHED';
    current.lastObserved = new Date().toISOString();

    this.baselineMetrics.set(target, current);
    this.lastLearningUpdate = current.lastObserved;

    try {
      if (brainPersistenceRepository) {
        brainPersistenceRepository.saveBaseline(target, current, this.currentSubnet);
      }
    } catch (_) {}

    this._debouncedSaveMemory();
  }

  /**
   * Evaluate anomaly through Bayesian Reasoning Engine with Idempotent SHA-256 Keys
   */
  _handleAnomalyEvent(event) {
    const rawTarget = (event.target || event.destIp || 'unknown').toLowerCase().trim();
    const rawPort = parseInt(event.destPort, 10) || 0;
    const rawType = (event.incidentType || (event.isRst ? 'TCP_RST_REJECT' : 'TCP_SYN_TIMEOUT')).toUpperCase();

    const dayBucket = new Date().toISOString().slice(0, 10);
    const shaKey = crypto.createHash('sha256').update(`${dayBucket}:${rawTarget}:${rawPort}:${rawType}`).digest('hex').substring(0, 16);
    const incidentKey = `INC-${shaKey}`;

    const evaluation = reasoningEngine.evaluateIncident({
      incidentType: rawType,
      destIp: rawTarget,
      destPort: rawPort,
      tcpRstObserved: Boolean(event.isRst),
      retransCount: event.retransCount || (event.isRetransmission ? 1 : 0),
      handshakeLatencyMs: event.handshakeLatencyMs,
      appLatencyMs: event.appLatencyMs,
      dnsRcode: event.dnsRcode,
      tlsAlertCode: event.tlsAlertCode,
      hostContext: event.hostContext || this.lastHostHealthSnapshot || null
    });

    let revisedEvaluation = evaluation;
    if (this.activeIncidents.has(incidentKey)) {
      const priorIncident = this.activeIncidents.get(incidentKey);
      revisedEvaluation = reasoningEngine.reviseBeliefs(priorIncident.evaluation, {
        ...event,
        hostContext: event.hostContext || this.lastHostHealthSnapshot || null
      });
    }

    const briefing = incidentBriefingProvider.synthesizeBriefing(revisedEvaluation, event);

    const activeIncident = {
      id: incidentKey,
      incidentKey,
      type: revisedEvaluation.incidentType,
      incidentType: revisedEvaluation.incidentType,
      target: rawTarget,
      destPort: rawPort,
      port: rawPort,
      status: 'INVESTIGATING',
      topHypothesis: revisedEvaluation.topHypothesis,
      rankedHypotheses: revisedEvaluation.rankedHypotheses,
      distinguishingProbes: revisedEvaluation.distinguishingProbes,
      briefing,
      event,
      evaluation: revisedEvaluation,
      createdAt: this.activeIncidents.get(incidentKey)?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.activeIncidents.set(incidentKey, activeIncident);

    const existingIdx = this.incidentHistory.findIndex(h => h.incidentKey === incidentKey);
    const histRecord = {
      incidentKey,
      incidentType: activeIncident.incidentType,
      topHypothesis: activeIncident.topHypothesis.label,
      confidence: activeIncident.topHypothesis.confidence,
      target: rawTarget,
      destPort: rawPort,
      timestamp: activeIncident.updatedAt
    };

    if (existingIdx >= 0) {
      this.incidentHistory[existingIdx] = histRecord;
    } else {
      this.incidentHistory.push(histRecord);
      if (this.incidentHistory.length > this.maxHistory) {
        this.incidentHistory.shift();
      }
    }

    this._notifyDiagnosticUpdate(activeIncident);

    try {
      if (brainPersistenceRepository) {
        brainPersistenceRepository.saveIncident(activeIncident);
      }
    } catch (_) {}

    this._debouncedSaveMemory();

    return activeIncident;
  }

  /**
   * Comprehensive On-Demand Incident Diagnostic Entry Point
   */
  diagnoseIncident(params = {}) {
    const enrichedParams = {
      ...params,
      hostContext: params.hostContext || this.lastHostHealthSnapshot || null
    };
    const evaluation = reasoningEngine.evaluateIncident(enrichedParams);
    const briefing = incidentBriefingProvider.synthesizeBriefing(evaluation, enrichedParams);

    let orchestratorDecision = null;
    if (this.aiModelOrchestrator) {
      try {
        orchestratorDecision = this.aiModelOrchestrator.orchestrateDiagnosis(evaluation, enrichedParams);
      } catch (_) {}
    }

    return {
      incidentType: evaluation.incidentType,
      failureCategory: evaluation.topHypothesis?.category || 'UNKNOWN',
      topHypothesis: evaluation.topHypothesis,
      rankedHypotheses: evaluation.rankedHypotheses,
      distinguishingProbes: evaluation.distinguishingProbes,
      orchestrator: orchestratorDecision,
      simpleOperatorMode: briefing.simpleOperatorMode,
      expertDiagnosticMode: briefing.expertDiagnosticMode,
      baselineContext: params.destIp ? this.baselineMetrics.get(params.destIp) || null : null,
      hostContext: evaluation.hostContext || enrichedParams.hostContext || null,
      crossLayerCorrelation: Boolean(evaluation.crossLayerCorrelation),
      crossLayerNotes: evaluation.crossLayerNotes || [],
      evaluatedAt: evaluation.evaluatedAt
    };
  }

  /**
   * Live Operational Brain State for UI Dashboard Drawer
   */
  getLiveState() {
    const activeList = Array.from(this.activeIncidents.values());
    const topIncident = activeList.length > 0 ? activeList[activeList.length - 1] : null;
    const netInfo = getPhysicalNetworkInfo();
    const liveGateway = netInfo?.gatewayIp || '192.168.31.1';

    let evaluation;
    let recommendedProbe = null;

    if (topIncident) {
      evaluation = topIncident.evaluation;
      recommendedProbe = topIncident.distinguishingProbes?.[0] || null;
    } else {
      evaluation = reasoningEngine.evaluateIncident({
        incidentType: 'NORMAL_OPERATION',
        gatewayReachable: true,
        targetPingReachable: true
      });
      recommendedProbe = {
        probeType: 'ICMP_PING_GATEWAY',
        name: 'Periodic L2 Perimeter Health Ping',
        command: `ping -n 1 ${liveGateway}`,
        target: `Default Gateway (${liveGateway})`,
        expectedOutcome: 'Confirms continuous L2 switch fabric and gateway connectivity.',
        informationGain: 'High (Perimeter Health Assertion)'
      };
    }

    return {
      status: 'OPERATIONAL',
      continuousMode: this.isRunning,
      activeIncidentCount: this.activeIncidents.size,
      activeIncidents: activeList.slice(-5),
      topHypothesis: evaluation.topHypothesis,
      rankedHypotheses: evaluation.rankedHypotheses,
      distinguishingProbes: evaluation.distinguishingProbes || (recommendedProbe ? [recommendedProbe] : []),
      recommendedProbe,
      learnedBaselinesCount: this.baselineMetrics.size,
      totalEventsIngested: this.recentEventsBuffer.length,
      lastLearningUpdate: this.lastLearningUpdate || new Date().toISOString(),
      engine: 'Continuous Bayesian (Hare-Niemeyer 100.0%)',
      dynamicConfig: { ...this.dynamicConfig },
      selfUpdateStatus: this.getSelfUpdateStatus()
    };
  }

  /**
   * Executes a recommended diagnostic probe on real physical network wire using safe execFile,
   * feeds results into Bayesian engine, and dynamically revises beliefs on matching active incidents.
   * Accurately extracts OS kernel socket error codes (ECONNREFUSED, ETIMEDOUT, EHOSTUNREACH),
   * dynamically reports negotiated TLS versions and cipher suites, attributes DNS resolver types,
   * and enforces strict target canonicalization and cloud metadata SSRF defense.
   */
  async executeDiagnosticProbe({ probeType, targetIp, probeId, targetPort = 443, alternatePort = 80 }) {
    const netInfo = getPhysicalNetworkInfo();
    const gatewayIp = netInfo?.gatewayIp || '192.168.31.1';

    // Target safety and SSRF validation (including DNS rebinding defense)
    let target = null;
    let pinnedIp = null;
    let isIpLiteral = false;

    if (probeType === 'ICMP_PING_GATEWAY') {
      target = isSafeNetworkTarget(targetIp) ? targetIp.trim() : gatewayIp;
      pinnedIp = target;
      isIpLiteral = net.isIP(target) !== 0;
    } else {
      if (targetIp) {
        try {
          const validated = await resolveAndValidateTarget(targetIp);
          target = validated.safeTarget;
          pinnedIp = (validated.resolvedIps && validated.resolvedIps[0])
            ? validated.resolvedIps[0]
            : validated.safeTarget;
          isIpLiteral = Boolean(validated.isIpLiteral);
        } catch (secErr) {
          return {
            success: false,
            probeType,
            target: targetIp,
            pinnedIp: null,
            probeSuccess: false,
            latencyMs: 0,
            errorCode: 'SECURITY_TARGET_REJECTED',
            rawOutput: `Security rejection: Target '${targetIp}' is invalid or blocked by SSRF defense policy (${secErr.message}).`,
            error: 'SECURITY_TARGET_REJECTED',
            probeDetails: {
              target: targetIp,
              pinnedIp: null,
              errorCode: 'SECURITY_TARGET_REJECTED'
            },
            revisedEvaluation: null
          };
        }
      } else {
        target = gatewayIp;
        pinnedIp = gatewayIp;
        isIpLiteral = net.isIP(gatewayIp) !== 0;
      }
    }

    const destPort = parseInt(targetPort || 443, 10);
    const altPort = parseInt(alternatePort || 80, 10);

    let probeSuccess = false;
    let latencyMs = 0;
    let rawOutput = '';
    let socketErrorCode = null;
    let tlsNegotiatedProtocol = null;
    let tlsNegotiatedCipher = null;

    const startTime = Date.now();
    try {
      if (probeType === 'ICMP_PING_GATEWAY' || probeType === 'ICMP_PING_TARGET') {
        const pingDest = pinnedIp || target;
        const pingArgs = process.platform === 'win32'
          ? ['-n', '1', '-w', '1000', pingDest]
          : ['-c', '1', '-W', '1', pingDest];
        rawOutput = await new Promise((resolve) => {
          execFile('ping', pingArgs, { timeout: 2500, windowsHide: true }, (err, stdout, stderr) => {
            resolve(stdout || stderr || (err ? err.message : ''));
          });
        });
        latencyMs = Date.now() - startTime;
        probeSuccess = /TTL=/i.test(rawOutput) || /bytes from/i.test(rawOutput);
      } else if (
        probeType === 'TCP_SYN_ALTERNATE_PORT' ||
        probeType === 'TCP_CONNECT_ALTERNATE_PORT' ||
        probeType === 'TCP_SYN_TARGET_PORT' ||
        probeType === 'TCP_CONNECT_TARGET_PORT' ||
        probeType === 'TCP_PORT_PROBE'
      ) {
        const isAlt = probeType === 'TCP_SYN_ALTERNATE_PORT' || probeType === 'TCP_CONNECT_ALTERNATE_PORT';
        const port = isAlt ? altPort : destPort;
        let timedOut = false;

        probeSuccess = await new Promise((resolve) => {
          const socket = new net.Socket();
          socket.setTimeout(1500);
          socket.on('connect', () => {
            latencyMs = Date.now() - startTime;
            socket.destroy();
            resolve(true);
          });
          socket.on('timeout', () => {
            latencyMs = Date.now() - startTime;
            timedOut = true;
            socketErrorCode = 'ETIMEDOUT';
            socket.destroy();
            resolve(false);
          });
          socket.on('error', (err) => {
            latencyMs = Date.now() - startTime;
            socketErrorCode = err.code || err.message;
            socket.destroy();
            resolve(false);
          });
          socket.connect(port, pinnedIp || target);
        });

        if (probeSuccess) {
          rawOutput = `TCP connection to ${target}:${port} [pinned=${pinnedIp}] connected in ${latencyMs}ms (full TCP 3-way handshake SYN->SYN/ACK->ACK completed via net.Socket)`;
        } else if (socketErrorCode === 'ECONNREFUSED') {
          rawOutput = `TCP connection to ${target}:${port} [pinned=${pinnedIp}] rejected with ECONNREFUSED in ${latencyMs}ms (host is online and reachable; target OS kernel returned explicit RFC 793 TCP RST)`;
        } else if (timedOut || socketErrorCode === 'ETIMEDOUT') {
          rawOutput = `TCP connection to ${target}:${port} [pinned=${pinnedIp}] timed out in ${latencyMs}ms (no TCP SYN/ACK or RST received; indicates stateful firewall silent drop / perimeter ACL or routing blackhole)`;
        } else if (socketErrorCode === 'EHOSTUNREACH' || socketErrorCode === 'ENETUNREACH') {
          rawOutput = `TCP connection to ${target}:${port} [pinned=${pinnedIp}] failed with ${socketErrorCode} in ${latencyMs}ms (upstream routing failure; intermediate router returned ICMP Destination Unreachable)`;
        } else {
          rawOutput = `TCP connection to ${target}:${port} [pinned=${pinnedIp}] failed: ${socketErrorCode || 'timed out or refused'} in ${latencyMs}ms`;
        }
      } else if (probeType === 'DNS_QUERY_PROBE' || probeType === 'DNS_RESOLVE') {
        const isIp = net.isIP(target) !== 0;
        if (isIp) {
          try {
            const hostnames = await dns.promises.reverse(target);
            latencyMs = Date.now() - startTime;
            probeSuccess = Array.isArray(hostnames) && hostnames.length > 0;
            rawOutput = `DNS reverse PTR query (RFC 1035 via c-ares resolver) for ${target}: ${hostnames.join(', ')} (${latencyMs}ms)`;
          } catch (dnsErr) {
            latencyMs = Date.now() - startTime;
            probeSuccess = false;
            socketErrorCode = dnsErr.code || 'DNS_ERR';
            rawOutput = `DNS reverse PTR query (RFC 1035 via c-ares resolver) failed for ${target} [code=${socketErrorCode}]: ${dnsErr.message} (${latencyMs}ms)`;
          }
        } else {
          try {
            const addresses = await dns.promises.resolve4(target);
            latencyMs = Date.now() - startTime;
            probeSuccess = Array.isArray(addresses) && addresses.length > 0;
            rawOutput = `DNS RFC 1035 A record query (via c-ares resolver) for ${target}: ${addresses.join(', ')} (${latencyMs}ms)`;
          } catch (dnsErr) {
            latencyMs = Date.now() - startTime;
            probeSuccess = false;
            socketErrorCode = dnsErr.code || 'DNS_ERR';
            rawOutput = `DNS RFC 1035 A record query (via c-ares resolver) failed for ${target} [code=${socketErrorCode}]: ${dnsErr.message} (${latencyMs}ms)`;
          }
        }
      } else if (probeType === 'TLS_HANDSHAKE_PROBE' || probeType === 'TLS_AUDIT') {
        probeSuccess = await new Promise((resolve) => {
          const tlsSocket = tls.connect({
            host: pinnedIp || target,
            port: destPort,
            servername: isIpLiteral ? undefined : target,
            rejectUnauthorized: false,
            timeout: 2500
          }, () => {
            latencyMs = Date.now() - startTime;
            tlsNegotiatedProtocol = tlsSocket.getProtocol() || 'TLSv1.3';
            tlsNegotiatedCipher = tlsSocket.getCipher()?.name || 'UNKNOWN';
            const alpn = tlsSocket.alpnProtocol || 'none';
            const cert = tlsSocket.getPeerCertificate();
            const certValidTo = cert?.valid_to || 'N/A';
            rawOutput = `TLS cryptographic handshake established [pinned=${pinnedIp}]: protocol=${tlsNegotiatedProtocol}, cipher=${tlsNegotiatedCipher}, alpn=${alpn}, certExpiry=${certValidTo} (${latencyMs}ms)`;
            tlsSocket.end();
            resolve(true);
          });
          tlsSocket.on('timeout', () => {
            latencyMs = Date.now() - startTime;
            socketErrorCode = 'ETIMEDOUT';
            tlsSocket.destroy();
            rawOutput = `TLS handshake timed out after ${latencyMs}ms (no ServerHello returned by endpoint [pinned=${pinnedIp}])`;
            resolve(false);
          });
          tlsSocket.on('error', (err) => {
            latencyMs = Date.now() - startTime;
            socketErrorCode = err.code || err.message;
            tlsSocket.destroy();
            rawOutput = `TLS handshake error [code=${err.code || 'ALERT'}]: ${err.message} (${latencyMs}ms) [pinned=${pinnedIp}]`;
            resolve(false);
          });
        });
      } else if (probeType === 'HTTP_HEAD_PROBE' || probeType === 'HTTP_PROBE') {
        const isHttps = destPort === 443;
        const httpLib = isHttps ? https : http;
        probeSuccess = await new Promise((resolve) => {
          const req = httpLib.request({
            host: pinnedIp || target,
            port: destPort,
            method: 'HEAD',
            timeout: 2500,
            rejectUnauthorized: false,
            headers: isIpLiteral ? {} : { 'Host': target }
          }, (res) => {
            latencyMs = Date.now() - startTime;
            const serverHdr = res.headers['server'] || 'N/A';
            rawOutput = `HTTP HEAD status: ${res.statusCode} ${res.statusMessage || ''} [HTTP/${res.httpVersion}, server=${serverHdr}, pinned=${pinnedIp}] in ${latencyMs}ms`;
            resolve(res.statusCode >= 200 && res.statusCode < 500);
          });
          req.on('timeout', () => {
            latencyMs = Date.now() - startTime;
            socketErrorCode = 'ETIMEDOUT';
            req.destroy();
            rawOutput = `HTTP HEAD timed out after ${latencyMs}ms (no response headers received [pinned=${pinnedIp}])`;
            resolve(false);
          });
          req.on('error', (err) => {
            latencyMs = Date.now() - startTime;
            socketErrorCode = err.code || err.message;
            req.destroy();
            rawOutput = `HTTP HEAD error [code=${err.code || 'CONN_ERR'}]: ${err.message} in ${latencyMs}ms [pinned=${pinnedIp}]`;
            resolve(false);
          });
          req.end();
        });
      } else {
        probeSuccess = false;
        rawOutput = `Unrecognized diagnostic probe type: ${probeType}`;
      }
    } catch (e) {
      probeSuccess = false;
      rawOutput = `Probe error: ${e.message}`;
    }

    const isAltPortProbe = probeType === 'TCP_SYN_ALTERNATE_PORT' || probeType === 'TCP_CONNECT_ALTERNATE_PORT';
    const isTargetPortProbe = probeType === 'TCP_SYN_TARGET_PORT' || probeType === 'TCP_CONNECT_TARGET_PORT' || probeType === 'TCP_PORT_PROBE';
    const isDnsProbe = probeType === 'DNS_QUERY_PROBE' || probeType === 'DNS_RESOLVE';
    const isTlsProbe = probeType === 'TLS_HANDSHAKE_PROBE' || probeType === 'TLS_AUDIT';
    const isHttpProbe = probeType === 'HTTP_HEAD_PROBE' || probeType === 'HTTP_PROBE';

    const revisionEvidence = {
      destIp: target,
      gatewayReachable: probeType === 'ICMP_PING_GATEWAY' ? probeSuccess : null,
      targetPingReachable: probeType === 'ICMP_PING_TARGET' ? probeSuccess : null,
      altPortReachable: isAltPortProbe ? probeSuccess : null,
      targetPortReachable: isTargetPortProbe ? probeSuccess : null,
      tcpRstObserved: (isAltPortProbe || isTargetPortProbe) ? (socketErrorCode === 'ECONNREFUSED') : false,
      dnsResolved: isDnsProbe ? probeSuccess : null,
      tlsHandshakeSuccess: isTlsProbe ? probeSuccess : null,
      httpStatusOk: isHttpProbe ? probeSuccess : null,
      errorCode: socketErrorCode,
      negotiatedProtocol: tlsNegotiatedProtocol,
      cipher: tlsNegotiatedCipher
    };

    const dayBucket = new Date().toISOString().slice(0, 10);
    const normalizedTarget = target.toLowerCase().trim();
    const dayBucketKey = `INC-${crypto.createHash('sha256').update(`${dayBucket}:${normalizedTarget}:${destPort}:TCP_SYN_TIMEOUT`).digest('hex').substring(0, 16)}`;
    const legacyKey = `INC-${crypto.createHash('sha256').update(`${normalizedTarget}:${destPort}:TCP_SYN_TIMEOUT`).digest('hex').substring(0, 16)}`;

    // Match day-bucketed key first, then legacy key, then any active incident for this target IP
    let matchedKey = null;
    if (this.activeIncidents.has(dayBucketKey)) {
      matchedKey = dayBucketKey;
    } else if (this.activeIncidents.has(legacyKey)) {
      matchedKey = legacyKey;
    } else {
      for (const [k, inc] of this.activeIncidents.entries()) {
        if ((inc.target || '').toLowerCase() === normalizedTarget) {
          matchedKey = k;
          break;
        }
      }
    }

    let revisedEvaluation = null;
    if (matchedKey && this.activeIncidents.has(matchedKey)) {
      const prior = this.activeIncidents.get(matchedKey);
      revisedEvaluation = reasoningEngine.reviseBeliefs(prior.evaluation, revisionEvidence);
      prior.evaluation = revisedEvaluation;
      prior.topHypothesis = revisedEvaluation.topHypothesis;
      prior.rankedHypotheses = revisedEvaluation.rankedHypotheses;
      prior.distinguishingProbes = revisedEvaluation.distinguishingProbes;
      prior.updatedAt = new Date().toISOString();
      this.activeIncidents.set(matchedKey, prior);
      this._notifyDiagnosticUpdate(prior);
    } else {
      const incidentKey = dayBucketKey;
      revisedEvaluation = reasoningEngine.evaluateIncident({
        incidentType: revisionEvidence.tcpRstObserved ? 'TCP_RST_REJECT' : 'TCP_SYN_TIMEOUT',
        destIp: normalizedTarget,
        destPort,
        ...revisionEvidence
      });
      const incident = {
        id: incidentKey,
        incidentKey,
        type: 'TCP_SYN_TIMEOUT',
        incidentType: 'TCP_SYN_TIMEOUT',
        target: normalizedTarget,
        port: destPort,
        destPort,
        status: 'INVESTIGATING',
        topHypothesis: revisedEvaluation.topHypothesis,
        rankedHypotheses: revisedEvaluation.rankedHypotheses,
        distinguishingProbes: revisedEvaluation.distinguishingProbes,
        evaluation: revisedEvaluation,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      this.activeIncidents.set(incidentKey, incident);
      this._notifyDiagnosticUpdate(incident);
    }

    return {
      success: true,
      probeType,
      target,
      pinnedIp: pinnedIp || target,
      port: isAltPortProbe ? altPort : destPort,
      probeSuccess,
      latencyMs,
      rawOutput,
      errorCode: socketErrorCode,
      negotiatedProtocol: tlsNegotiatedProtocol,
      probeDetails: {
        target,
        pinnedIp: pinnedIp || target,
        port: isAltPortProbe ? altPort : destPort,
        socketErrorCode,
        tlsNegotiatedProtocol,
        tlsNegotiatedCipher
      },
      revisedEvaluation
    };
  }

  /**
   * Alias for executeDiagnosticProbe to support distinguishing probe callers.
   */
  async executeDistinguishingProbe(probeType, targetIp, params = {}) {
    return this.executeDiagnosticProbe({ probeType, targetIp, ...params });
  }

  /**
   * Runs an end-to-end autonomous multi-step diagnostic investigation against a target host/port.
   * Dispatches distinguishing probes on physical wire, revises Bayesian beliefs iteratively,
   * and terminates early when conclusive disambiguation (>= 80% confidence or 40% lead) is achieved.
   * Strictly enforces target SSRF protection, bounded step limits, and explainable stopping conditions.
   */
  async runAutonomousInvestigation({ targetIp, targetPort = 443, maxSteps = 4 } = {}) {
    const netInfo = getPhysicalNetworkInfo();
    const gatewayIp = netInfo?.gatewayIp || '192.168.31.1';
    const rawCandidate = targetIp || gatewayIp;
    const port = parseInt(targetPort, 10) || 443;
    const boundedSteps = Math.min(Math.max(1, parseInt(maxSteps, 10) || 4), 10);
    const investigationId = `INV-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const startTime = Date.now();

    if (targetIp) {
      try {
        await resolveAndValidateTarget(targetIp);
      } catch (secErr) {
        return {
          success: false,
          investigationId,
          target: targetIp,
          targetPort: port,
          stepsExecuted: 0,
          maxSteps: boundedSteps,
          conclusive: false,
          durationMs: 0,
          stoppingReason: 'SECURITY_TARGET_REJECTED',
          error: `Target '${targetIp}' is rejected by security and SSRF protection policy: ${secErr.message}`,
          steps: []
        };
      }
    }

    const target = isSafeNetworkTarget(rawCandidate) ? rawCandidate.trim() : gatewayIp;

    // 1. Initial Evaluation
    const dayBucket = new Date().toISOString().slice(0, 10);
    const dayBucketKey = `INC-${crypto.createHash('sha256').update(`${dayBucket}:${target.toLowerCase().trim()}:${port}:TCP_SYN_TIMEOUT`).digest('hex').substring(0, 16)}`;
    let currentIncident = this.activeIncidents.get(dayBucketKey);

    let currentEvaluation = currentIncident?.evaluation || reasoningEngine.evaluateIncident({
      incidentType: 'TCP_SYN_TIMEOUT',
      destIp: target,
      destPort: port,
      calibrationWeights: this.hypothesisCalibration['TCP_SYN_TIMEOUT'] || {}
    });

    const initialTopHypothesis = currentEvaluation.topHypothesis;
    const steps = [];
    const executedProbeTypes = new Set();
    let stoppingReason = 'MAX_STEPS_REACHED';

    const isDbOrInfraPort = [3306, 5432, 1433, 6379, 27017, 445, 3389, 22].includes(port);
    let probeCandidates;
    if (isDbOrInfraPort) {
      probeCandidates = [
        { probeType: 'ICMP_PING_GATEWAY', label: 'ICMP Echo Perimeter Gateway Probe' },
        { probeType: 'ICMP_PING_TARGET', label: 'ICMP Echo Target L3 Reachability' },
        { probeType: 'TCP_CONNECT_TARGET_PORT', label: `TCP Connect on Service Port ${port}` },
        { probeType: 'TCP_SYN_ALTERNATE_PORT', label: 'TCP Alternate Port Connection' }
      ];
    } else if (port === 443 || port === 8443) {
      probeCandidates = [
        { probeType: 'ICMP_PING_TARGET', label: 'ICMP Echo Target L3 Reachability' },
        { probeType: 'TLS_HANDSHAKE_PROBE', label: 'TLS 1.3 Cryptographic Handshake' },
        { probeType: 'HTTP_HEAD_PROBE', label: 'HTTP/HTTPS Application Layer Probe' },
        { probeType: 'TCP_SYN_ALTERNATE_PORT', label: 'TCP Alternate Port 80 Connection' },
        { probeType: 'DNS_QUERY_PROBE', label: 'RFC 1035 DNS Query' },
        { probeType: 'ICMP_PING_GATEWAY', label: 'ICMP Echo Perimeter Gateway Probe' }
      ];
    } else {
      probeCandidates = [
        { probeType: 'ICMP_PING_TARGET', label: 'ICMP Echo Target L3 Reachability' },
        { probeType: 'TCP_CONNECT_TARGET_PORT', label: `TCP Connect on Target Port ${port}` },
        { probeType: 'TCP_SYN_ALTERNATE_PORT', label: 'TCP Alternate Port Connection' },
        { probeType: 'DNS_QUERY_PROBE', label: 'RFC 1035 DNS Query' },
        { probeType: 'ICMP_PING_GATEWAY', label: 'ICMP Echo Perimeter Gateway Probe' }
      ];
    }

    for (let step = 1; step <= boundedSteps; step++) {
      const top = currentEvaluation.topHypothesis;
      const second = currentEvaluation.rankedHypotheses?.[1];
      const isConclusive = top && (top.confidence >= 80 || (second && (top.confidence - second.confidence) >= 40));

      if (currentEvaluation.allHypothesesContradicted) {
        stoppingReason = 'ALL_HYPOTHESES_CONTRADICTED';
        break;
      }

      if (isConclusive && step > 1) {
        stoppingReason = 'CONFIDENCE_THRESHOLD_REACHED';
        break;
      }

      let selectedProbe = (currentEvaluation.distinguishingProbes || []).find(p => !executedProbeTypes.has(p.probeType));
      if (!selectedProbe) {
        selectedProbe = probeCandidates.find(p => !executedProbeTypes.has(p.probeType));
      }
      if (!selectedProbe) {
        stoppingReason = 'PROBE_SPACE_EXHAUSTED';
        break;
      }

      executedProbeTypes.add(selectedProbe.probeType);

      const probeResult = await this.executeDiagnosticProbe({
        probeType: selectedProbe.probeType,
        targetIp: target,
        targetPort: port
      });

      const isIcmpFail = selectedProbe.probeType === 'ICMP_PING_TARGET' && !probeResult.probeSuccess;
      let icmpFilteredButHostAlive = false;
      let hostAliveEvidence = null;

      if (isIcmpFail) {
        // Multi-Turn Recovery Probing: Many office equipment, printers, and secure endpoints drop ICMP Echo.
        // Perform bounded Layer 4 socket sweep across common enterprise ports (80, 443, 445, 9100, 631).
        try {
          const l4Ports = [80, 443, 445, 9100, 631];
          for (const l4p of l4Ports) {
            const check = await new Promise((resolve) => {
              const s = new net.Socket();
              s.setTimeout(300);
              s.once('connect', () => { s.destroy(); resolve({ open: true, port: l4p, status: 'CONNECTED' }); });
              s.once('error', (err) => {
                s.destroy();
                if (err.code === 'ECONNREFUSED') {
                  resolve({ open: false, port: l4p, status: 'RST_ACTIVE' });
                } else {
                  resolve({ open: false, port: l4p, status: err.code || 'FAIL' });
                }
              });
              s.once('timeout', () => { s.destroy(); resolve({ open: false, port: l4p, status: 'TIMEOUT' }); });
              s.connect(l4p, target);
            });

            if (check.open || check.status === 'RST_ACTIVE') {
              icmpFilteredButHostAlive = true;
              hostAliveEvidence = check;
              break;
            }
          }
        } catch (_) {}

        if (icmpFilteredButHostAlive) {
          currentEvaluation = reasoningEngine.reviseBeliefs(currentEvaluation, {
            icmpFilteredButHostAlive: true,
            targetPingReachable: false,
            hostAliveL2OrL4: true
          });
        }
      }

      const priorTop = currentEvaluation.topHypothesis;
      currentEvaluation = probeResult.revisedEvaluation || currentEvaluation;
      const newTop = currentEvaluation.topHypothesis;

      steps.push({
        stepNumber: step,
        probeType: selectedProbe.probeType,
        probeSuccess: probeResult.probeSuccess,
        latencyMs: probeResult.latencyMs,
        rawOutput: probeResult.rawOutput,
        errorCode: probeResult.errorCode || null,
        priorTopHypothesis: priorTop?.label || null,
        newTopHypothesis: newTop?.label || null,
        confidence: newTop?.confidence || 0,
        revisions: currentEvaluation.revisions || [],
        icmpFilteredButHostAlive: Boolean(icmpFilteredButHostAlive),
        hostAliveEvidence
      });
    }

    const durationMs = Date.now() - startTime;
    const finalTop = currentEvaluation.topHypothesis;
    const finalSecond = currentEvaluation.rankedHypotheses?.[1];
    const conclusive = Boolean(finalTop && (finalTop.confidence >= 70 || (finalSecond && (finalTop.confidence - finalSecond.confidence) >= 30)));

    const initialEpistemic = reasoningEngine.computeEpistemicMetrics(initialTopHypothesis ? [initialTopHypothesis] : []);
    const finalEpistemic = reasoningEngine.computeEpistemicMetrics(currentEvaluation.rankedHypotheses || []);
    const initialEntropy = initialEpistemic.shannonEntropyBits;
    const finalEntropy = finalEpistemic.shannonEntropyBits;
    const informationGainBits = Math.max(0, Number((initialEntropy - finalEntropy).toFixed(4)));
    const entropyReductionRatio = initialEntropy > 0 ? Number((informationGainBits / initialEntropy).toFixed(4)) : 0;

    // Causal DAG Construction with Backtracking Detection
    const dagNodes = [{ id: 'NODE-START', label: `Target: ${target}:${port}`, type: 'INIT' }];
    const dagEdges = [];
    let prevNodeId = 'NODE-START';
    let backtrackingOccurred = false;

    steps.forEach((s) => {
      const nodeId = `STEP-${s.stepNumber}`;
      dagNodes.push({
        id: nodeId,
        label: `${s.probeType} (${s.probeSuccess ? 'PASS' : 'FAIL'})`,
        type: 'PROBE',
        probeType: s.probeType,
        success: s.probeSuccess,
        topHypothesis: s.newTopHypothesis,
        confidence: s.confidence
      });
      dagEdges.push({
        from: prevNodeId,
        to: nodeId,
        relation: s.probeSuccess ? 'EVIDENTIARY_PASS' : 'EVIDENTIARY_FAIL'
      });
      if (s.priorTopHypothesis && s.newTopHypothesis && s.priorTopHypothesis !== s.newTopHypothesis) {
        backtrackingOccurred = true;
      }
      prevNodeId = nodeId;
    });

    dagNodes.push({
      id: 'NODE-VERDICT',
      label: finalTop?.label || 'Inconclusive',
      type: 'VERDICT',
      confidence: finalTop?.confidence || 0
    });
    dagEdges.push({ from: prevNodeId, to: 'NODE-VERDICT', relation: 'CAUSAL_INFERENCE' });

    const dagSummary = {
      nodesCount: dagNodes.length,
      edgesCount: dagEdges.length,
      isAcyclic: true,
      backtrackingOccurred,
      dagNodes,
      dagEdges
    };

    return {
      success: true,
      investigationId,
      target,
      targetPort: port,
      stepsExecuted: steps.length,
      maxSteps: boundedSteps,
      conclusive,
      stoppingReason,
      durationMs,
      initialTopHypothesis: initialTopHypothesis?.label || null,
      finalTopHypothesis: finalTop,
      rankedHypotheses: currentEvaluation.rankedHypotheses || [],
      contradictoryEvidence: currentEvaluation.contradictoryEvidence || [],
      epistemicProgress: {
        initialEntropyBits: initialEntropy,
        finalEntropyBits: finalEntropy,
        informationGainBits,
        entropyReductionRatio,
        initialCertainty: initialEpistemic.epistemicCertaintyRatio,
        finalCertainty: finalEpistemic.epistemicCertaintyRatio
      },
      dagSummary,
      steps,
      icmpFilteredButHostAlive: steps.some(s => s.icmpFilteredButHostAlive),
      evaluation: currentEvaluation
    };
  }

  /**
   * Get operational status and health metrics of the AI Brain
   */
  getStatus() {
    const netInfo = getPhysicalNetworkInfo();
    return {
      status: 'OPERATIONAL',
      continuousMode: this.isRunning,
      activeIncidentsCount: this.activeIncidents.size,
      activeIncidents: Array.from(this.activeIncidents.values()),
      learnedBaselinesCount: this.baselineMetrics.size,
      totalEventsIngested: this.recentEventsBuffer.length,
      historyLength: this.incidentHistory.length,
      dynamicConfig: { ...this.dynamicConfig },
      selfUpdateStatus: this.getSelfUpdateStatus(),
      hostEnvironment: {
        hostIp: netInfo?.hostIp || '192.168.31.89',
        gatewayIp: netInfo?.gatewayIp || '192.168.31.1',
        adapter: netInfo?.adapterName || 'Wi-Fi'
      },
      lastMemorySync: this.lastLearningUpdate || new Date().toISOString()
    };
  }

  /**
   * Correlates concurrent failing targets across subnets and parent switches/gateways.
   * Clusters multiple failing hosts into a single Shared Upstream Outage event,
   * isolating whether a common default gateway, switch node (e.g. NODE-LAN-01, NODE-GW-01),
   * or subnet is the common single point of failure (SPOF).
   */
  correlateSharedUpstreamFaults(windowMs = 120000) {
    const now = Date.now();
    const failingIncidents = [];

    for (const [key, inc] of this.activeIncidents.entries()) {
      const ts = new Date(inc.timestamp || inc.lastSeen || now).getTime();
      if (now - ts <= windowMs) {
        const topH = inc.evaluation?.topHypothesis?.id || inc.incidentType;
        const isFailing = inc.incidentType !== 'NORMAL_OPERATION' &&
          (topH === 'GATEWAY_UNREACHABLE' || topH === 'REMOTE_HOST_DOWN' || topH === 'TCP_SYN_TIMEOUT' || topH === 'ARP_CONFLICT' || topH === 'FIREWALL_SILENT_DROP' || inc.incidentType === 'TCP_SYN_TIMEOUT');
        if (isFailing) {
          failingIncidents.push({
            incidentId: key,
            targetIp: inc.destIp || inc.targetIp,
            targetPort: inc.destPort || inc.targetPort,
            incidentType: inc.incidentType,
            topHypothesis: inc.evaluation?.topHypothesis?.label || topH,
            confidence: inc.evaluation?.topHypothesis?.confidence || 0,
            timestamp: inc.timestamp || inc.lastSeen || new Date().toISOString()
          });
        }
      }
    }

    // Group by subnet (/24)
    const subnetClusters = new Map();
    for (const inc of failingIncidents) {
      const ip = inc.targetIp;
      if (!ip) continue;
      const parts = ip.split('.');
      const subnet = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : 'UNKNOWN_SUBNET';
      if (!subnetClusters.has(subnet)) subnetClusters.set(subnet, []);
      subnetClusters.get(subnet).push(inc);
    }

    const clusters = [];
    let netInfo = null;
    try {
      netInfo = getPhysicalNetworkInfo();
    } catch (_) {}
    const liveGateway = netInfo?.gatewayIp || '192.168.31.1';

    for (const [subnet, incidents] of subnetClusters.entries()) {
      if (incidents.length >= 2) {
        const hasGateway = incidents.some(i => i.targetIp === liveGateway || String(i.topHypothesis).includes('Gateway'));
        const parentNode = hasGateway ? 'NODE-GW-01' : 'NODE-LAN-01';
        clusters.push({
          clusterId: `OUTAGE-${crypto.createHash('sha256').update(`${subnet}-${now}`).digest('hex').slice(0, 10)}`,
          subnet,
          parentNode,
          failingHostsCount: incidents.length,
          failingTargets: incidents.map(i => i.targetIp),
          sharedFaultHypothesis: hasGateway ? 'UPSTREAM_GATEWAY_OUTAGE' : 'COMMON_ACCESS_SWITCH_FAILURE',
          confidence: Math.min(99, 65 + incidents.length * 10),
          incidents,
          recommendedAction: hasGateway
            ? `Inspect Default Gateway (${liveGateway}) L2 ARP / link state before troubleshooting individual endpoints.`
            : `Inspect upstream switch (${parentNode}) servicing subnet ${subnet}; multiple concurrent failures indicate common switch/VLAN outage.`,
          detectedAt: new Date().toISOString()
        });
      }
    }

    return {
      evaluatedAt: new Date().toISOString(),
      activeFailingCount: failingIncidents.length,
      sharedOutagesDetected: clusters.length > 0,
      sharedOutagesCount: clusters.length,
      clusters,
      unclusteredFailingIncidents: failingIncidents.filter(inc => !clusters.some(c => c.failingTargets.includes(inc.targetIp)))
    };
  }

  /**
   * Get target baseline details
   */
  getTargetBaseline(target) {
    return this.baselineMetrics.get(target) || null;
  }

  /**
   * Evaluate host hardware diagnostics audit and produce plain-English synthesis with raw proof
   */
  evaluateHostHealth(hostAudit = {}) {
    this.lastHostHealthSnapshot = this._extractHostContext(hostAudit);

    const anomalies = hostAudit.anomalies || [];
    const overallStatus = hostAudit.overallStatus || 'HEALTHY';
    const hostName = hostAudit.host?.hostname || 'Host';

    let result;
    if (overallStatus === 'COLLECTION_ERROR') {
      result = {
        overallStatus: 'COLLECTION_ERROR',
        summary: `Host ${hostName} telemetry collection encountered operating system or permission errors.`,
        criticalIssuesCount: 0,
        warningIssuesCount: anomalies.length,
        recommendedAction: 'Verify PowerShell execution permissions and WMI/CIM service health.',
        plainEnglishReport: 'One or more subsystem telemetry queries failed, timed out, or encountered access denials on the host.',
        crossLayerCorrelationActive: true,
        hostContext: this.lastHostHealthSnapshot
      };
    } else if (overallStatus === 'UNKNOWN') {
      result = {
        overallStatus: 'UNKNOWN',
        summary: `Host ${hostName} telemetry unsupported on platform '${hostAudit.host?.platform || 'unknown'}'.`,
        criticalIssuesCount: 0,
        warningIssuesCount: 0,
        recommendedAction: 'Execute on supported Windows environment for full CIM/WMI telemetry.',
        plainEnglishReport: 'Hardware and subsystem telemetry sources are not supported on this platform.',
        crossLayerCorrelationActive: true,
        hostContext: this.lastHostHealthSnapshot
      };
    } else if (anomalies.length === 0) {
      result = {
        overallStatus,
        summary: `Host ${hostName} is operating with nominal parameters across all 4 foundational pillars.`,
        criticalIssuesCount: 0,
        warningIssuesCount: 0,
        recommendedAction: 'No remediation necessary.',
        plainEnglishReport: 'All hardware subsystems (CPU, memory, storage volumes, network interfaces, and drivers) are functioning within normal operational baselines.',
        crossLayerCorrelationActive: true,
        hostContext: this.lastHostHealthSnapshot
      };
    } else {
      const criticals = anomalies.filter(a => a.severity === 'CRITICAL');
      const warnings = anomalies.filter(a => a.severity === 'WARNING');
      const topAnomaly = criticals[0] || warnings[0];

      result = {
        overallStatus,
        summary: `Host stability is ${overallStatus.toLowerCase()} with ${criticals.length} critical and ${warnings.length} warning condition(s).`,
        criticalIssuesCount: criticals.length,
        warningIssuesCount: warnings.length,
        topAnomaly: {
          title: topAnomaly.title,
          severity: topAnomaly.severity,
          plainEnglish: topAnomaly.plainEnglish,
          rawProof: topAnomaly.rawProof,
          recipeId: topAnomaly.recipeId
        },
        recommendedAction: topAnomaly.recipeId || 'review_audit',
        plainEnglishReport: `Primary operational finding: ${topAnomaly.plainEnglish} Technical evidence: ${topAnomaly.rawProof}. Staged remediation: ${topAnomaly.recipeId}.`,
        crossLayerCorrelationActive: true,
        hostContext: this.lastHostHealthSnapshot
      };
    }

    this._notifyDiagnosticUpdate({
      eventType: 'HOST_HEALTH_DIAGNOSTIC',
      report: result,
      hostContext: this.lastHostHealthSnapshot
    });

    return result;
  }

  /**
   * Post-Remediation Verification & Telemetry Re-Calibration Hook
   */
  onRemediationExecuted(remediationResult, params = {}) {
    const target = params.target || params.destIp;
    if (target || params.pid) {
      if (target && Array.isArray(this.anomalyHistory)) {
        this.anomalyHistory = this.anomalyHistory.filter(a => a.destIp !== target);
      }
      // Re-evaluate any active incident matching the remediated subsystem/target
      if (this.activeIncidents) {
        for (const [key, incident] of this.activeIncidents.entries()) {
          if ((target && (key.includes(target) || incident.destIp === target)) ||
              (params.recipeId && incident.recipeId === params.recipeId)) {
            incident.status = 'REMEDIATED_PENDING_WIRE_CONFIRMATION';
            if (!Array.isArray(incident.remediationHistory)) {
              incident.remediationHistory = [];
            }
            incident.remediationHistory.push({
              recipeId: remediationResult?.recipeId,
              executedAt: new Date().toISOString(),
              verificationProof: remediationResult?.proof || remediationResult?.result || 'Remediation completed; awaiting wire verification',
              success: remediationResult?.success !== false
            });
            if (brainPersistenceRepository && typeof brainPersistenceRepository.saveIncident === 'function') {
              try { brainPersistenceRepository.saveIncident(incident); } catch (_) {}
            }
          }
        }
      }
    }

    if (this.dispatchedNotifications && notificationDispatcher) {
      this.dispatchedNotifications.push({
        type: 'REMEDIATION_EXECUTED',
        recipeId: remediationResult?.recipeId,
        target,
        timestamp: new Date().toISOString(),
        success: remediationResult?.success !== false
      });
      if (this.dispatchedNotifications.length > 100) this.dispatchedNotifications.shift();
    }

    return {
      acknowledged: true,
      timestamp: new Date().toISOString(),
      recipeId: remediationResult?.recipeId,
      status: 'REMEDIATED_PENDING_WIRE_CONFIRMATION'
    };
  }

  /**
   * Counterfactual Causal Remediation Simulator (do-calculus intervention)
   * Models the counterfactual intervention do(Action) against Bayesian incident hypotheses.
   */
  simulateCounterfactualFix({
    incidentType = 'TCP_SYN_TIMEOUT',
    currentEvaluation = null,
    proposedAction = 'flush_dns_cache',
    telemetry = {}
  } = {}) {
    // 1. Compute current evaluation & baseline entropy
    let baselineEval = currentEvaluation;
    if (!baselineEval || !Array.isArray(baselineEval.rankedHypotheses)) {
      const baseTelemetry = { ...telemetry };
      if ((incidentType === 'DNS_RESOLUTION_FAILURE' || incidentType === 'DNS_FAILURE') && baseTelemetry.dnsResolved === undefined) {
        baseTelemetry.dnsResolved = false;
      }
      baselineEval = reasoningEngine.evaluateIncident({
        incidentType,
        ...baseTelemetry
      });
    }

    const initialEpistemic = reasoningEngine.computeEpistemicMetrics(baselineEval.rankedHypotheses);
    const shannonEntropyBefore = initialEpistemic.shannonEntropyBits;
    const topBefore = baselineEval.topHypothesis || baselineEval.rankedHypotheses?.[0];

    // Calculate baseline risk (non-nominal probability)
    const nominalBefore = (baselineEval.rankedHypotheses || []).find((h) => h.id === 'NORMAL_OPERATION');
    const riskBefore = 100 - (nominalBefore ? nominalBefore.confidence : 0);

    // 2. Model the counterfactual intervention do(Action)
    const actionKey = String(proposedAction || '').toLowerCase().trim();
    let simulatedEvidence = {};
    let targetedHypothesis = 'GENERAL_ANOMALY';
    let resolutionExplanation = '';

    if (actionKey.includes('dns')) {
      targetedHypothesis = 'DNS_RESOLUTION_FAILURE';
      simulatedEvidence = { dnsResolved: true, dnsRcode: 'NOERROR' };
      resolutionExplanation = 'Flushing DNS cache and rebuilding resolver state eliminates domain resolution failures (RFC 1035).';
    } else if (actionKey.includes('spooler') || actionKey.includes('print')) {
      targetedHypothesis = 'PORT_CLOSED_SERVICE_STOPPED';
      simulatedEvidence = { targetPortReachable: true, tcpRstObserved: false, errorCode: null };
      resolutionExplanation = 'Restarting the Windows Print Spooler service clears hung RPC print queues and rebinds JetDirect/IPP ports (RFC 793).';
    } else if (actionKey.includes('service') || actionKey.includes('port')) {
      targetedHypothesis = 'PORT_CLOSED_SERVICE_STOPPED';
      simulatedEvidence = { targetPortReachable: true, tcpRstObserved: false, errorCode: null };
      resolutionExplanation = 'Starting the target application service process clears TCP RST rejections and establishes listener sockets.';
    } else if (actionKey.includes('trim') || actionKey.includes('memory') || actionKey.includes('resource')) {
      targetedHypothesis = 'LOCAL_HOST_RESOURCE_EXHAUSTION';
      simulatedEvidence = { hostContext: { localHostSaturated: false, cpuPercent: 15, memoryPercent: 35 } };
      resolutionExplanation = 'Trimming system working sets and releasing exhausted handles restores kernel socket allocation capacity.';
    } else if (actionKey.includes('nic') || actionKey.includes('adapter') || actionKey.includes('pnp')) {
      targetedHypothesis = 'LOCAL_NIC_STACK_ERROR';
      simulatedEvidence = { hostContext: { localNicDegraded: false }, gatewayReachable: true };
      resolutionExplanation = 'Resetting the local network adapter clears NDIS driver state and flushes corrupted ARP tables (RFC 1122).';
    } else if (actionKey.includes('dhcp') || actionKey.includes('renew') || actionKey.includes('ipconfig') || actionKey.includes('apipa')) {
      targetedHypothesis = 'APIPA_SELF_ASSIGNED_IP';
      simulatedEvidence = { gatewayReachable: true, targetPortReachable: true, dhcpLeaseAcquired: true };
      resolutionExplanation = 'Renewing DHCP lease acquires valid routable IP configuration, eliminating APIPA 169.254.x.x link-local fallback.';
    } else {
      targetedHypothesis = topBefore ? topBefore.id : 'ANOMALY';
      simulatedEvidence = { targetPortReachable: true, gatewayReachable: true };
      resolutionExplanation = `Executing proposed action "${proposedAction}" applies empirical remediation to target fault.`;
    }

    // 3. Compute projected post-intervention distribution P(H | E, do(Action))
    const combinedTelemetry = {
      ...(baselineEval.telemetry || {}),
      incidentType,
      ...telemetry,
      ...simulatedEvidence
    };

    const projectedEval = reasoningEngine.evaluateIncident(combinedTelemetry);
    const afterEpistemic = reasoningEngine.computeEpistemicMetrics(projectedEval.rankedHypotheses);
    const shannonEntropyAfter = afterEpistemic.shannonEntropyBits;
    const topAfter = projectedEval.topHypothesis || projectedEval.rankedHypotheses?.[0];

    const nominalAfter = (projectedEval.rankedHypotheses || []).find((h) => h.id === 'NORMAL_OPERATION');
    const riskAfter = 100 - (nominalAfter ? nominalAfter.confidence : 0);

    const targetHBefore = (baselineEval.rankedHypotheses || []).find((h) => h.id === targetedHypothesis) || topBefore;
    const targetHAfter = (projectedEval.rankedHypotheses || []).find((h) => h.id === targetedHypothesis);

    const probBefore = targetHBefore ? targetHBefore.confidence : 0;
    const probAfter = targetHAfter ? targetHAfter.confidence : 0;

    let expectedRiskReductionPct = 0;
    if (probBefore > 0) {
      expectedRiskReductionPct = Number(Math.max(0, Math.min(100, ((probBefore - probAfter) / probBefore) * 100)).toFixed(1));
    } else if (riskBefore > 0) {
      expectedRiskReductionPct = Number(Math.max(0, Math.min(100, ((riskBefore - riskAfter) / riskBefore) * 100)).toFixed(1));
    }

    const entropyDeltaBits = Number((shannonEntropyBefore - shannonEntropyAfter).toFixed(4));

    return {
      success: true,
      timestamp: new Date().toISOString(),
      intervention: {
        proposedAction,
        targetedHypothesis,
        resolutionExplanation
      },
      baseline: {
        incidentType,
        topHypothesis: topBefore,
        shannonEntropyBits: shannonEntropyBefore,
        failureRiskPct: Number(riskBefore.toFixed(1))
      },
      projected: {
        topHypothesis: topAfter,
        shannonEntropyBits: shannonEntropyAfter,
        failureRiskPct: Number(riskAfter.toFixed(1)),
        rankedHypotheses: projectedEval.rankedHypotheses
      },
      expectedRiskReductionPct,
      entropyDeltaBits,
      epistemicGainBits: entropyDeltaBits,
      plainLanguageSummary: `Counterfactual intervention do(${proposedAction}) targets ${targetedHypothesis}. Projected to reduce failure probability from ${probBefore}% to ${probAfter}% (an expected ${expectedRiskReductionPct}% risk reduction), lowering Shannon uncertainty by ${entropyDeltaBits} bits.`
    };
  }

  /**
   * Closed-Loop Autonomous Goal-Driven Task Planner & Executor:
   * 1. Parses operator goal & loads learned Endpoint Behavioral Profile from SQLite WAL.
   * 2. Plans a multi-stage DAG of diagnostic probes & office equipment checks.
   * 3. Executes probes with automatic L2/L4 recovery if ICMP is filtered.
   * 4. Correlates shared upstream subnet outages & builds token-budgeted context window.
   * 5. Retrieves Hybrid BM25 + Trigram Cosine RRF runbooks & simulates counterfactual fixes.
   * 6. Validates output against 8 empirical invariants & persists the workflow run.
   */
  async planAndExecuteAutonomousWorkflow({
    goal = 'Diagnose connectivity and service health',
    targetHost = '127.0.0.1',
    targetPort = 80,
    processName = '',
    deviceTypeHint = 'AUTO',
    userRole = 'ADMIN',
    maxIterations = 5
  } = {}) {
    const cleanTarget = String(targetHost || '127.0.0.1').trim();
    if (!isSafeNetworkTarget(cleanTarget) && !(/^169\.254\./.test(cleanTarget) && cleanTarget !== '169.254.169.254')) {
      throw new Error(`SECURITY_VIOLATION: Target "${cleanTarget}" is blocked by SSRF safety policy.`);
    }

    const startedAt = new Date().toISOString();
    const workflowId = `WF-${Date.now()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
    const numPort = Math.max(1, Math.min(65535, Number(targetPort) || 80));

    // Step 1: Load learned Endpoint Behavioral Profile from SQLite WAL
    const learnedProfile = brainPersistenceRepository && typeof brainPersistenceRepository.getEndpointProfile === 'function'
      ? brainPersistenceRepository.getEndpointProfile(cleanTarget)
      : null;

    // Step 2: Determine if target is an Office Equipment / APIPA target
    const { diagnoseOfficeDevice } = require('../network/diagnostics/office-device-resolver');
    const isApipa = /^169\.254\./.test(cleanTarget) && cleanTarget !== '169.254.169.254';
    const inferredDeviceType =
      deviceTypeHint !== 'AUTO'
        ? deviceTypeHint
        : /print|laserjet|canon|epson|brother|xerox|9100|631/i.test(goal) || numPort === 9100 || numPort === 631
          ? 'PRINTER'
          : /phone|voip|sip|5060/i.test(goal) || numPort === 5060
            ? 'VOIP_PHONE'
            : 'COMPUTER';

    // Step 3: Execute Office Device & 4-Hop Smart Path Diagnosis + Autonomous Multi-Step Wire Investigation
    const officeDiag = await diagnoseOfficeDevice({
      targetIp: cleanTarget,
      deviceTypeHint: inferredDeviceType,
      deviceName: processName || cleanTarget
    });

    let wireInvestigation = null;
    if (!isApipa) {
      try {
        wireInvestigation = await this.runAutonomousInvestigation({
          target: cleanTarget,
          targetIp: cleanTarget,
          destPort: numPort,
          incidentType: officeDiag.faultScenario === 'DEVICE_OFFLINE_OR_DISCONNECTED' ? 'TCP_SYN_TIMEOUT' : 'TCP_RST_REJECT',
          maxSteps: 3
        });
      } catch (_) {}
    }

    // Step 4: Update Endpoint Behavioral Profile if ICMP was filtered while L4 ports answered
    const openPorts = officeDiag.technicalTelemetry?.openPorts || [];
    const refusedPorts = officeDiag.technicalTelemetry?.refusedPorts || [];
    const icmpFilteredButAlive =
      !officeDiag.technicalTelemetry?.targetPingAlive && (openPorts.length > 0 || refusedPorts.length > 0);

    if (brainPersistenceRepository && typeof brainPersistenceRepository.upsertEndpointProfile === 'function') {
      try {
        brainPersistenceRepository.upsertEndpointProfile({
          targetKey: cleanTarget,
          macAddress: officeDiag.equipmentProfile?.digitalSignatureMac || 'Unknown',
          icmpFilteredNormal: icmpFilteredButAlive ? 1 : (learnedProfile?.icmp_filtered_normal || 0),
          knownOpenPorts: openPorts.length > 0 ? openPorts : (learnedProfile?.knownOpenPorts || []),
          expectedEquipmentType: officeDiag.equipmentProfile?.equipmentType || inferredDeviceType,
          apipaFlapIncrement: isApipa ? 1 : 0,
          lastRootCauseId: wireInvestigation?.finalEvaluation?.topHypothesis?.id || officeDiag.faultScenario
        });
      } catch (_) {}
    }

    // Step 5: Correlate Shared Upstream Subnet Outages & Build Prioritized Context Window
    const sharedOutages = typeof this.correlateSharedUpstreamFaults === 'function'
      ? this.correlateSharedUpstreamFaults(120000)
      : { clusters: [] };

    const { ragKnowledgeEngine } = require('./rag-knowledge-engine');
    const { contextWindowManager } = require('./context-window-manager');
    const { aiModelOrchestrator } = require('./ai-model-orchestrator');

    let ragHits = [];
    try {
      ragHits = ragKnowledgeEngine.retrieveRelevantContext(
        `${goal} ${cleanTarget} ${officeDiag.faultScenario} ${inferredDeviceType}`,
        { topK: 3 }
      );
    } catch (_) {}

    const bayesianEval = wireInvestigation?.finalEvaluation || reasoningEngine.evaluateIncident({
      incidentType: isApipa ? 'DHCP_POOL_EXHAUSTED_OR_APIPA' : 'TCP_SYN_TIMEOUT',
      destIp: cleanTarget,
      destPort: numPort,
      icmpFilteredButHostAlive: icmpFilteredButAlive
    });

    const contextBundle = contextWindowManager.buildPrioritizedContext({
      activeIncident: { goal, targetHost: cleanTarget, targetPort: numPort, faultScenario: officeDiag.faultScenario },
      wireEvidence: wireInvestigation?.steps || [],
      hostTelemetry: this.lastHostTelemetry || {},
      ragCitations: ragHits,
      historicalBaselines: this.baselineMetrics ? Object.fromEntries(this.baselineMetrics) : {}
    });

    // Step 6: Simulate Counterfactual Remediation Impact
    const proposedAction = isApipa
      ? 'renew_dhcp_lease'
      : inferredDeviceType === 'PRINTER'
        ? 'restart_print_spooler'
        : 'flush_dns_cache';
    const counterfactual = this.simulateCounterfactualFix({
      incidentType: bayesianEval.incidentType || 'TCP_SYN_TIMEOUT',
      currentEvaluation: bayesianEval,
      proposedAction
    });

    // Step 7: Self-Validate Final Diagnosis Against 8 Empirical Invariants
    const selfValidation = aiModelOrchestrator.validateDiagnosisOutput({
      synthesis: {
        headline: officeDiag.plainLanguageDiagnosis?.badge || bayesianEval.topHypothesis?.label,
        rationale: officeDiag.plainLanguageDiagnosis?.whatTheProblemIs || bayesianEval.topHypothesis?.rationale
      },
      bayesianEvaluation: bayesianEval,
      telemetryContext: {
        destIp: cleanTarget,
        target: cleanTarget,
        openPorts,
        icmpFilteredButHostAlive: icmpFilteredButAlive,
        tcpRstObserved: refusedPorts.includes(numPort),
        gatewayReachable: officeDiag.technicalTelemetry?.gatewayReachable
      }
    });

    const completedAt = new Date().toISOString();
    const durationMs = Math.max(1, new Date(completedAt).getTime() - new Date(startedAt).getTime());
    const steps = wireInvestigation?.steps || (officeDiag ? [{ step: 1, tool: 'office_diagnostics', output: officeDiag }] : []);
    const report = {
      success: true,
      workflowId,
      goal,
      targetHost: cleanTarget,
      targetPort: numPort,
      inferredDeviceType,
      status: 'COMPLETED',
      startedAt,
      completedAt,
      durationMs,
      iterations: Math.min(maxIterations, steps.length || 1),
      executionSteps: steps,
      synthesis: {
        summary: officeDiag.plainLanguageDiagnosis?.whatTheProblemIs || 'Autonomous goal completed successfully.',
        headline: officeDiag.plainLanguageDiagnosis?.badge || 'OPERATIONAL',
        rootCauseHypothesis: bayesianEval?.topHypothesis?.label || 'NORMAL_OPERATION',
        ragCitations: ragHits
      },
      learnedProfileApplied: Boolean(learnedProfile),
      icmpFilteredButAlive,
      officeEquipmentDiagnosis: officeDiag,
      visualConnectionPath: officeDiag.visualConnectionPath,
      plainLanguageDiagnosis: officeDiag.plainLanguageDiagnosis,
      bayesianEvaluation: bayesianEval,
      counterfactualSimulation: counterfactual,
      sharedOutageCorrelation: sharedOutages,
      contextWindowAccounting: contextBundle?.tokenAccounting || {},
      ragCitations: ragHits,
      selfValidation,
      invariantValidation: selfValidation,
      profile: brainPersistenceRepository ? brainPersistenceRepository.getEndpointProfile(cleanTarget) : null
    };

    if (brainPersistenceRepository && typeof brainPersistenceRepository.saveAutonomousWorkflowRun === 'function') {
      try {
        brainPersistenceRepository.saveAutonomousWorkflowRun(report);
      } catch (_) {}
    }

    return report;
  }

  getDispatchedNotifications(limit = 50) {
    return (this.dispatchedNotifications || []).slice(-limit).reverse();
  }
}

const defaultAIBrain = new AIBrain();

module.exports = {
  AIBrain,
  aiBrain: defaultAIBrain,
  isSafeNetworkTarget,
  resolveAndValidateTarget
};
