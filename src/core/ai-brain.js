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
 * Validates that a probe target is a safe IPv4/IPv6 address or RFC-1123 hostname
 * (Strictly blocks command injection metacharacters).
 */
function isSafeNetworkTarget(target) {
  if (typeof target !== 'string' || target.length === 0 || target.length > 253) return false;
  if (/[;&|`$><\n\r\0\\'"]/.test(target)) return false;
  if (net.isIP(target) !== 0) return true;
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(target);
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
   * Set custom memory file path (useful for test runner isolation)
   */
  setMemoryFilePath(customPath) {
    if (customPath) {
      this.memoryFilePath = customPath;
      this.baselineMetrics.clear();
      this.incidentHistory = [];
      this._loadMemory();
    }
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
        selfUpdateHistory: this.selfUpdateHistory.slice(-25)
      };

      writeFileAtomicSync(this.memoryFilePath, JSON.stringify(payload, null, 2));
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
   * Ingest a live wire frame from Npcap packet streamer or socket telemetry.
   */
  ingestWireFrame(frame) {
    if (!frame) return;

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
      tlsAlertCode: event.tlsAlertCode
    });

    let revisedEvaluation = evaluation;
    if (this.activeIncidents.has(incidentKey)) {
      const priorIncident = this.activeIncidents.get(incidentKey);
      revisedEvaluation = reasoningEngine.reviseBeliefs(priorIncident.evaluation, event);
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
    this._debouncedSaveMemory();

    return activeIncident;
  }

  /**
   * Comprehensive On-Demand Incident Diagnostic Entry Point
   */
  diagnoseIncident(params = {}) {
    const evaluation = reasoningEngine.evaluateIncident(params);
    const briefing = incidentBriefingProvider.synthesizeBriefing(evaluation, params);

    return {
      incidentType: evaluation.incidentType,
      failureCategory: evaluation.topHypothesis?.category || 'UNKNOWN',
      topHypothesis: evaluation.topHypothesis,
      rankedHypotheses: evaluation.rankedHypotheses,
      distinguishingProbes: evaluation.distinguishingProbes,
      simpleOperatorMode: briefing.simpleOperatorMode,
      expertDiagnosticMode: briefing.expertDiagnosticMode,
      baselineContext: params.destIp ? this.baselineMetrics.get(params.destIp) || null : null,
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
   */
  async executeDiagnosticProbe({ probeType, targetIp, probeId, targetPort = 443, alternatePort = 80 }) {
    const netInfo = getPhysicalNetworkInfo();
    const gatewayIp = netInfo?.gatewayIp || '192.168.31.1';
    const rawCandidate = targetIp || (probeType === 'ICMP_PING_GATEWAY' ? gatewayIp : gatewayIp);
    const target = isSafeNetworkTarget(rawCandidate) ? rawCandidate : gatewayIp;
    const destPort = parseInt(targetPort || 443, 10);
    const altPort = parseInt(alternatePort || 80, 10);

    let probeSuccess = false;
    let latencyMs = 0;
    let rawOutput = '';

    const startTime = Date.now();
    try {
      if (probeType === 'ICMP_PING_GATEWAY' || probeType === 'ICMP_PING_TARGET') {
        const pingArgs = process.platform === 'win32'
          ? ['-n', '1', '-w', '1000', target]
          : ['-c', '1', '-W', '1', target];
        rawOutput = await new Promise((resolve) => {
          execFile('ping', pingArgs, { timeout: 2500, windowsHide: true }, (err, stdout, stderr) => {
            resolve(stdout || stderr || (err ? err.message : ''));
          });
        });
        latencyMs = Date.now() - startTime;
        probeSuccess = /TTL=/i.test(rawOutput) || /bytes from/i.test(rawOutput);
      } else if (probeType === 'TCP_SYN_ALTERNATE_PORT') {
        probeSuccess = await new Promise((resolve) => {
          const socket = new net.Socket();
          socket.setTimeout(1500);
          socket.on('connect', () => {
            latencyMs = Date.now() - startTime;
            socket.destroy();
            resolve(true);
          });
          socket.on('timeout', () => { socket.destroy(); resolve(false); });
          socket.on('error', () => { socket.destroy(); resolve(false); });
          socket.connect(altPort, target);
        });
        rawOutput = probeSuccess ? `TCP alternate port ${altPort} connected in ${latencyMs}ms` : `TCP alternate port ${altPort} connection timed out or refused`;
      } else if (probeType === 'TCP_SYN_TARGET_PORT' || probeType === 'TCP_PORT_PROBE') {
        probeSuccess = await new Promise((resolve) => {
          const socket = new net.Socket();
          socket.setTimeout(1500);
          socket.on('connect', () => {
            latencyMs = Date.now() - startTime;
            socket.destroy();
            resolve(true);
          });
          socket.on('timeout', () => { socket.destroy(); resolve(false); });
          socket.on('error', () => { socket.destroy(); resolve(false); });
          socket.connect(destPort, target);
        });
        rawOutput = probeSuccess ? `TCP target port ${destPort} connected in ${latencyMs}ms` : `TCP target port ${destPort} connection timed out or refused`;
      } else if (probeType === 'DNS_QUERY_PROBE' || probeType === 'DNS_RESOLVE') {
        const isIp = /^[0-9.]+$/.test(target);
        if (isIp) {
          try {
            const hostnames = await dns.promises.reverse(target);
            latencyMs = Date.now() - startTime;
            probeSuccess = Array.isArray(hostnames) && hostnames.length > 0;
            rawOutput = `DNS reverse lookup for ${target}: ${hostnames.join(', ')}`;
          } catch (dnsErr) {
            latencyMs = Date.now() - startTime;
            probeSuccess = false;
            rawOutput = `DNS reverse lookup failed for ${target}: ${dnsErr.message}`;
          }
        } else {
          try {
            const addresses = await dns.promises.resolve4(target);
            latencyMs = Date.now() - startTime;
            probeSuccess = Array.isArray(addresses) && addresses.length > 0;
            rawOutput = `DNS RFC 1035 A record for ${target}: ${addresses.join(', ')}`;
          } catch (dnsErr) {
            latencyMs = Date.now() - startTime;
            probeSuccess = false;
            rawOutput = `DNS resolution failed for ${target}: ${dnsErr.message}`;
          }
        }
      } else if (probeType === 'TLS_HANDSHAKE_PROBE' || probeType === 'TLS_AUDIT') {
        probeSuccess = await new Promise((resolve) => {
          const tlsSocket = tls.connect({
            host: target,
            port: destPort,
            servername: /^[0-9.]+$/.test(target) ? undefined : target,
            rejectUnauthorized: false,
            timeout: 2500
          }, () => {
            latencyMs = Date.now() - startTime;
            rawOutput = `TLS 1.3/1.2 handshake established: protocol=${tlsSocket.getProtocol()}, cipher=${tlsSocket.getCipher()?.name}`;
            tlsSocket.end();
            resolve(true);
          });
          tlsSocket.on('timeout', () => {
            latencyMs = Date.now() - startTime;
            tlsSocket.destroy();
            rawOutput = 'TLS handshake timed out';
            resolve(false);
          });
          tlsSocket.on('error', (err) => {
            latencyMs = Date.now() - startTime;
            tlsSocket.destroy();
            rawOutput = `TLS handshake error: ${err.message}`;
            resolve(false);
          });
        });
      } else if (probeType === 'HTTP_HEAD_PROBE' || probeType === 'HTTP_PROBE') {
        const isHttps = destPort === 443;
        const httpLib = isHttps ? https : http;
        probeSuccess = await new Promise((resolve) => {
          const req = httpLib.request({
            hostname: target,
            port: destPort,
            method: 'HEAD',
            timeout: 2500,
            rejectUnauthorized: false
          }, (res) => {
            latencyMs = Date.now() - startTime;
            rawOutput = `HTTP HEAD status: ${res.statusCode} ${res.statusMessage || ''}`;
            resolve(res.statusCode >= 200 && res.statusCode < 500);
          });
          req.on('timeout', () => {
            latencyMs = Date.now() - startTime;
            req.destroy();
            rawOutput = 'HTTP HEAD timed out';
            resolve(false);
          });
          req.on('error', (err) => {
            latencyMs = Date.now() - startTime;
            req.destroy();
            rawOutput = `HTTP HEAD error: ${err.message}`;
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

    const revisionEvidence = {
      destIp: target,
      gatewayReachable: probeType === 'ICMP_PING_GATEWAY' ? probeSuccess : null,
      targetPingReachable: probeType === 'ICMP_PING_TARGET' ? probeSuccess : null,
      altPortReachable: probeType === 'TCP_SYN_ALTERNATE_PORT' ? probeSuccess : null,
      targetPortReachable: (probeType === 'TCP_SYN_TARGET_PORT' || probeType === 'TCP_PORT_PROBE') ? probeSuccess : null,
      dnsResolved: (probeType === 'DNS_QUERY_PROBE' || probeType === 'DNS_RESOLVE') ? probeSuccess : null,
      tlsHandshakeSuccess: (probeType === 'TLS_HANDSHAKE_PROBE' || probeType === 'TLS_AUDIT') ? probeSuccess : null,
      httpStatusOk: (probeType === 'HTTP_HEAD_PROBE' || probeType === 'HTTP_PROBE') ? probeSuccess : null
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
        incidentType: 'TCP_SYN_TIMEOUT',
        destIp: normalizedTarget,
        destPort,
        gatewayReachable: revisionEvidence.gatewayReachable,
        targetPingReachable: revisionEvidence.targetPingReachable,
        altPortReachable: revisionEvidence.altPortReachable,
        targetPortReachable: revisionEvidence.targetPortReachable,
        dnsResolved: revisionEvidence.dnsResolved,
        tlsHandshakeSuccess: revisionEvidence.tlsHandshakeSuccess,
        httpStatusOk: revisionEvidence.httpStatusOk
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
      probeSuccess,
      latencyMs,
      rawOutput,
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
   */
  async runAutonomousInvestigation({ targetIp, targetPort = 443, maxSteps = 4 } = {}) {
    const netInfo = getPhysicalNetworkInfo();
    const gatewayIp = netInfo?.gatewayIp || '192.168.31.1';
    const rawCandidate = targetIp || gatewayIp;
    const target = isSafeNetworkTarget(rawCandidate) ? rawCandidate : gatewayIp;
    const port = parseInt(targetPort, 10) || 443;
    const boundedSteps = Math.min(Math.max(1, parseInt(maxSteps, 10) || 4), 10);

    const investigationId = `INV-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const startTime = Date.now();

    // 1. Initial Evaluation
    const dayBucket = new Date().toISOString().slice(0, 10);
    const dayBucketKey = `INC-${crypto.createHash('sha256').update(`${dayBucket}:${target.toLowerCase().trim()}:${port}:TCP_SYN_TIMEOUT`).digest('hex').substring(0, 16)}`;
    let currentIncident = this.activeIncidents.get(dayBucketKey);

    let currentEvaluation = currentIncident?.evaluation || reasoningEngine.evaluateIncident({
      incidentType: 'TCP_SYN_TIMEOUT',
      destIp: target,
      destPort: port
    });

    const initialTopHypothesis = currentEvaluation.topHypothesis;
    const steps = [];
    const executedProbeTypes = new Set();

    const probeCandidates = [
      { probeType: 'ICMP_PING_TARGET', label: 'ICMP Echo Target L3 Reachability' },
      { probeType: 'TCP_SYN_ALTERNATE_PORT', label: 'TCP SYN Alternate Port 80' },
      { probeType: 'DNS_QUERY_PROBE', label: 'RFC 1035 DNS Query' },
      { probeType: 'HTTP_HEAD_PROBE', label: 'HTTP/HTTPS Application Layer Probe' },
      { probeType: 'TLS_HANDSHAKE_PROBE', label: 'TLS 1.3 Cryptographic Handshake' },
      { probeType: 'ICMP_PING_GATEWAY', label: 'ICMP Echo Perimeter Gateway Probe' }
    ];

    for (let step = 1; step <= boundedSteps; step++) {
      const top = currentEvaluation.topHypothesis;
      const second = currentEvaluation.rankedHypotheses?.[1];
      const isConclusive = top && (top.confidence >= 80 || (second && (top.confidence - second.confidence) >= 40));

      if (isConclusive && step > 1) {
        break;
      }

      let selectedProbe = (currentEvaluation.distinguishingProbes || []).find(p => !executedProbeTypes.has(p.probeType));
      if (!selectedProbe) {
        selectedProbe = probeCandidates.find(p => !executedProbeTypes.has(p.probeType));
      }
      if (!selectedProbe) break;

      executedProbeTypes.add(selectedProbe.probeType);

      const probeResult = await this.executeDiagnosticProbe({
        probeType: selectedProbe.probeType,
        targetIp: target,
        targetPort: port
      });

      const priorTop = currentEvaluation.topHypothesis;
      currentEvaluation = probeResult.revisedEvaluation || currentEvaluation;
      const newTop = currentEvaluation.topHypothesis;

      steps.push({
        stepNumber: step,
        probeType: selectedProbe.probeType,
        probeSuccess: probeResult.probeSuccess,
        latencyMs: probeResult.latencyMs,
        rawOutput: probeResult.rawOutput,
        priorTopHypothesis: priorTop?.label || null,
        newTopHypothesis: newTop?.label || null,
        confidence: newTop?.confidence || 0,
        revisions: currentEvaluation.revisions || []
      });
    }

    const durationMs = Date.now() - startTime;
    const finalTop = currentEvaluation.topHypothesis;
    const finalSecond = currentEvaluation.rankedHypotheses?.[1];
    const conclusive = Boolean(finalTop && (finalTop.confidence >= 70 || (finalSecond && (finalTop.confidence - finalSecond.confidence) >= 30)));

    return {
      success: true,
      investigationId,
      target,
      targetPort: port,
      stepsExecuted: steps.length,
      maxSteps: boundedSteps,
      conclusive,
      durationMs,
      initialTopHypothesis: initialTopHypothesis?.label || null,
      finalTopHypothesis: finalTop,
      rankedHypotheses: currentEvaluation.rankedHypotheses || [],
      contradictoryEvidence: currentEvaluation.contradictoryEvidence || [],
      steps,
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
   * Get target baseline details
   */
  getTargetBaseline(target) {
    return this.baselineMetrics.get(target) || null;
  }

  /**
   * Evaluate host hardware diagnostics audit and produce plain-English synthesis with raw proof
   */
  evaluateHostHealth(hostAudit = {}) {
    const anomalies = hostAudit.anomalies || [];
    const overallStatus = hostAudit.overallStatus || 'HEALTHY';
    const hostName = hostAudit.host?.hostname || 'Host';

    if (overallStatus === 'COLLECTION_ERROR') {
      return {
        overallStatus: 'COLLECTION_ERROR',
        summary: `Host ${hostName} telemetry collection encountered operating system or permission errors.`,
        criticalIssuesCount: 0,
        warningIssuesCount: anomalies.length,
        recommendedAction: 'Verify PowerShell execution permissions and WMI/CIM service health.',
        plainEnglishReport: 'One or more subsystem telemetry queries failed, timed out, or encountered access denials on the host.'
      };
    }

    if (overallStatus === 'UNKNOWN') {
      return {
        overallStatus: 'UNKNOWN',
        summary: `Host ${hostName} telemetry unsupported on platform '${hostAudit.host?.platform || 'unknown'}'.`,
        criticalIssuesCount: 0,
        warningIssuesCount: 0,
        recommendedAction: 'Execute on supported Windows environment for full CIM/WMI telemetry.',
        plainEnglishReport: 'Hardware and subsystem telemetry sources are not supported on this platform.'
      };
    }

    if (anomalies.length === 0) {
      return {
        overallStatus,
        summary: `Host ${hostName} is operating with nominal parameters across all 4 foundational pillars.`,
        criticalIssuesCount: 0,
        warningIssuesCount: 0,
        recommendedAction: 'No remediation necessary.',
        plainEnglishReport: 'All hardware subsystems (CPU, memory, storage volumes, network interfaces, and drivers) are functioning within normal operational baselines.'
      };
    }

    const criticals = anomalies.filter(a => a.severity === 'CRITICAL');
    const warnings = anomalies.filter(a => a.severity === 'WARNING');
    const topAnomaly = criticals[0] || warnings[0];

    return {
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
      plainEnglishReport: `Primary operational finding: ${topAnomaly.plainEnglish} Technical evidence: ${topAnomaly.rawProof}. Staged remediation: ${topAnomaly.recipeId}.`
    };
  }
}

const defaultAIBrain = new AIBrain();

module.exports = {
  AIBrain,
  aiBrain: defaultAIBrain,
  isSafeNetworkTarget
};
