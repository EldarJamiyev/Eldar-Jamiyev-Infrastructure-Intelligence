/**
 * EJII Enterprise Architectural TypeScript Contracts & Interface Declarations
 * Authoritative type definitions across Language & Concurrency, Storage, CNCF Observability,
 * Heterogeneous OS Parity, and Autonomous GitOps Operations.
 */

export type EvidenceClassification = 'Observed' | 'Configured' | 'Management' | 'OS' | 'Inferred' | 'Unknown';
export type NodeStatus = 'healthy' | 'warning' | 'critical' | 'offline';
export type LinkStatus = 'up' | 'degraded' | 'down';
export type LinkType = 'fiber' | 'ethernet' | 'wireless' | 'virtual';

export interface ITopologyNodeMetadata {
  role?: string;
  vendor?: string;
  model?: string;
  discovery?: string;
  evidenceClassification?: EvidenceClassification;
  evidenceSource?: EvidenceClassification;
  ports?: number[];
  vlan?: number;
  hostsCount?: number;
  os?: string;
  [key: string]: unknown;
}

export interface ITopologyNode {
  id: string;
  name: string;
  hostname_or_ip: string;
  mac_address: string | null;
  type: string;
  layer: 'wan' | 'edge' | 'core' | 'service' | 'access' | 'endpoint';
  layer_level: 1 | 2 | 3 | 4 | 5 | 6;
  parent_id: string | null;
  status: NodeStatus;
  last_checked: string;
  last_latency_ms: number;
  vendor: string | null;
  if_name: string | null;
  x: number;
  y: number;
  metadata: ITopologyNodeMetadata | string;
  evidenceClassification?: EvidenceClassification;
  evidenceSource?: EvidenceClassification;
  last_seen?: string;
  environment_cidr?: string;
  is_stale?: number | boolean;
}

export interface ITopologyEdgeMetadata {
  role?: string;
  [key: string]: unknown;
}

export interface ITopologyEdge {
  id: string;
  source_id: string;
  target_id: string;
  link_type: LinkType;
  status: LinkStatus;
  bandwidth_mbps: number;
  utilization_pct: number;
  latency_ms: number;
  packet_rate: number;
  metadata: ITopologyEdgeMetadata | string;
  evidenceSource?: EvidenceClassification;
}

export interface ITopologyLayer {
  level: 1 | 2 | 3 | 4 | 5 | 6;
  id: string;
  name: string;
  description: string;
}

export interface ITopologyGraph {
  nodes: ITopologyNode[];
  edges: ITopologyEdge[];
  layers: ITopologyLayer[];
  timestamp: string;
}

export interface IPhysicalNetworkInfo {
  localIp: string;
  defaultGateway: string;
  subnetMask: string;
  subnetCidr: string;
  macAddress: string;
  adapterName: string;
  hardwareDescription?: string;
  gatewayMac: string;
  gatewayVendor: string;
  dnsServers: string[];
  primaryDnsIp: string;
  secondaryDnsIp?: string;
  arpNeighbors: Array<{ ip: string; mac: string; vendor: string }>;
  arpNeighborsCount: number;
  locationSignature: string;
  networkSignatureHash: string;
  isVirtual: boolean;
  detectedAt: string;
}

export interface ITcpFlags {
  syn: boolean;
  ack: boolean;
  fin: boolean;
  rst: boolean;
  psh: boolean;
  urg?: boolean;
}

export interface IPacketFrame {
  timestamp: string;
  srcMac?: string;
  dstMac?: string;
  vlanId?: number | null;
  etherType?: string;
  srcIp: string;
  dstIp: string;
  protocol?: string;
  payloadLength?: number;
  tcp?: {
    srcPort: number;
    dstPort: number;
    seq: number;
    ack: number;
    flags: ITcpFlags;
    windowSize: number;
    dataOffset: number;
    payloadLength?: number;
  };
  udp?: {
    srcPort: number;
    dstPort: number;
    length: number;
  };
  icmp?: {
    type: number;
    code: number;
  };
  bpfMatched?: boolean;
  tcpDeltaStatus?: string;
  isKeepAlive?: boolean;
  isKeepAliveAck?: boolean;
  isRetransmission?: boolean;
}

export interface ITimeSeriesPoint {
  timestamp: number | string;
  metric: string;
  value: number;
  tags?: Record<string, string>;
  fields?: Record<string, number | string | boolean>;
}

export interface ITimeSeriesBatch {
  points: ITimeSeriesPoint[];
  flushedAt: number;
  driver: 'sqlite' | 'timescaledb' | 'clickhouse' | 'influxdb';
}

export interface IObservabilityMetric {
  name: string;
  help: string;
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
  values: Array<{
    labels: Record<string, string>;
    value: number;
    timestamp?: number;
  }>;
}

export interface IOtelSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  kind: 'INTERNAL' | 'SERVER' | 'CLIENT' | 'PRODUCER' | 'CONSUMER';
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: Record<string, string | number | boolean>;
  status: { code: 'UNSET' | 'OK' | 'ERROR'; message?: string };
}

export interface IGitOpsDesiredState {
  version: string;
  schemaVersion: string;
  baseline: {
    minimumNodesCount: number;
    requiredLayers: number[];
    enforceGatewayMacOui: boolean;
    allowedSubnets: string[];
    security: {
      prohibitedOpenPortsOnHost: number[];
      maxToleratedLatencyMs: number;
      maxToleratedLossPct: number;
    };
    topologyInvariants: Array<{
      nodeId: string;
      layerLevel: number;
      required: boolean;
    }>;
  };
}

export interface IGitOpsDriftItem {
  id: string;
  category: 'TOPOLOGY' | 'SECURITY' | 'PERFORMANCE' | 'NETWORK';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  expected: unknown;
  actual: unknown;
  driftHash: string;
  autoReconcilable: boolean;
}

export interface IGitOpsDriftReport {
  timestamp: string;
  driftDetected: boolean;
  driftCount: number;
  stateHash: string;
  driftItems: IGitOpsDriftItem[];
  previewToken?: string;
}

export interface IProcMemInfo {
  MemTotalKB: number;
  MemFreeKB: number;
  MemAvailableKB: number;
  BuffersKB: number;
  CachedKB: number;
  SwapTotalKB: number;
  SwapFreeKB: number;
  ShmemKB: number;
  SReclaimableKB: number;
}

export interface IProcNetDevInterface {
  interface: string;
  rxBytes: number;
  rxPackets: number;
  rxErrors: number;
  rxDrop: number;
  txBytes: number;
  txPackets: number;
  txErrors: number;
  txDrop: number;
}

export interface ILinuxParityMetrics {
  osFamily: 'linux' | 'windows-simulation';
  kernelVersion: string;
  uptimeSeconds: number;
  memInfo: IProcMemInfo;
  netDev: IProcNetDevInterface[];
  arpEntries: Array<{ ip: string; mac: string; dev: string }>;
  openSockets: {
    tcpEstablished: number;
    tcpListen: number;
    tcpTimeWait: number;
    udpTotal: number;
  };
  systemdUnits?: Array<{ name: string; state: string; sub: string }>;
}

export interface IWorkerPoolTelemetry {
  workerCount: number;
  activeJobs: number;
  completedJobs: number;
  failedJobs: number;
  queueDepth: number;
  eventLoopDelayAvgMs: number;
  eventLoopDelayMaxMs: number;
  eventLoopDelayP99Ms: number;
  poolStatus: 'ready' | 'busy' | 'draining' | 'terminated';
}

export interface ISymbolicProofRule {
  axiom: string;
  ruleName: string;
  head: string;
  datalog: string;
  rfc: string;
  action: 'BOOST' | 'CONTRADICT' | 'ELIMINATE';
  weight: number;
  logWeight: number;
  contradicts?: string[];
  rationale: string;
  satisfied: boolean;
}

export interface IActiveInferenceProbeScore {
  probeType: string;
  name: string;
  expectedFreeEnergy_G: number;
  epistemicValueBits: number;
  pragmaticValueScore: number;
  informationGain: string;
}

export interface IActiveInferenceMetrics {
  variationalFreeEnergy: number;
  complexityTerm: number;
  accuracyTerm: number;
  shannonEntropyBits: number;
  activeHypothesesCount: number;
  expectedFreeEnergyByProbe: IActiveInferenceProbeScore[];
  optimalProbe: IActiveInferenceProbeScore | null;
}

export interface IWorldModelHorizon {
  step: 't_0' | 't_10s' | 't_1m' | 't_5m' | 't_10m';
  timeLabel: string;
  failureRiskPct: number;
  entropyBits: number;
  recoveryProbability: number;
  state: string;
}

export interface IWorldModelRollout {
  action: string;
  rolloutHorizons: IWorldModelHorizon[];
  mctsStats: {
    iterations: number;
    rolloutsCompleted: number;
    treeDepth: number;
    uctExplorationConstant: number;
    convergenceConfidence: number;
  };
  trajectoryOutcome: string;
}

export interface ICausalDirectedEdge {
  from: string;
  to: string;
  causalWeight: number;
  lagSteps: number;
  pValue: number;
}

export interface ICausalDiscoveryGraph {
  variables: string[];
  adjacencyMatrix: number[][];
  acyclicityTraceMetric: number;
  isDag: boolean;
  directedEdges: ICausalDirectedEdge[];
  rootCauseCandidate: string;
  discoveryAlgorithm: string;
  timestamp: string;
}

export interface IPacketFactoryResult {
  success: boolean;
  tool: string;
  rfcCompliance: string;
  frameSpecification: Record<string, unknown>;
  hexDump: string;
  byteLength: number;
  checksumVerified: boolean;
  timestamp: string;
}

export interface IHardwareAnchorStatus {
  hardwareBound: boolean;
  algorithm: string;
  anchorHash: string;
  platform: string;
  hostname: string;
  platformVerified: boolean;
  sealedAt: string;
}

export type EpistemicState = 'OBSERVED' | 'INFERRED' | 'RECOMMENDED' | 'VERIFIED';
export type LivenessState = 'CURRENTLY_OBSERVED' | 'RECENTLY_OBSERVED' | 'HISTORICAL' | 'UNREACHABLE_UNDER_CURRENT_TEST' | 'UNKNOWN';
export type ScoreSemantics = 'PHYSICAL_TRUTH' | 'PROBABILITY_MARGIN' | 'BAYESIAN_POSTERIOR' | 'CONFIDENCE_SCORE' | 'FORMAL_VERIFICATION';

export interface IEpistemicMetadata {
  epistemicState: EpistemicState;
  sourceAdapter: string;
  observedAt?: string;
  inferenceMethod?: string;
  scoreSemantics: ScoreSemantics;
  verificationCriterion?: string;
  verified: boolean;
  livenessState?: LivenessState;
}

export interface ISTLFormulaResult {
  formulaId: string;
  formulaName: string;
  specification: string;
  robustnessDegree: number;
  satisfied: boolean;
  evaluationWindowSeconds: number;
  evaluatedAt: string;
  sampleCount: number;
}

export interface ISTLMonitorReport {
  timestamp: string;
  slidingWindowSeconds: number;
  overallSatisfaction: boolean;
  minRobustness: number;
  formulas: ISTLFormulaResult[];
}

export interface IGNNNodeEmbedding {
  nodeId: string;
  embeddingVector: number[];
  structuralCriticality: number;
  blastRadiusWeight: number;
  hopDistances: Record<string, number>;
  layerIndex: number;
}

export interface IDSRLVaultReport {
  actionName: string;
  targetAsset: string;
  approved: boolean;
  rejectionReason?: string;
  safetyChecklist: {
    scriptRegistryVerified: boolean;
    symbolicPreconditionProven: boolean;
    hostCapacityHeadroomOk: boolean;
    sessionDisconnectGuardOk: boolean;
    postActionVerificationPlan: boolean;
  };
  projectedReward: number;
  policyConfidence: number;
  evaluatedAt: string;
}

export type EvidenceClass = 'Observed' | 'OS' | 'Management' | 'Inferred' | 'Configured' | 'Unknown';
export type CollectionOutcome = 'SUCCESS' | 'PARTIAL' | 'TIMEOUT' | 'PERMISSION_DENIED' | 'UNSUPPORTED_PLATFORM' | 'COLLECTION_ERROR' | 'PROVISIONAL_WARM_STATE';

export interface EvidenceRecord<T = unknown> {
  evidenceId: string;
  metricKey: string;
  value: T | null; // Must be null when outcome !== 'SUCCESS'
  unit?: string;
  evidenceClass: EvidenceClass;
  collectorId: string; // e.g., 'host-diagnostics:collectStoragePillar', 'wire-diagnostics:tcpSynProbe'
  collectionMethod: string; // e.g., 'PowerShell:Get-CimInstance', 'Node:tls.connect', 'npcap:raw_socket'
  timestampIso: string;
  freshnessMs: number;
  targetIdentity: {
    host?: string;
    pinnedIp?: string | null;
    pid?: number | null;
    processName?: string | null;
    interfaceId?: string | null;
  };
  outcome: CollectionOutcome;
  errorDetails?: string | null;
  measurementUncertainty?: number | null; // [0.0, 1.0]
  isProvisional?: boolean;
  isAuthoritative: boolean; // False for warm snapshots, defaults, or unverified inputs
  supportsHypotheses: string[];
  contradictsHypotheses: string[];
}

export type HypothesisStatus = 'SUPPORTED' | 'CONTRADICTED' | 'INSUFFICIENT_EVIDENCE' | 'PLAUSIBLE_UNVERIFIED';

export interface HypothesisEvaluation {
  hypothesisId: string;
  title: string;
  status: HypothesisStatus;
  priorProbability: number; // Explicit domain prior; never silently fabricated
  rawLikelihood: number | null; // 0.0 is preserved strictly for contradicted hypotheses
  normalizedPosterior: number; // Mathematical Bayes posterior in [0.0, 1.0]
  normalizedSharePct?: number; // Integer [0, 100]
  displayPercentage: number; // Hare-Niemeyer integer formatting only; explicitly labeled as normalized share
  calibratedConfidence: number | null; // Empirically calibrated probability or null if uncalibrated heuristic
  confidenceType: 'EMPIRICALLY_CALIBRATED' | 'RULE_HEURISTIC' | 'INSUFFICIENT_DATA';
  supportingEvidenceIds: string[];
  contradictingEvidenceIds: string[];
  missingDistinguishingEvidence?: string[]; // Next measurements required to disambiguate
  missingDistinguishingProbes?: string[];
  symbolicViolations?: string[]; // Explicit Horn-clause / constraint violations
  symbolicProofTrace?: string[];
}

export interface ModelOrchestrationResult {
  invocationDecision: 'INVOKED' | 'BYPASSED_HIGH_EVIDENCE_CONFIDENCE' | 'BLOCKED_PRIVACY_POLICY' | 'PROVIDER_UNAVAILABLE' | 'DETERMINISTIC_CONFIG_DEFAULT';
  providerId: 'OLLAMA' | 'OPENAI' | 'ANTHROPIC' | 'NONE'; // Normalize 'local_ollama' -> 'OLLAMA'
  privacyGate: {
    policyId: string; // e.g., 'POL-01-LOCAL_ONLY'
    permitted: boolean;
    redactionApplied: boolean;
    redactedFields: string[];
  };
  transportState: {
    attempted: boolean;
    connected: boolean;
    httpStatus?: number | null;
    latencyMs?: number | null;
    transportError?: string | null; // e.g., 'ECONNREFUSED 127.0.0.1:11434'
  };
  inferenceState: {
    liveResponse: boolean; // True ONLY if HTTP request succeeded, payload parsed, and schema validated
    synthesisMode: 'LIVE_NEURAL_INFERENCE' | 'DETERMINISTIC_TEMPLATE_FALLBACK';
    schemaValid: boolean;
    incorporatedIntoDiagnosis: boolean;
  };
  outputPayload: Record<string, unknown> | null;
}

export type OrchestrationEnvelope = ModelOrchestrationResult;


