/**
 * EJII Enterprise Runtime Type Contract Validator
 * Enforces schema compliance against src/types/ejii-contracts.d.ts
 * Provides zero-overhead, production-grade schema validation.
 */

class TypeContractValidator {
  /**
   * Validate ITopologyNode
   */
  static validateTopologyNode(node) {
    if (!node || typeof node !== 'object') {
      return { valid: false, error: 'Node must be a non-null object' };
    }
    const requiredFields = ['id', 'name', 'hostname_or_ip', 'type', 'layer', 'layer_level', 'status'];
    for (const f of requiredFields) {
      if (node[f] === undefined || node[f] === null) {
        return { valid: false, error: `Missing required field: ${f}` };
      }
    }
    const validLayers = ['wan', 'edge', 'core', 'service', 'access', 'endpoint'];
    if (!validLayers.includes(node.layer)) {
      return { valid: false, error: `Invalid layer: ${node.layer}` };
    }
    if (typeof node.layer_level !== 'number' || node.layer_level < 1 || node.layer_level > 6) {
      return { valid: false, error: `Invalid layer_level: ${node.layer_level} (must be 1-6)` };
    }
    return { valid: true };
  }

  /**
   * Validate ITopologyEdge
   */
  static validateTopologyEdge(edge) {
    if (!edge || typeof edge !== 'object') {
      return { valid: false, error: 'Edge must be a non-null object' };
    }
    const required = ['id', 'source_id', 'target_id', 'link_type', 'status', 'bandwidth_mbps'];
    for (const f of required) {
      if (edge[f] === undefined || edge[f] === null) {
        return { valid: false, error: `Missing required field: ${f}` };
      }
    }
    return { valid: true };
  }

  /**
   * Validate ITimeSeriesPoint
   */
  static validateTimeSeriesPoint(point) {
    if (!point || typeof point !== 'object') {
      return { valid: false, error: 'Point must be a non-null object' };
    }
    if (typeof point.metric !== 'string' || !point.metric) {
      return { valid: false, error: 'Invalid or missing metric name' };
    }
    if (typeof point.value !== 'number' || isNaN(point.value)) {
      return { valid: false, error: 'Invalid or non-numeric value' };
    }
    return { valid: true };
  }

  /**
   * Validate IGitOpsDesiredState
   */
  static validateGitOpsDesiredState(state) {
    if (!state || typeof state !== 'object') {
      return { valid: false, error: 'Desired state must be an object' };
    }
    if (!state.baseline || typeof state.baseline !== 'object') {
      return { valid: false, error: 'Missing baseline object in desired state' };
    }
    if (!Array.isArray(state.baseline.requiredLayers)) {
      return { valid: false, error: 'baseline.requiredLayers must be an array' };
    }
    return { valid: true };
  }

  /**
   * Validate IPacketFrame
   */
  static validatePacketFrame(frame) {
    if (!frame || typeof frame !== 'object') {
      return { valid: false, error: 'Frame must be a non-null object' };
    }
    if (!frame.srcIp || !frame.dstIp) {
      return { valid: false, error: 'Frame missing srcIp or dstIp' };
    }
    return { valid: true };
  }
}

module.exports = { TypeContractValidator };
