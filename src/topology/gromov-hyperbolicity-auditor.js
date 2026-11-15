/**
 * EJII Gromov 4-Point Delta-Hyperbolicity Auditor
 *
 * Evaluates the Gromov 4-point delta-hyperbolicity condition over network distance matrices
 * to quantify negative curvature, metric tree-likeness, and routing bottleneck congestion.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

class GromovHyperbolicityAuditor {
  constructor() {
    this.auditsPerformed = 0;
    this.maxDeltaObserved = 0;
  }

  /**
   * Evaluates the Gromov 4-point delta-hyperbolicity condition:
   * delta(x, y, z, w) = 0.5 * (L1 - L2) where L1 >= L2 >= L3 are sorted values of:
   * [d(x,y)+d(z,w), d(x,z)+d(y,w), d(x,w)+d(y,z)]
   */
  auditHyperbolicity(distanceMatrix, nodeCount) {
    this.auditsPerformed++;
    const reportId = `gromov_${Date.now()}_${Math.floor(Math.random() * 10000)}`;

    if (nodeCount < 4) {
      return {
        reportId,
        nodeCount,
        maxDelta: 0.0,
        avgDelta: 0.0,
        sampledQuadruplets: 0,
        isHyperbolic: true,
        curvatureClassification: 'tree-like',
        timestamp: Date.now()
      };
    }

    const getDist = (i, j) => {
      if (distanceMatrix instanceof Float64Array) {
        return distanceMatrix[i * nodeCount + j];
      }
      return distanceMatrix[i][j];
    };

    let maxDelta = 0.0;
    let sumDelta = 0.0;
    let sampledQuadruplets = 0;

    // For graphs with <= 18 nodes, compute all quadruplets exhaustively; otherwise sample up to 1000
    if (nodeCount <= 18) {
      for (let x = 0; x < nodeCount; x++) {
        for (let y = x + 1; y < nodeCount; y++) {
          for (let z = y + 1; z < nodeCount; z++) {
            for (let w = z + 1; w < nodeCount; w++) {
              const s1 = getDist(x, y) + getDist(z, w);
              const s2 = getDist(x, z) + getDist(y, w);
              const s3 = getDist(x, w) + getDist(y, z);

              const sorted = [s1, s2, s3].sort((a, b) => b - a);
              const delta = 0.5 * (sorted[0] - sorted[1]);

              if (delta > maxDelta) {
                maxDelta = delta;
              }
              sumDelta += delta;
              sampledQuadruplets++;
            }
          }
        }
      }
    } else {
      const maxSamples = 1000;
      for (let s = 0; s < maxSamples; s++) {
        const indices = new Set();
        while (indices.size < 4) {
          indices.add(Math.floor(Math.random() * nodeCount));
        }
        const [x, y, z, w] = Array.from(indices);

        const s1 = getDist(x, y) + getDist(z, w);
        const s2 = getDist(x, z) + getDist(y, w);
        const s3 = getDist(x, w) + getDist(y, z);

        const sorted = [s1, s2, s3].sort((a, b) => b - a);
        const delta = 0.5 * (sorted[0] - sorted[1]);

        if (delta > maxDelta) {
          maxDelta = delta;
        }
        sumDelta += delta;
        sampledQuadruplets++;
      }
    }

    const avgDelta = sampledQuadruplets > 0 ? sumDelta / sampledQuadruplets : 0.0;

    if (maxDelta > this.maxDeltaObserved) {
      this.maxDeltaObserved = maxDelta;
    }

    let curvatureClassification;
    if (maxDelta <= 0.05) {
      curvatureClassification = 'tree-like';
    } else if (maxDelta <= 1.0) {
      curvatureClassification = 'moderately-hyperbolic';
    } else if (maxDelta <= 2.5) {
      curvatureClassification = 'flat-euclidean';
    } else {
      curvatureClassification = 'spherical';
    }

    return {
      reportId,
      nodeCount,
      maxDelta: Number(maxDelta.toFixed(4)),
      avgDelta: Number(avgDelta.toFixed(4)),
      sampledQuadruplets,
      isHyperbolic: maxDelta <= 1.5,
      curvatureClassification,
      timestamp: Date.now()
    };
  }

  getMetrics() {
    return {
      auditsPerformed: this.auditsPerformed,
      maxDeltaObserved: Number(this.maxDeltaObserved.toFixed(4))
    };
  }
}

const gromovHyperbolicityAuditor = new GromovHyperbolicityAuditor();

module.exports = {
  GromovHyperbolicityAuditor,
  gromovHyperbolicityAuditor
};
