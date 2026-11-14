/**
 * EJII Track 4: Equipotential Diffusion Shader & Continuous Scalar Field Renderer
 *
 * Implements real-time 2D scalar potential field computation and heat gradient contour visualization
 * for the Continuous Laplacian Heat Diffusion vector u(t):
 *
 *   u(x, y) = \sum_{k=1}^K u_k \cdot \exp\left(-\frac{(x - x_k)^2 + (y - y_k)^2}{2 \sigma_k^2}\right)
 *
 * Color Ramp: Emerald (Low / Healthy) -> Amber (Elevated / Congestion) -> Crimson (Hotspot / Root Cause)
 * Universal Module Definition: runs in Browser (`window`) and Node.js (`module.exports`).
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    const exported = factory();
    root.EquipotentialContourShader = exported;
    root.evaluateScalarPotential = exported.evaluateScalarPotential;
    root.computeEquipotentialField = exported.computeEquipotentialField;
    root.renderEquipotentialCanvas = exported.renderEquipotentialCanvas;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Evaluate continuous potential u(x, y) at a single coordinate given K potential sources
   */
  function evaluateScalarPotential(x, y, sources = [], defaultSigma = 60.0) {
    if (!Array.isArray(sources) || sources.length === 0) return 0.0;
    let potential = 0.0;

    for (let k = 0; k < sources.length; k++) {
      const src = sources[k];
      const uk = Number(src.potential ?? src.u ?? src.weight ?? 1.0);
      const xk = Number(src.x ?? 0);
      const yk = Number(src.y ?? 0);
      const sigma = Number(src.sigma ?? defaultSigma);
      const twoSigmaSq = 2.0 * sigma * sigma;

      const dx = x - xk;
      const dy = y - yk;
      const distSq = dx * dx + dy * dy;

      potential += uk * Math.exp(-distSq / twoSigmaSq);
    }

    return potential;
  }

  /**
   * Discretize potential field onto a computational grid
   */
  function computeEquipotentialField(sources = [], width = 800, height = 600, resolution = 10, defaultSigma = 60.0) {
    const step = Math.max(2, parseInt(resolution, 10) || 10);
    const cols = Math.ceil(width / step);
    const rows = Math.ceil(height / step);
    const totalCells = cols * rows;
    const grid = new Float32Array(totalCells);

    let maxPotential = 0.0;
    let minPotential = Infinity;

    let idx = 0;
    for (let r = 0; r < rows; r++) {
      const y = r * step;
      for (let c = 0; c < cols; c++) {
        const x = c * step;
        const u = evaluateScalarPotential(x, y, sources, defaultSigma);
        grid[idx++] = u;
        if (u > maxPotential) maxPotential = u;
        if (u < minPotential) minPotential = u;
      }
    }

    if (minPotential === Infinity) minPotential = 0.0;

    return {
      width,
      height,
      resolution: step,
      cols,
      rows,
      grid,
      minPotential: Number(minPotential.toFixed(4)),
      maxPotential: Number(maxPotential.toFixed(4)),
      sourceCount: sources.length
    };
  }

  /**
   * Continuous color ramp: Emerald -> Amber -> Crimson
   * Returns [r, g, b] array
   */
  function getHeatRgb(normVal) {
    const t = Math.max(0.0, Math.min(1.0, normVal));
    let r, g, b;

    if (t < 0.4) {
      // Emerald (16, 185, 129) -> Amber (245, 158, 11)
      const factor = t / 0.4;
      r = Math.round(16 + factor * (245 - 16));
      g = Math.round(185 + factor * (158 - 185));
      b = Math.round(129 + factor * (11 - 129));
    } else {
      // Amber (245, 158, 11) -> Crimson (239, 68, 68)
      const factor = (t - 0.4) / 0.6;
      r = Math.round(245 + factor * (239 - 245));
      g = Math.round(158 + factor * (68 - 158));
      b = Math.round(11 + factor * (68 - 11));
    }

    return [r, g, b];
  }

  /**
   * Render continuous equipotential gradient & contour rings to an HTML5 Canvas
   */
  function renderEquipotentialCanvas(canvas, sources = [], options = {}) {
    if (!canvas || typeof canvas.getContext !== 'function') return null;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;

    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);

    if (!Array.isArray(sources) || sources.length === 0) {
      return { rendered: false, sourceCount: 0 };
    }

    const defaultSigma = options.sigma || 80.0;
    const contourLevels = options.contourLevels || [0.25, 0.50, 0.75, 0.90];

    // 1. Draw smooth additive radial heat blooms
    ctx.save();
    ctx.globalCompositeOperation = 'screen';

    for (const src of sources) {
      const u = Math.max(0.01, Math.min(1.0, Number(src.potential ?? src.u ?? 0.5)));
      const x = Number(src.x || 0);
      const y = Number(src.y || 0);
      const sigma = Number(src.sigma || defaultSigma);
      const radius = sigma * 2.5;

      const [r, g, b] = getHeatRgb(u);
      const grad = ctx.createRadialGradient(x, y, 0, x, y, radius);
      grad.addColorStop(0.0, `rgba(${r}, ${g}, ${b}, ${0.55 * u})`);
      grad.addColorStop(0.4, `rgba(${r}, ${g}, ${b}, ${0.25 * u})`);
      grad.addColorStop(0.8, `rgba(${r}, ${g}, ${b}, ${0.08 * u})`);
      grad.addColorStop(1.0, `rgba(${r}, ${g}, ${b}, 0.0)`);

      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();

    // 2. Draw crisp equipotential contour rings around hotspots
    ctx.save();
    for (const src of sources) {
      const u = Math.max(0.01, Math.min(1.0, Number(src.potential ?? src.u ?? 0.5)));
      if (u < 0.20) continue;
      const x = Number(src.x || 0);
      const y = Number(src.y || 0);
      const sigma = Number(src.sigma || defaultSigma);

      for (const level of contourLevels) {
        if (u >= level) {
          // Solve for contour radius: level = u * exp(-r^2 / 2sigma^2)
          // r = sigma * sqrt(2 * ln(u / level))
          const ratio = u / level;
          if (ratio > 1.0) {
            const rContour = sigma * Math.sqrt(2 * Math.log(ratio));
            const [r, g, b] = getHeatRgb(level);
            ctx.beginPath();
            ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, 0.75)`;
            ctx.lineWidth = 1.2;
            ctx.setLineDash([4, 4]);
            ctx.arc(x, y, rContour, 0, Math.PI * 2);
            ctx.stroke();
          }
        }
      }
    }
    ctx.restore();

    return {
      rendered: true,
      sourceCount: sources.length,
      width,
      height
    };
  }

  return {
    evaluateScalarPotential,
    computeEquipotentialField,
    getHeatRgb,
    renderEquipotentialCanvas
  };
});
