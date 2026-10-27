/**
 * EJII Learning Center — Longest-Prefix Match Routing Explorer Lab
 * High-precision IPv4 Longest-Prefix Match (LPM) evaluation, AD tie-breaking, and explanation engine.
 * Mandate: Educational simulation only.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
  window.EJIILearning.Labs = window.EJIILearning.Labs || {};
}

(function() {
  function ipToInt(ipStr) {
    if (typeof ipStr !== 'string') return null;
    const parts = ipStr.trim().split('.');
    if (parts.length !== 4) return null;
    let num = 0n;
    for (let i = 0; i < 4; i++) {
      const p = Number(parts[i]);
      if (isNaN(p) || p < 0 || p > 255 || !Number.isInteger(p)) return null;
      num = (num << 8n) | BigInt(p);
    }
    return num;
  }

  function intToIp(intVal) {
    const p1 = Number((intVal >> 24n) & 0xFFn);
    const p2 = Number((intVal >> 16n) & 0xFFn);
    const p3 = Number((intVal >> 8n) & 0xFFn);
    const p4 = Number(intVal & 0xFFn);
    return `${p1}.${p2}.${p3}.${p4}`;
  }

  function prefixToMaskInt(prefix) {
    if (prefix === 0) return 0n;
    return (0xFFFFFFFFn << BigInt(32 - prefix)) & 0xFFFFFFFFn;
  }

  const DEFAULT_ROUTING_TABLE = [
    { prefix: '10.0.0.0/8', nextHop: '172.16.1.1', iface: 'Gi0/0', type: 'OSPF', ad: 110, metric: 20 },
    { prefix: '10.1.0.0/16', nextHop: '172.16.2.1', iface: 'Gi0/1', type: 'Static', ad: 1, metric: 0 },
    { prefix: '10.1.20.0/24', nextHop: 'Directly Connected', iface: 'Gi0/2', type: 'Connected', ad: 0, metric: 0 },
    { prefix: '10.1.20.128/25', nextHop: '172.16.3.1', iface: 'Gi0/3', type: 'eBGP', ad: 20, metric: 100 },
    { prefix: '172.16.0.0/16', nextHop: 'Directly Connected', iface: 'Gi0/4', type: 'Connected', ad: 0, metric: 0 },
    { prefix: '192.168.1.0/24', nextHop: '172.16.1.2', iface: 'Gi0/0', type: 'OSPF', ad: 110, metric: 10 },
    { prefix: '0.0.0.0/0', nextHop: '203.0.113.1', iface: 'Gi0/5', type: 'Static Default (Gateway of Last Resort)', ad: 1, metric: 0 }
  ];

  function evaluateLPM(destIpStr, table) {
    const ipInt = ipToInt(destIpStr);
    if (ipInt === null) {
      return { error: 'Invalid destination IPv4 address. Enter format like 10.1.20.150' };
    }

    const routingTable = table || DEFAULT_ROUTING_TABLE;
    const candidates = [];

    for (const route of routingTable) {
      const [netStr, lenStr] = route.prefix.split('/');
      const len = Number(lenStr);
      const netInt = ipToInt(netStr);
      const maskInt = prefixToMaskInt(len);

      if ((ipInt & maskInt) === (netInt & maskInt)) {
        candidates.push({
          ...route,
          prefixLen: len,
          matchedNetwork: intToIp(ipInt & maskInt)
        });
      }
    }

    if (candidates.length === 0) {
      return {
        destIp: destIpStr,
        bestRoute: null,
        candidates: [],
        explanation: 'Destination Host Unreachable: No matching route found in the routing table, and no default route (0.0.0.0/0) is configured.'
      };
    }

    // Sort according to router decision tree:
    // 1. Longest Prefix Length (DESC)
    // 2. Lowest Administrative Distance (ASC)
    // 3. Lowest Metric (ASC)
    candidates.sort((a, b) => {
      if (b.prefixLen !== a.prefixLen) return b.prefixLen - a.prefixLen;
      if (a.ad !== b.ad) return a.ad - b.ad;
      return a.metric - b.metric;
    });

    const bestRoute = candidates[0];

    // Build explanatory breakdown
    let explanation = `Best route selected: ${bestRoute.prefix} via ${bestRoute.iface} (Next Hop: ${bestRoute.nextHop}).\n\n`;
    if (candidates.length > 1) {
      explanation += `Matched ${candidates.length} candidate route(s). Longest-Prefix Match (LPM) rule dictates that the route with the most specific subnet mask (longest bit length) wins, regardless of Administrative Distance.\n`;
      if (bestRoute.prefixLen > candidates[1].prefixLen) {
        explanation += `• Winner prefix length /${bestRoute.prefixLen} is more specific than candidate /${candidates[1].prefixLen} (${candidates[1].prefix}).`;
      } else if (bestRoute.ad < candidates[1].ad) {
        explanation += `• Equal prefix length /${bestRoute.prefixLen}: Winner chosen by lower Administrative Distance (${bestRoute.ad} vs ${candidates[1].ad}).`;
      } else {
        explanation += `• Equal prefix and AD: Winner chosen by lower Metric (${bestRoute.metric} vs ${candidates[1].metric}).`;
      }
    } else {
      explanation += `Only 1 route matched this destination address.`;
    }

    return {
      destIp: destIpStr,
      bestRoute,
      candidates,
      explanation
    };
  }

  function renderRoutingExplorerLab(containerEl) {
    if (!containerEl) return;

    let targetIp = '10.1.20.150';

    function renderUI() {
      const result = evaluateLPM(targetIp, DEFAULT_ROUTING_TABLE);

      containerEl.innerHTML = `
        <div class="ejii-learning-lab-header">
          <div>
            <span class="ejii-learning-badge ejii-learning-badge--accent">SIMULATED LAB</span>
            <span class="ejii-learning-badge" style="margin-left:8px;">IP Routing & FIB</span>
            <h2 style="margin: 8px 0 4px; font-size: 20px;">Longest-Prefix Match (LPM) Routing Explorer</h2>
            <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">
              Observe how Layer 3 routers evaluate candidate routes, apply LPM, and resolve next-hop interfaces.
            </p>
          </div>
        </div>

        <!-- Destination Address Input & Quick Drill Buttons -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-top: 16px;">
          <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
            <div style="flex: 1; min-width: 220px;">
              <label style="display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Destination IPv4 Address:</label>
              <input type="text" id="inputDestIp" class="ejii-learning-input" value="${targetIp}" placeholder="e.g. 10.1.20.150" style="font-family: monospace; font-size: 14px;">
            </div>
            <div style="display: flex; gap: 8px; align-self: flex-end; flex-wrap: wrap;">
              <button id="btnLookup" class="ejii-learning-btn ejii-learning-btn--primary">Evaluate Route</button>
            </div>
          </div>

          <div style="margin-top: 12px; font-size: 12px; color: var(--text-secondary);">
            <span>Quick Test Scenarios: </span>
            <button class="ejii-learning-btn ejii-learning-btn--secondary" style="padding: 2px 8px; font-size: 11px; margin: 2px;" data-ip="10.1.20.150">10.1.20.150 (LPM Trap)</button>
            <button class="ejii-learning-btn ejii-learning-btn--secondary" style="padding: 2px 8px; font-size: 11px; margin: 2px;" data-ip="10.1.20.50">10.1.20.50 (Direct /24)</button>
            <button class="ejii-learning-btn ejii-learning-btn--secondary" style="padding: 2px 8px; font-size: 11px; margin: 2px;" data-ip="10.1.50.1">10.1.50.1 (Static /16)</button>
            <button class="ejii-learning-btn ejii-learning-btn--secondary" style="padding: 2px 8px; font-size: 11px; margin: 2px;" data-ip="10.99.1.1">10.99.1.1 (OSPF /8)</button>
            <button class="ejii-learning-btn ejii-learning-btn--secondary" style="padding: 2px 8px; font-size: 11px; margin: 2px;" data-ip="8.8.8.8">8.8.8.8 (Default /0)</button>
          </div>
        </div>

        ${result.error ? `
          <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 12px; margin-top: 16px; color: #fca5a5;">
            ${result.error}
          </div>
        ` : `
          <!-- Decision Summary Card -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-left: 4px solid #10b981; border-radius: 8px; padding: 16px; margin-top: 16px;">
            <div style="font-weight: 600; font-size: 15px; color: #10b981; margin-bottom: 4px;">
              &#10003; WINNING ROUTE: ${result.bestRoute ? result.bestRoute.prefix : 'None'}
            </div>
            <div style="font-size: 13px; color: var(--text-primary); margin-bottom: 8px;">
              Outgoing Interface: <strong>${result.bestRoute ? result.bestRoute.iface : 'N/A'}</strong> &bull; Next Hop: <strong>${result.bestRoute ? result.bestRoute.nextHop : 'N/A'}</strong> &bull; Protocol: <strong>${result.bestRoute ? result.bestRoute.type : 'N/A'} (AD: ${result.bestRoute ? result.bestRoute.ad : 'N/A'})</strong>
            </div>
            <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5; white-space: pre-line;">
              ${result.explanation}
            </div>
          </div>

          <!-- Candidates & Routing Table Display -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-top: 16px;">
            <div style="font-weight: 600; font-size: 14px; margin-bottom: 12px; color: var(--text-primary);">
              ROUTER RIB (ROUTING INFORMATION BASE) EVALUATION
            </div>
            <div style="overflow-x: auto;">
              <table class="ejii-learning-table" style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <thead>
                  <tr style="border-bottom: 1px solid var(--border-color); text-align: left;">
                    <th style="padding: 8px;">Prefix</th>
                    <th style="padding: 8px;">Mask Bits</th>
                    <th style="padding: 8px;">Protocol (AD)</th>
                    <th style="padding: 8px;">Metric</th>
                    <th style="padding: 8px;">Next Hop</th>
                    <th style="padding: 8px;">Interface</th>
                    <th style="padding: 8px;">LPM Match Status</th>
                  </tr>
                </thead>
                <tbody>
                  ${DEFAULT_ROUTING_TABLE.map(r => {
                    const candidate = result.candidates.find(c => c.prefix === r.prefix);
                    const isWinner = result.bestRoute && result.bestRoute.prefix === r.prefix;
                    const isMatch = Boolean(candidate);
                    const [_, len] = r.prefix.split('/');

                    let rowBg = 'transparent';
                    if (isWinner) rowBg = 'rgba(16, 185, 129, 0.12)';
                    else if (isMatch) rowBg = 'rgba(59, 130, 246, 0.08)';

                    return `
                      <tr style="background: ${rowBg}; border-bottom: 1px solid rgba(255,255,255,0.05); font-family: monospace;">
                        <td style="padding: 8px; font-weight: 600;">${r.prefix}</td>
                        <td style="padding: 8px;">/${len}</td>
                        <td style="padding: 8px;">${r.type} (${r.ad})</td>
                        <td style="padding: 8px;">${r.metric}</td>
                        <td style="padding: 8px;">${r.nextHop}</td>
                        <td style="padding: 8px;">${r.iface}</td>
                        <td style="padding: 8px;">
                          ${isWinner ? `
                            <span class="ejii-learning-badge ejii-learning-badge--completed" style="font-size: 11px;">WINNER (LPM /${len})</span>
                          ` : (isMatch ? `
                            <span class="ejii-learning-badge ejii-learning-badge--accent" style="font-size: 11px;">MATCH (/${len})</span>
                          ` : `
                            <span style="color: var(--text-secondary); font-size: 11px;">NO MATCH</span>
                          `)}
                        </td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          </div>
        `}
      `;

      // Event handlers
      const inputEl = containerEl.querySelector('#inputDestIp');
      const btnLookup = containerEl.querySelector('#btnLookup');

      if (btnLookup && inputEl) {
        btnLookup.addEventListener('click', () => {
          targetIp = inputEl.value.trim();
          renderUI();
        });
        inputEl.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') {
            targetIp = inputEl.value.trim();
            renderUI();
          }
        });
      }

      containerEl.querySelectorAll('button[data-ip]').forEach(btn => {
        btn.addEventListener('click', () => {
          targetIp = btn.getAttribute('data-ip');
          renderUI();
        });
      });
    }

    renderUI();
  }

  if (typeof window !== 'undefined' && window.EJIILearning) {
    window.EJIILearning.Labs['net-routing-explorer'] = {
      render: renderRoutingExplorerLab,
      evaluateLPM,
      DEFAULT_ROUTING_TABLE
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      renderRoutingExplorerLab,
      evaluateLPM,
      DEFAULT_ROUTING_TABLE
    };
  }
})();
