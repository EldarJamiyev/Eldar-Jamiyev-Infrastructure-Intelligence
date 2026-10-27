/**
 * EJII Learning Center — VLAN Segmentation & 802.1Q Trunking Lab
 * Deterministic Layer 2 switching, trunk pruning, and native VLAN evaluation.
 * Mandate: Educational simulation only.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
  window.EJIILearning.Labs = window.EJIILearning.Labs || {};
}

(function() {
  const DEFAULT_CONFIG = {
    sw1: {
      p1: { vlan: 10, mode: 'access' }, // Host A (Engineering)
      p2: { vlan: 20, mode: 'access' }, // Host B (Sales)
      trunk: { mode: 'trunk', nativeVlan: 1, allowedVlans: [10, 20, 30] }
    },
    sw2: {
      trunk: { mode: 'trunk', nativeVlan: 1, allowedVlans: [10, 20, 30] },
      p1: { vlan: 10, mode: 'access' }, // Host C (Engineering)
      p2: { vlan: 20, mode: 'access' }  // Host D (Sales)
    }
  };

  const HOSTS = [
    { id: 'hostA', name: 'Host A (Engineering)', ip: '10.10.10.1/24', switch: 'sw1', port: 'p1', defaultVlan: 10 },
    { id: 'hostB', name: 'Host B (Sales)', ip: '10.20.20.1/24', switch: 'sw1', port: 'p2', defaultVlan: 20 },
    { id: 'hostC', name: 'Host C (Engineering)', ip: '10.10.10.2/24', switch: 'sw2', port: 'p1', defaultVlan: 10 },
    { id: 'hostD', name: 'Host D (Sales)', ip: '10.20.20.2/24', switch: 'sw2', port: 'p2', defaultVlan: 20 }
  ];

  function evaluatePairConnectivity(srcHostId, dstHostId, config) {
    const srcHost = HOSTS.find(h => h.id === srcHostId);
    const dstHost = HOSTS.find(h => h.id === dstHostId);

    if (!srcHost || !dstHost) {
      return { connected: false, reason: 'Invalid host identifier' };
    }

    if (srcHostId === dstHostId) {
      return { connected: true, reason: 'Local loopback communication succeeds' };
    }

    const srcVlan = config[srcHost.switch][srcHost.port].vlan;
    const dstVlan = config[dstHost.switch][dstHost.port].vlan;

    // Rule 1: Layer 2 switches cannot forward across different VLANs without a Layer 3 router
    if (srcVlan !== dstVlan) {
      return {
        connected: false,
        vlan: null,
        reason: `VLAN Isolation: ${srcHost.name} is on VLAN ${srcVlan}, while ${dstHost.name} is on VLAN ${dstVlan}. Broadcast domains are completely isolated at Layer 2 (requires an inter-VLAN router / SVI).`
      };
    }

    const sharedVlan = srcVlan;

    // Intra-switch communication (both hosts on same switch)
    if (srcHost.switch === dstHost.switch) {
      return {
        connected: true,
        vlan: sharedVlan,
        reason: `Intra-Switch Success: Both hosts share VLAN ${sharedVlan} on ${srcHost.switch.toUpperCase()}. Frames are switched directly within the local broadcast domain.`
      };
    }

    // Inter-switch communication via Trunk link
    const sw1Trunk = config.sw1.trunk;
    const sw2Trunk = config.sw2.trunk;

    // Check trunk modes
    if (sw1Trunk.mode !== 'trunk' || sw2Trunk.mode !== 'trunk') {
      return {
        connected: false,
        vlan: sharedVlan,
        reason: 'Trunk Mode Error: Inter-switch link is not operating in 802.1Q trunk mode on both switches.'
      };
    }

    // Check Native VLAN mismatch
    if (sw1Trunk.nativeVlan !== sw2Trunk.nativeVlan) {
      return {
        connected: false,
        vlan: sharedVlan,
        reason: `Native VLAN Mismatch: SW1 native VLAN is ${sw1Trunk.nativeVlan}, but SW2 native VLAN is ${sw2Trunk.nativeVlan}. STP/CDP blocks traffic to prevent VLAN hopping.`
      };
    }

    // Check allowed VLAN list
    const sw1Allows = sw1Trunk.allowedVlans.includes(sharedVlan);
    const sw2Allows = sw2Trunk.allowedVlans.includes(sharedVlan);

    if (!sw1Allows || !sw2Allows) {
      const prunedOn = (!sw1Allows && !sw2Allows) ? 'SW1 and SW2' : (!sw1Allows ? 'SW1' : 'SW2');
      return {
        connected: false,
        vlan: sharedVlan,
        reason: `Trunk Pruning: VLAN ${sharedVlan} is filtered / pruned from the 802.1Q trunk allowed list on ${prunedOn}.`
      };
    }

    const isNative = (sharedVlan === sw1Trunk.nativeVlan);
    return {
      connected: true,
      vlan: sharedVlan,
      reason: `Inter-Switch 802.1Q Success: Traffic on VLAN ${sharedVlan} traverses the trunk link ${isNative ? 'untagged (Native VLAN)' : 'encapsulated with an 802.1Q tag (VID ' + sharedVlan + ')'}.`
    };
  }

  function evaluateAllPairs(config) {
    const results = [];
    for (let i = 0; i < HOSTS.length; i++) {
      for (let j = i + 1; j < HOSTS.length; j++) {
        const src = HOSTS[i];
        const dst = HOSTS[j];
        const evalRes = evaluatePairConnectivity(src.id, dst.id, config);
        results.push({
          srcId: src.id,
          dstId: dst.id,
          srcName: src.name,
          dstName: dst.name,
          ...evalRes
        });
      }
    }
    return results;
  }

  function renderVlanLab(containerEl) {
    if (!containerEl) return;

    let config = JSON.parse(JSON.stringify(DEFAULT_CONFIG));

    function renderUI() {
      const results = evaluateAllPairs(config);
      const nativeMismatch = (config.sw1.trunk.nativeVlan !== config.sw2.trunk.nativeVlan);

      containerEl.innerHTML = `
        <div class="ejii-learning-lab-header">
          <div>
            <span class="ejii-learning-badge ejii-learning-badge--accent">SIMULATED LAB</span>
            <span class="ejii-learning-badge" style="margin-left:8px;">Switching & 802.1Q</span>
            <h2 style="margin: 8px 0 4px; font-size: 20px;">VLAN Segmentation & 802.1Q Trunking Lab</h2>
            <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">
              Configure switchport access VLANs, trunk allowed lists, and observe L2 isolation vs 802.1Q transport.
            </p>
          </div>
          <button id="btnResetVlan" class="ejii-learning-btn ejii-learning-btn--secondary">&#8635; Reset Defaults</button>
        </div>

        ${nativeMismatch ? `
          <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 12px; margin-top: 16px; color: #fca5a5; font-size: 13px;">
            <strong>&excl; Warning: Native VLAN Mismatch Detected</strong><br>
            SW1 native VLAN is ${config.sw1.trunk.nativeVlan}, while SW2 native VLAN is ${config.sw2.trunk.nativeVlan}. Cisco switches trigger "%CDP-4-NATIVE_VLAN_MISMATCH" and block untagged traffic.
          </div>
        ` : ''}

        <!-- Configuration Controls Grid -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-top: 16px;">
          <!-- Switch 1 Configuration -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
            <div style="font-weight: 600; font-size: 14px; margin-bottom: 12px; color: var(--accent-color);">
              SWITCH SW1 CONFIGURATION
            </div>

            <!-- Port 1 (Host A) -->
            <div style="margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--border-color);">
              <div style="font-weight: 600; font-size: 13px; margin-bottom: 4px;">Port Fa0/1 &rarr; Host A (10.10.10.1)</div>
              <div style="display: flex; gap: 8px; align-items: center;">
                <label style="font-size: 12px; color: var(--text-secondary);">Access VLAN:</label>
                <select id="sw1_p1_vlan" class="ejii-learning-input" style="width: auto; padding: 4px 8px;">
                  <option value="10" ${config.sw1.p1.vlan === 10 ? 'selected' : ''}>VLAN 10 (Engineering)</option>
                  <option value="20" ${config.sw1.p1.vlan === 20 ? 'selected' : ''}>VLAN 20 (Sales)</option>
                  <option value="30" ${config.sw1.p1.vlan === 30 ? 'selected' : ''}>VLAN 30 (Management)</option>
                </select>
              </div>
            </div>

            <!-- Port 2 (Host B) -->
            <div style="margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--border-color);">
              <div style="font-weight: 600; font-size: 13px; margin-bottom: 4px;">Port Fa0/2 &rarr; Host B (10.20.20.1)</div>
              <div style="display: flex; gap: 8px; align-items: center;">
                <label style="font-size: 12px; color: var(--text-secondary);">Access VLAN:</label>
                <select id="sw1_p2_vlan" class="ejii-learning-input" style="width: auto; padding: 4px 8px;">
                  <option value="10" ${config.sw1.p2.vlan === 10 ? 'selected' : ''}>VLAN 10 (Engineering)</option>
                  <option value="20" ${config.sw1.p2.vlan === 20 ? 'selected' : ''}>VLAN 20 (Sales)</option>
                  <option value="30" ${config.sw1.p2.vlan === 30 ? 'selected' : ''}>VLAN 30 (Management)</option>
                </select>
              </div>
            </div>

            <!-- Port 24 Trunk -->
            <div>
              <div style="font-weight: 600; font-size: 13px; margin-bottom: 6px;">Port Gi0/1 (802.1Q Trunk to SW2)</div>
              <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px;">
                <label style="font-size: 12px; color: var(--text-secondary);">Native VLAN:</label>
                <select id="sw1_trunk_native" class="ejii-learning-input" style="width: auto; padding: 4px 8px;">
                  <option value="1" ${config.sw1.trunk.nativeVlan === 1 ? 'selected' : ''}>VLAN 1 (Default)</option>
                  <option value="99" ${config.sw1.trunk.nativeVlan === 99 ? 'selected' : ''}>VLAN 99 (Dedicated)</option>
                  <option value="10" ${config.sw1.trunk.nativeVlan === 10 ? 'selected' : ''}>VLAN 10 (Mismatched!)</option>
                </select>
              </div>
              <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Allowed VLANs:</div>
              <div style="display: flex; gap: 12px; font-size: 12px;">
                <label><input type="checkbox" id="sw1_allow_10" ${config.sw1.trunk.allowedVlans.includes(10) ? 'checked' : ''}> VLAN 10</label>
                <label><input type="checkbox" id="sw1_allow_20" ${config.sw1.trunk.allowedVlans.includes(20) ? 'checked' : ''}> VLAN 20</label>
                <label><input type="checkbox" id="sw1_allow_30" ${config.sw1.trunk.allowedVlans.includes(30) ? 'checked' : ''}> VLAN 30</label>
              </div>
            </div>
          </div>

          <!-- Switch 2 Configuration -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
            <div style="font-weight: 600; font-size: 14px; margin-bottom: 12px; color: var(--accent-color);">
              SWITCH SW2 CONFIGURATION
            </div>

            <!-- Port 1 (Host C) -->
            <div style="margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--border-color);">
              <div style="font-weight: 600; font-size: 13px; margin-bottom: 4px;">Port Fa0/1 &rarr; Host C (10.10.10.2)</div>
              <div style="display: flex; gap: 8px; align-items: center;">
                <label style="font-size: 12px; color: var(--text-secondary);">Access VLAN:</label>
                <select id="sw2_p1_vlan" class="ejii-learning-input" style="width: auto; padding: 4px 8px;">
                  <option value="10" ${config.sw2.p1.vlan === 10 ? 'selected' : ''}>VLAN 10 (Engineering)</option>
                  <option value="20" ${config.sw2.p1.vlan === 20 ? 'selected' : ''}>VLAN 20 (Sales)</option>
                  <option value="30" ${config.sw2.p1.vlan === 30 ? 'selected' : ''}>VLAN 30 (Management)</option>
                </select>
              </div>
            </div>

            <!-- Port 2 (Host D) -->
            <div style="margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--border-color);">
              <div style="font-weight: 600; font-size: 13px; margin-bottom: 4px;">Port Fa0/2 &rarr; Host D (10.20.20.2)</div>
              <div style="display: flex; gap: 8px; align-items: center;">
                <label style="font-size: 12px; color: var(--text-secondary);">Access VLAN:</label>
                <select id="sw2_p2_vlan" class="ejii-learning-input" style="width: auto; padding: 4px 8px;">
                  <option value="10" ${config.sw2.p2.vlan === 10 ? 'selected' : ''}>VLAN 10 (Engineering)</option>
                  <option value="20" ${config.sw2.p2.vlan === 20 ? 'selected' : ''}>VLAN 20 (Sales)</option>
                  <option value="30" ${config.sw2.p2.vlan === 30 ? 'selected' : ''}>VLAN 30 (Management)</option>
                </select>
              </div>
            </div>

            <!-- Port 24 Trunk -->
            <div>
              <div style="font-weight: 600; font-size: 13px; margin-bottom: 6px;">Port Gi0/1 (802.1Q Trunk to SW1)</div>
              <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px;">
                <label style="font-size: 12px; color: var(--text-secondary);">Native VLAN:</label>
                <select id="sw2_trunk_native" class="ejii-learning-input" style="width: auto; padding: 4px 8px;">
                  <option value="1" ${config.sw2.trunk.nativeVlan === 1 ? 'selected' : ''}>VLAN 1 (Default)</option>
                  <option value="99" ${config.sw2.trunk.nativeVlan === 99 ? 'selected' : ''}>VLAN 99 (Dedicated)</option>
                  <option value="20" ${config.sw2.trunk.nativeVlan === 20 ? 'selected' : ''}>VLAN 20 (Mismatched!)</option>
                </select>
              </div>
              <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Allowed VLANs:</div>
              <div style="display: flex; gap: 12px; font-size: 12px;">
                <label><input type="checkbox" id="sw2_allow_10" ${config.sw2.trunk.allowedVlans.includes(10) ? 'checked' : ''}> VLAN 10</label>
                <label><input type="checkbox" id="sw2_allow_20" ${config.sw2.trunk.allowedVlans.includes(20) ? 'checked' : ''}> VLAN 20</label>
                <label><input type="checkbox" id="sw2_allow_30" ${config.sw2.trunk.allowedVlans.includes(30) ? 'checked' : ''}> VLAN 30</label>
              </div>
            </div>
          </div>
        </div>

        <!-- Connectivity Matrix Evaluation -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-top: 16px;">
          <div style="font-weight: 600; font-size: 14px; margin-bottom: 12px; color: var(--text-primary);">
            CONNECTIVITY SIMULATION MATRIX (6 LINK COMBINATIONS)
          </div>
          <div style="overflow-x: auto;">
            <table class="ejii-learning-table" style="width: 100%; border-collapse: collapse; font-size: 13px;">
              <thead>
                <tr style="border-bottom: 1px solid var(--border-color); text-align: left;">
                  <th style="padding: 8px;">Source Host</th>
                  <th style="padding: 8px;">Destination Host</th>
                  <th style="padding: 8px;">Status</th>
                  <th style="padding: 8px;">Evaluation Explanation</th>
                </tr>
              </thead>
              <tbody>
                ${results.map(r => `
                  <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <td style="padding: 8px; font-weight: 500;">${r.srcName}</td>
                    <td style="padding: 8px; font-weight: 500;">${r.dstName}</td>
                    <td style="padding: 8px;">
                      <span class="ejii-learning-badge ${r.connected ? 'ejii-learning-badge--completed' : 'ejii-learning-badge--danger'}" style="font-size: 11px;">
                        ${r.connected ? '&#10003; REACHABLE' : '&#10007; ISOLATED'}
                      </span>
                    </td>
                    <td style="padding: 8px; color: var(--text-secondary); font-size: 12px;">${r.reason}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;

      // Helper to wire change listeners
      function bindSelect(id, setter) {
        const el = containerEl.querySelector('#' + id);
        if (el) el.addEventListener('change', (e) => { setter(Number(e.target.value)); renderUI(); });
      }

      function bindCheck(id, vlanVal, list) {
        const el = containerEl.querySelector('#' + id);
        if (el) {
          el.addEventListener('change', (e) => {
            if (e.target.checked) {
              if (!list.includes(vlanVal)) list.push(vlanVal);
            } else {
              const idx = list.indexOf(vlanVal);
              if (idx !== -1) list.splice(idx, 1);
            }
            renderUI();
          });
        }
      }

      bindSelect('sw1_p1_vlan', val => { config.sw1.p1.vlan = val; });
      bindSelect('sw1_p2_vlan', val => { config.sw1.p2.vlan = val; });
      bindSelect('sw1_trunk_native', val => { config.sw1.trunk.nativeVlan = val; });
      bindCheck('sw1_allow_10', 10, config.sw1.trunk.allowedVlans);
      bindCheck('sw1_allow_20', 20, config.sw1.trunk.allowedVlans);
      bindCheck('sw1_allow_30', 30, config.sw1.trunk.allowedVlans);

      bindSelect('sw2_p1_vlan', val => { config.sw2.p1.vlan = val; });
      bindSelect('sw2_p2_vlan', val => { config.sw2.p2.vlan = val; });
      bindSelect('sw2_trunk_native', val => { config.sw2.trunk.nativeVlan = val; });
      bindCheck('sw2_allow_10', 10, config.sw2.trunk.allowedVlans);
      bindCheck('sw2_allow_20', 20, config.sw2.trunk.allowedVlans);
      bindCheck('sw2_allow_30', 30, config.sw2.trunk.allowedVlans);

      const btnReset = containerEl.querySelector('#btnResetVlan');
      if (btnReset) {
        btnReset.addEventListener('click', () => {
          config = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
          renderUI();
        });
      }
    }

    renderUI();
  }

  if (typeof window !== 'undefined' && window.EJIILearning) {
    window.EJIILearning.Labs['net-vlan-lab'] = {
      render: renderVlanLab,
      evaluatePairConnectivity,
      evaluateAllPairs,
      DEFAULT_CONFIG,
      HOSTS
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      renderVlanLab,
      evaluatePairConnectivity,
      evaluateAllPairs,
      DEFAULT_CONFIG,
      HOSTS
    };
  }
})();
