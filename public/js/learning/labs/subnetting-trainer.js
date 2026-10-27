/**
 * EJII Learning Center — IPv4 Subnetting & CIDR Trainer Lab
 * High-precision 32-bit arithmetic, step-by-step breakdown, and randomized practice engine.
 * Fully handles /0 through /32, /31 point-to-point links (RFC 3021), and /32 host routes.
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

  function calculateSubnet(ipStr, prefixInput) {
    const ipInt = ipToInt(ipStr);
    if (ipInt === null) return { error: 'Invalid IPv4 address format (must be 4 octets 0-255)' };

    let prefix = Number(prefixInput);
    if (isNaN(prefix) || prefix < 0 || prefix > 32 || !Number.isInteger(prefix)) {
      return { error: 'CIDR prefix must be an integer between 0 and 32' };
    }

    const maskInt = prefixToMaskInt(prefix);
    const networkInt = ipInt & maskInt;
    const wildcardInt = (~maskInt) & 0xFFFFFFFFn;
    const broadcastInt = networkInt | wildcardInt;

    const totalAddresses = 2n ** BigInt(32 - prefix);
    let usableHosts = 0n;
    let firstUsableInt = 0n;
    let lastUsableInt = 0n;
    let note = '';

    if (prefix === 32) {
      usableHosts = 1n;
      firstUsableInt = networkInt;
      lastUsableInt = networkInt;
      note = 'Single Host Route (/32). Network and host are identical; no broadcast address.';
    } else if (prefix === 31) {
      usableHosts = 2n;
      firstUsableInt = networkInt;
      lastUsableInt = broadcastInt;
      note = 'RFC 3021 Point-to-Point Link (/31). Both addresses are usable hosts (no dedicated broadcast).';
    } else if (prefix === 0) {
      usableHosts = totalAddresses - 2n;
      firstUsableInt = networkInt + 1n;
      lastUsableInt = broadcastInt - 1n;
      note = 'Default Route (0.0.0.0/0). Encompasses all 4.29 billion global IPv4 addresses.';
    } else {
      usableHosts = totalAddresses - 2n;
      firstUsableInt = networkInt + 1n;
      lastUsableInt = broadcastInt - 1n;
      note = `Standard subnet: ${Number(usableHosts).toLocaleString()} usable host addresses.`;
    }

    // Step-by-step breakdown calculation
    const interestingOctet = prefix === 32 ? 4 : Math.floor(prefix / 8) + 1;
    const bitsInInterestingOctet = prefix % 8;
    const magicNumber = bitsInInterestingOctet === 0 ? 256 : (2 ** (8 - bitsInInterestingOctet));

    return {
      ip: ipStr.trim(),
      prefix,
      networkAddress: intToIp(networkInt),
      subnetMask: intToIp(maskInt),
      wildcardMask: intToIp(wildcardInt),
      broadcastAddress: prefix === 32 ? 'N/A (Host Route)' : intToIp(broadcastInt),
      firstUsableIp: intToIp(firstUsableInt),
      firstUsable: intToIp(firstUsableInt),
      lastUsableIp: intToIp(lastUsableInt),
      lastUsable: intToIp(lastUsableInt),
      totalAddresses: totalAddresses.toString(),
      usableHosts: Number(usableHosts),
      usableHostsStr: usableHosts.toString(),
      interestingOctet,
      magicNumber,
      note,
      breakdown: [
        `Prefix /${prefix} provides ${prefix} network bits and ${32 - prefix} host bits.`,
        `Subnet mask: ${intToIp(maskInt)} (Wildcard: ${intToIp(wildcardInt)}).`,
        `Interesting octet is Octet #${interestingOctet} with magic block size ${magicNumber}.`,
        `Subnet boundaries in octet #${interestingOctet} increment in steps of ${magicNumber}: 0, ${magicNumber}, ${magicNumber * 2}...`,
        `Network address: ${intToIp(networkInt)} | Broadcast: ${prefix === 32 ? 'N/A' : intToIp(broadcastInt)}.`
      ]
    };
  }

  // Export functions to namespace
  if (typeof window !== 'undefined') {
    window.EJIILearning = window.EJIILearning || {};
    window.EJIILearning.Labs = window.EJIILearning.Labs || {};
    window.EJIILearning.Labs.SubnettingTrainer = {
      calculateSubnet,
      ipToInt,
      intToIp
    };
  }

  /**
   * UI Component Renderer
   */
  function renderSubnettingTrainer(containerEl) {
    if (!containerEl) return;

    let currentExercise = null;

    function renderUI() {
      containerEl.innerHTML = `
        <div class="ejii-learning-lab-shell card" style="padding: 24px; max-width: 900px; margin: 0 auto;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-default); padding-bottom: 14px; margin-bottom: 20px;">
            <div>
              <div style="display: flex; align-items: center; gap: 8px;">
                <span class="hud-pill" style="background: rgba(2, 132, 199, 0.1); color: #0284c7; font-weight: 700;">SIMULATED LAB</span>
                <h3 style="margin: 0; font-size: 18px; color: var(--text-primary);">IPv4 Subnetting & CIDR Trainer</h3>
              </div>
              <p style="margin: 4px 0 0; font-size: 13px; color: var(--text-secondary);">Interactive 32-bit boundary calculator and randomized certification drill engine.</p>
            </div>
            <div style="display: flex; gap: 8px;">
              <button id="btnSubnetRandom" class="btn btn-secondary" style="font-size: 12px; padding: 6px 12px;">🎲 Random Drill</button>
              <button id="btnSubnetReset" class="btn btn-secondary" style="font-size: 12px; padding: 6px 12px;">Reset</button>
            </div>
          </div>

          <!-- Input Bar -->
          <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 8px; padding: 16px; margin-bottom: 20px;">
            <div style="display: flex; flex-wrap: wrap; gap: 14px; align-items: flex-end;">
              <div style="flex: 1; min-width: 200px;">
                <label style="display: block; font-size: 11px; font-weight: 700; color: var(--text-secondary); margin-bottom: 6px;">IPV4 ADDRESS</label>
                <input id="inputSubnetIp" type="text" class="form-input" style="width: 100%; font-family: var(--font-mono); font-size: 14px; padding: 8px 12px;" value="192.168.10.34" placeholder="e.g. 192.168.10.34">
              </div>
              <div style="width: 130px;">
                <label style="display: block; font-size: 11px; font-weight: 700; color: var(--text-secondary); margin-bottom: 6px;">CIDR PREFIX (/)</label>
                <div style="display: flex; align-items: center; gap: 4px;">
                  <span style="font-weight: 700; font-family: var(--font-mono); color: var(--text-secondary);">/</span>
                  <input id="inputSubnetPrefix" type="number" min="0" max="32" class="form-input" style="width: 100%; font-family: var(--font-mono); font-size: 14px; padding: 8px 12px;" value="27">
                </div>
              </div>
              <div>
                <button id="btnSubnetCalculate" class="btn btn-primary" style="height: 40px; padding: 0 20px; font-weight: 700;">Calculate</button>
              </div>
            </div>
          </div>

          <!-- Results Panel Mount -->
          <div id="subnetResultsContainer"></div>
        </div>
      `;

      const ipInp = containerEl.querySelector('#inputSubnetIp');
      const prefixInp = containerEl.querySelector('#inputSubnetPrefix');
      const calcBtn = containerEl.querySelector('#btnSubnetCalculate');
      const randBtn = containerEl.querySelector('#btnSubnetRandom');
      const resetBtn = containerEl.querySelector('#btnSubnetReset');

      calcBtn.addEventListener('click', () => {
        executeCalculation(ipInp.value, prefixInp.value);
      });

      randBtn.addEventListener('click', () => {
        generateRandomExercise();
      });

      resetBtn.addEventListener('click', () => {
        ipInp.value = '192.168.10.34';
        prefixInp.value = '27';
        executeCalculation(ipInp.value, prefixInp.value);
      });

      // Initial calculation
      executeCalculation(ipInp.value, prefixInp.value);
    }

    function executeCalculation(ip, prefix) {
      const resContainer = containerEl.querySelector('#subnetResultsContainer');
      if (!resContainer) return;

      const res = calculateSubnet(ip, prefix);
      if (res.error) {
        resContainer.innerHTML = `
          <div style="padding: 16px; background: #FFF1F2; border: 1px solid #FECDD3; border-radius: 8px; color: #9F1239; font-size: 13px;">
            <strong>Calculation Error:</strong> ${res.error}
          </div>
        `;
        return;
      }

      resContainer.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 16px;">
          <!-- 4 Essential Boundaries Grid -->
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
            <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 8px; padding: 14px;">
              <div style="font-size: 10px; font-weight: 700; color: #64748B; font-family: var(--font-mono);">NETWORK ADDRESS</div>
              <div style="font-size: 16px; font-weight: 800; color: var(--accent-primary); font-family: var(--font-mono); margin-top: 4px;">${res.networkAddress}</div>
            </div>
            <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 8px; padding: 14px;">
              <div style="font-size: 10px; font-weight: 700; color: #64748B; font-family: var(--font-mono);">USABLE HOST RANGE</div>
              <div style="font-size: 14px; font-weight: 700; color: #10B981; font-family: var(--font-mono); margin-top: 4px;">${res.firstUsableIp} – ${res.lastUsableIp}</div>
            </div>
            <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 8px; padding: 14px;">
              <div style="font-size: 10px; font-weight: 700; color: #64748B; font-family: var(--font-mono);">BROADCAST ADDRESS</div>
              <div style="font-size: 16px; font-weight: 800; color: #EF4444; font-family: var(--font-mono); margin-top: 4px;">${res.broadcastAddress}</div>
            </div>
            <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 8px; padding: 14px;">
              <div style="font-size: 10px; font-weight: 700; color: #64748B; font-family: var(--font-mono);">USABLE HOST COUNT</div>
              <div style="font-size: 16px; font-weight: 800; color: var(--text-primary); font-family: var(--font-mono); margin-top: 4px;">${Number(res.usableHosts).toLocaleString()}</div>
            </div>
          </div>

          <!-- Secondary Metrics -->
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; font-size: 12px; background: rgba(0,0,0,0.02); padding: 12px; border-radius: 6px;">
            <div><span style="color: var(--text-secondary);">Subnet Mask:</span> <code style="font-weight:700;">${res.subnetMask}</code></div>
            <div><span style="color: var(--text-secondary);">Wildcard Mask:</span> <code style="font-weight:700;">${res.wildcardMask}</code></div>
            <div><span style="color: var(--text-secondary);">Total Capacity:</span> <code style="font-weight:700;">${Number(res.totalAddresses).toLocaleString()}</code></div>
            <div><span style="color: var(--text-secondary);">Magic Number:</span> <code style="font-weight:700;">${res.magicNumber}</code></div>
          </div>

          <!-- Step-by-Step Breakdown -->
          <div style="border-top: 1px solid var(--border-default); padding-top: 14px;">
            <div style="font-size: 11px; font-weight: 800; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 8px;">Step-by-Step Calculation Breakdown</div>
            <ol style="margin: 0; padding-left: 20px; font-size: 13px; color: var(--text-primary); line-height: 1.6;">
              ${res.breakdown.map(step => `<li>${step}</li>`).join('')}
            </ol>
            <div style="margin-top: 10px; font-size: 12px; color: var(--text-secondary); font-style: italic;">
              ${res.note}
            </div>
          </div>
        </div>
      `;
    }

    function generateRandomExercise() {
      const samplePrefixes = [24, 25, 26, 27, 28, 29, 30, 20, 16];
      const p = samplePrefixes[Math.floor(Math.random() * samplePrefixes.length)];
      const o1 = 10;
      const o2 = Math.floor(Math.random() * 250);
      const o3 = Math.floor(Math.random() * 250);
      const o4 = Math.floor(Math.random() * 250) + 1;
      const ip = `${o1}.${o2}.${o3}.${o4}`;

      containerEl.querySelector('#inputSubnetIp').value = ip;
      containerEl.querySelector('#inputSubnetPrefix').value = p;
      executeCalculation(ip, p);
    }

    renderUI();
  };

  if (typeof window !== 'undefined' && window.EJIILearning) {
    window.EJIILearning.Labs['net-subnetting-trainer'] = {
      render: renderSubnettingTrainer,
      calculateSubnet,
      ipToInt,
      intToIp,
      prefixToMaskInt
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      renderSubnettingTrainer,
      calculateSubnet,
      ipToInt,
      intToIp,
      prefixToMaskInt
    };
  }
})();
