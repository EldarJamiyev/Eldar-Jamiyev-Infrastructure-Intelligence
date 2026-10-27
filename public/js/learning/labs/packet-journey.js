/**
 * EJII Learning Center — L2/L3 Packet Journey Visualizer Lab
 * Simulates step-by-step frame encapsulation, ARP resolution, and router L2 header rewriting.
 * Mandate: Educational simulation only.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
  window.EJIILearning.Labs = window.EJIILearning.Labs || {};
}

(function() {
  const JOURNEY_SCENARIOS = {
    'same-subnet': {
      title: 'Same Subnet Direct Delivery (Host A -> Host B via Switch)',
      nodes: [
        { id: 'hostA', label: 'Host A', ip: '192.168.1.10/24', mac: 'AA:AA:AA:11:11:11', role: 'Source Client', x: 80, y: 120 },
        { id: 'switch', label: 'Switch SW1', ip: 'Layer 2 Device', mac: 'Transparent Bridge', role: 'Distribution Switch', x: 300, y: 120 },
        { id: 'hostB', label: 'Host B', ip: '192.168.1.20/24', mac: 'BB:BB:BB:22:22:22', role: 'Destination Host', x: 520, y: 120 }
      ],
      steps: [
        {
          title: 'Step 1: Subnet Evaluation & Route Check',
          source: 'hostA',
          target: 'hostA',
          l2: { srcMac: 'AA:AA:AA:11:11:11', dstMac: 'Unresolved', etherType: '0x0800 (IPv4)' },
          l3: { srcIp: '192.168.1.10', dstIp: '192.168.1.20', ttl: 64, proto: 'ICMP Echo (Ping)' },
          explanation: 'Host A evaluates destination 192.168.1.20 with its own subnet mask 255.255.255.0. Both reside on 192.168.1.0/24. Direct delivery is selected (no router required).'
        },
        {
          title: 'Step 2: ARP Cache Inspection & ARP Broadcast',
          source: 'hostA',
          target: 'switch',
          l2: { srcMac: 'AA:AA:AA:11:11:11', dstMac: 'FF:FF:FF:FF:FF:FF', etherType: '0x0806 (ARP)' },
          l3: { srcIp: '192.168.1.10', dstIp: '192.168.1.20', ttl: 'N/A (L2)', proto: 'ARP Request (Who has 192.168.1.20?)' },
          explanation: 'Host A has an empty ARP cache. It broadcasts an ARP Request (destination MAC FF:FF:FF:FF:FF:FF) inquiring for the hardware address of 192.168.1.20.'
        },
        {
          title: 'Step 3: Switch Flooding & Host B Receipt',
          source: 'switch',
          target: 'hostB',
          l2: { srcMac: 'AA:AA:AA:11:11:11', dstMac: 'FF:FF:FF:FF:FF:FF', etherType: '0x0806 (ARP)' },
          l3: { srcIp: '192.168.1.10', dstIp: '192.168.1.20', ttl: 'N/A (L2)', proto: 'ARP Request Forwarded' },
          explanation: 'SW1 learns Host A MAC on port 1 and floods the broadcast out all access ports in VLAN 1. Host B receives the frame and matches its configured IPv4 address.'
        },
        {
          title: 'Step 4: Unicast ARP Reply from Host B',
          source: 'hostB',
          target: 'hostA',
          l2: { srcMac: 'BB:BB:BB:22:22:22', dstMac: 'AA:AA:AA:11:11:11', etherType: '0x0806 (ARP)' },
          l3: { srcIp: '192.168.1.20', dstIp: '192.168.1.10', ttl: 'N/A (L2)', proto: 'ARP Reply (192.168.1.20 is at BB:BB:BB:22:22:22)' },
          explanation: 'Host B updates its ARP cache with Host A and sends a unicast ARP Reply directly back to Host A. SW1 forwards it directly using its learned MAC table.'
        },
        {
          title: 'Step 5: Frame Encapsulation & Transmission',
          source: 'hostA',
          target: 'switch',
          l2: { srcMac: 'AA:AA:AA:11:11:11', dstMac: 'BB:BB:BB:22:22:22', etherType: '0x0800 (IPv4)' },
          l3: { srcIp: '192.168.1.10', dstIp: '192.168.1.20', ttl: 64, proto: 'ICMP Echo Request' },
          explanation: 'Host A caches Host B MAC. Host A encapsulates the IP packet into an Ethernet frame: Src MAC AA:AA:AA:11:11:11, Dst MAC BB:BB:BB:22:22:22. The frame enters SW1.'
        },
        {
          title: 'Step 6: Layer 2 Frame Delivery to Destination',
          source: 'switch',
          target: 'hostB',
          l2: { srcMac: 'AA:AA:AA:11:11:11', dstMac: 'BB:BB:BB:22:22:22', etherType: '0x0800 (IPv4)' },
          l3: { srcIp: '192.168.1.10', dstIp: '192.168.1.20', ttl: 64, proto: 'ICMP Echo Request Delivered' },
          explanation: 'SW1 forwards the frame out port 2. Host B verifies Dst MAC, decapsulates the Ethernet header, processes the IP payload, and prepares an ICMP Echo Reply.'
        }
      ]
    },
    'different-subnet': {
      title: 'Different Subnet Routed Delivery (Host A -> Router R1 -> Web Server)',
      nodes: [
        { id: 'hostA', label: 'Client A', ip: '10.0.1.50/24', mac: 'AA:AA:AA:11:11:11', role: 'Default Gateway: 10.0.1.1', x: 80, y: 120 },
        { id: 'router', label: 'Router R1', ip: 'eth0: 10.0.1.1 | eth1: 172.16.2.1', mac: 'eth0: 00:00:5E:01 | eth1: 00:00:5E:02', role: 'L3 Default Gateway', x: 300, y: 120 },
        { id: 'webServer', label: 'Web Server', ip: '172.16.2.80/24', mac: 'CC:CC:CC:33:33:33', role: 'HTTP Server (:80)', x: 520, y: 120 }
      ],
      steps: [
        {
          title: 'Step 1: Subnet Evaluation & Default Gateway Selection',
          source: 'hostA',
          target: 'hostA',
          l2: { srcMac: 'AA:AA:AA:11:11:11', dstMac: 'Unresolved', etherType: '0x0800' },
          l3: { srcIp: '10.0.1.50', dstIp: '172.16.2.80', ttl: 64, proto: 'TCP SYN (Port 80)' },
          explanation: 'Client A wants to reach 172.16.2.80. Subnet test reveals it is off-link. Host A selects its configured Default Gateway 10.0.1.1 for delivery.'
        },
        {
          title: 'Step 2: L2 Encapsulation to Router MAC (Hop 1)',
          source: 'hostA',
          target: 'router',
          l2: { srcMac: 'AA:AA:AA:11:11:11', dstMac: '00:00:5E:00:01:01', etherType: '0x0800' },
          l3: { srcIp: '10.0.1.50', dstIp: '172.16.2.80', ttl: 64, proto: 'TCP SYN' },
          explanation: 'KEY PRINCIPLE: Destination IP is 172.16.2.80 (Web Server), but Destination MAC is 00:00:5E:00:01:01 (Router eth0)! L2 delivers hop-by-hop; L3 delivers end-to-end.'
        },
        {
          title: 'Step 3: Router Ingress & Decapsulation',
          source: 'router',
          target: 'router',
          l2: { srcMac: 'Stripped', dstMac: 'Stripped', etherType: 'Decapsulated' },
          l3: { srcIp: '10.0.1.50', dstIp: '172.16.2.80', ttl: 63, proto: 'Route Lookup in Progress' },
          explanation: 'Router R1 receives the frame on eth0, matches its own MAC, strips the L2 header, and decrements IPv4 TTL from 64 to 63 (updating IPv4 header checksum).'
        },
        {
          title: 'Step 4: Longest-Prefix Match Routing Table Lookup',
          source: 'router',
          target: 'router',
          l2: { srcMac: 'Pending Rewrite', dstMac: 'Pending ARP', etherType: '0x0800' },
          l3: { srcIp: '10.0.1.50', dstIp: '172.16.2.80', ttl: 63, proto: 'Matched 172.16.2.0/24 on eth1' },
          explanation: 'R1 searches its routing table for 172.16.2.80. Route found: 172.16.2.0/24 directly connected on eth1. Next-hop is the destination host directly.'
        },
        {
          title: 'Step 5: L2 MAC Header Rewrite (Hop 2)',
          source: 'router',
          target: 'webServer',
          l2: { srcMac: '00:00:5E:00:02:01', dstMac: 'CC:CC:CC:33:33:33', etherType: '0x0800' },
          l3: { srcIp: '10.0.1.50', dstIp: '172.16.2.80', ttl: 63, proto: 'TCP SYN Forwarded' },
          explanation: 'CRITICAL ROUTING MECHANISM: R1 prepends a brand-new L2 Ethernet header! Src MAC is now R1 eth1 (00:00:5E:00:02:01); Dst MAC is Server (CC:CC:CC:33:33:33). L3 IPs remain unchanged.'
        },
        {
          title: 'Step 6: Server Arrival & Layer 4 Ingress',
          source: 'webServer',
          target: 'webServer',
          l2: { srcMac: '00:00:5E:00:02:01', dstMac: 'CC:CC:CC:33:33:33', etherType: '0x0800' },
          l3: { srcIp: '10.0.1.50', dstIp: '172.16.2.80', ttl: 63, proto: 'TCP Handshake Initiated' },
          explanation: 'Web Server receives the frame on its NIC, verifies Destination MAC, strips L2, checks Destination IP, and delivers the TCP SYN payload to the HTTP listening socket.'
        }
      ]
    }
  };

  function getJourneyState(mode, stepIndex) {
    const scenario = JOURNEY_SCENARIOS[mode] || JOURNEY_SCENARIOS['same-subnet'];
    const safeIndex = Math.max(0, Math.min(stepIndex, scenario.steps.length - 1));
    return {
      mode,
      title: scenario.title,
      nodes: scenario.nodes,
      currentStepIndex: safeIndex,
      totalSteps: scenario.steps.length,
      step: scenario.steps[safeIndex],
      isFirst: safeIndex === 0,
      isLast: safeIndex === scenario.steps.length - 1
    };
  }

  function renderPacketJourneyLab(containerEl) {
    if (!containerEl) return;

    let currentMode = 'different-subnet';
    let currentStep = 0;
    let timerId = null;

    function renderUI() {
      const state = getJourneyState(currentMode, currentStep);
      const isAutoPlaying = timerId !== null;

      containerEl.innerHTML = `
        <div class="ejii-learning-lab-header">
          <div>
            <span class="ejii-learning-badge ejii-learning-badge--accent">SIMULATED LAB</span>
            <span class="ejii-learning-badge" style="margin-left:8px;">Network Fundamentals</span>
            <h2 style="margin: 8px 0 4px; font-size: 20px;">L2/L3 Packet Journey Visualizer</h2>
            <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">
              Trace frame encapsulation, MAC address rewriting, and IP persistence across network boundaries.
            </p>
          </div>
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            <select id="selectJourneyMode" class="ejii-learning-input" style="width: auto; padding: 6px 12px;">
              <option value="different-subnet" ${currentMode === 'different-subnet' ? 'selected' : ''}>Different Subnet (Routed Delivery)</option>
              <option value="same-subnet" ${currentMode === 'same-subnet' ? 'selected' : ''}>Same Subnet (Direct L2 Delivery)</option>
            </select>
            <button id="btnPrevStep" class="ejii-learning-btn ejii-learning-btn--secondary" ${state.isFirst ? 'disabled' : ''}>&larr; Prev</button>
            <button id="btnNextStep" class="ejii-learning-btn ejii-learning-btn--primary" ${state.isLast ? 'disabled' : ''}>Next &rarr;</button>
            <button id="btnPlayPause" class="ejii-learning-btn ejii-learning-btn--secondary">${isAutoPlaying ? '&#10074;&#10074; Pause' : '&#9658; Auto-Play'}</button>
            <button id="btnResetJourney" class="ejii-learning-btn ejii-learning-btn--secondary">&#8635; Reset</button>
          </div>
        </div>

        <!-- SVG Topology Diagram -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-top: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="font-weight: 600; font-size: 14px; color: var(--text-primary);">${state.title}</div>
            <div style="font-size: 12px; color: var(--text-secondary);">Step ${state.currentStepIndex + 1} of ${state.totalSteps}</div>
          </div>

          <div style="width: 100%; overflow-x: auto; text-align: center;">
            <svg id="journeySvg" viewBox="0 0 600 240" style="max-width: 600px; width: 100%; height: auto; display: inline-block;">
              <!-- Connecting Links -->
              <line x1="80" y1="120" x2="300" y2="120" stroke="var(--border-color)" stroke-width="4" stroke-dasharray="2,2"/>
              <line x1="300" y1="120" x2="520" y2="120" stroke="var(--border-color)" stroke-width="4" stroke-dasharray="2,2"/>

              ${state.nodes.map(n => {
                const isActive = (n.id === state.step.source || n.id === state.step.target);
                const fillColor = isActive ? '#0e8a72' : '#2b303c';
                const strokeColor = isActive ? '#4dd0e1' : '#454e5e';
                return `
                  <g class="journey-node" data-node-id="${n.id}">
                    <circle cx="${n.x}" cy="${n.y}" r="34" fill="${fillColor}" stroke="${strokeColor}" stroke-width="2.5" />
                    <text x="${n.x}" y="${n.y - 42}" text-anchor="middle" font-size="12" font-weight="600" fill="var(--text-primary)">${n.label}</text>
                    <text x="${n.x}" y="${n.y + 4}" text-anchor="middle" font-size="10" fill="#ffffff" font-family="monospace">${n.id === 'switch' ? 'SW1' : (n.id === 'router' ? 'R1' : 'HOST')}</text>
                    <text x="${n.x}" y="${n.y + 54}" text-anchor="middle" font-size="10" fill="var(--text-secondary)">${n.ip}</text>
                    <text x="${n.x}" y="${n.y + 68}" text-anchor="middle" font-size="9" fill="var(--text-secondary)" font-family="monospace">${n.mac}</text>
                  </g>
                `;
              }).join('')}
            </svg>
          </div>
        </div>

        <!-- Inspection Grid (L2 Frame vs L3 Packet) -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 16px;">
          <!-- L2 Frame Card -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; margin-bottom: 12px;">
              <span style="font-weight: 600; font-size: 13px; color: #4dd0e1;">LAYER 2 ETHERNET FRAME</span>
              <span class="ejii-learning-badge" style="font-size: 10px;">Changes Hop-by-Hop</span>
            </div>
            <div style="display: flex; flex-direction: column; gap: 8px; font-family: monospace; font-size: 12px;">
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-secondary);">Source MAC:</span>
                <span style="color: var(--text-primary); font-weight: 600;">${state.step.l2.srcMac}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-secondary);">Dest MAC:</span>
                <span style="color: #ffb74d; font-weight: 600;">${state.step.l2.dstMac}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-secondary);">EtherType:</span>
                <span style="color: var(--text-primary);">${state.step.l2.etherType}</span>
              </div>
            </div>
          </div>

          <!-- L3 Packet Card -->
          <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; margin-bottom: 12px;">
              <span style="font-weight: 600; font-size: 13px; color: #81c784;">LAYER 3 IP PACKET</span>
              <span class="ejii-learning-badge" style="font-size: 10px;">Preserved End-to-End</span>
            </div>
            <div style="display: flex; flex-direction: column; gap: 8px; font-family: monospace; font-size: 12px;">
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-secondary);">Source IP:</span>
                <span style="color: var(--text-primary); font-weight: 600;">${state.step.l3.srcIp}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-secondary);">Dest IP:</span>
                <span style="color: #81c784; font-weight: 600;">${state.step.l3.dstIp}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-secondary);">IPv4 TTL / Proto:</span>
                <span style="color: var(--text-primary);">TTL: ${state.step.l3.ttl} | ${state.step.l3.proto}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Step Explanation -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-left: 4px solid var(--accent-color); border-radius: 8px; padding: 16px; margin-top: 16px;">
          <div style="font-weight: 600; font-size: 14px; margin-bottom: 6px; color: var(--text-primary);">
            ${state.step.title}
          </div>
          <div style="font-size: 13px; line-height: 1.6; color: var(--text-secondary);">
            ${state.step.explanation}
          </div>
        </div>
      `;

      // Wire handlers
      containerEl.querySelector('#selectJourneyMode').addEventListener('change', (e) => {
        currentMode = e.target.value;
        currentStep = 0;
        stopAutoPlay();
        renderUI();
      });

      const btnPrev = containerEl.querySelector('#btnPrevStep');
      if (btnPrev) {
        btnPrev.addEventListener('click', () => {
          if (currentStep > 0) {
            currentStep--;
            stopAutoPlay();
            renderUI();
          }
        });
      }

      const btnNext = containerEl.querySelector('#btnNextStep');
      if (btnNext) {
        btnNext.addEventListener('click', () => {
          const scenario = JOURNEY_SCENARIOS[currentMode];
          if (currentStep < scenario.steps.length - 1) {
            currentStep++;
            stopAutoPlay();
            renderUI();
          }
        });
      }

      const btnPlay = containerEl.querySelector('#btnPlayPause');
      if (btnPlay) {
        btnPlay.addEventListener('click', () => {
          if (timerId) {
            stopAutoPlay();
          } else {
            startAutoPlay();
          }
          renderUI();
        });
      }

      const btnReset = containerEl.querySelector('#btnResetJourney');
      if (btnReset) {
        btnReset.addEventListener('click', () => {
          currentStep = 0;
          stopAutoPlay();
          renderUI();
        });
      }
    }

    function startAutoPlay() {
      if (timerId) clearInterval(timerId);
      timerId = setInterval(() => {
        const scenario = JOURNEY_SCENARIOS[currentMode];
        if (currentStep < scenario.steps.length - 1) {
          currentStep++;
          renderUI();
        } else {
          stopAutoPlay();
          renderUI();
        }
      }, 2500);
    }

    function stopAutoPlay() {
      if (timerId) {
        clearInterval(timerId);
        timerId = null;
      }
    }

    renderUI();
  }

  if (typeof window !== 'undefined' && window.EJIILearning) {
    window.EJIILearning.Labs['net-packet-journey'] = {
      render: renderPacketJourneyLab,
      getJourneyState,
      JOURNEY_SCENARIOS
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      renderPacketJourneyLab,
      getJourneyState,
      JOURNEY_SCENARIOS
    };
  }
})();
