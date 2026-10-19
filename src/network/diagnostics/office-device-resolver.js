/**
 * EJII Office Equipment Classifier, Visual Smart Path Mapper &
 * Plain-Language Automated Problem Resolver
 *
 * Designed for dual-audience operational excellence:
 *  1. Everyday IT Support / L1 Helpdesk Staff: Jargon-free "What the Problem Is",
 *     "Why It Happened", and "Step-by-Step Fix Plan" for office printers, VoIP phones,
 *     APIPA (169.254.x.x) self-assigned IP faults, and workstation drops.
 *  2. Senior Network Architects: Exact RFC 3927 / RFC 2131 / RFC 793 / RFC 826
 *     wire telemetry, L2 MAC OUI signatures, and hop-by-hop latency/loss proofs.
 */

const net = require('net');
const dns = require('dns').promises;
const { getPhysicalNetworkInfo } = require('../routing/physical-network-detector');
const { pingHost } = require('../../protocols/icmp-ping');

const PRINTER_VENDOR_KEYWORDS = [
  'hewlett packard', 'hp ', 'canon', 'epson', 'brother', 'xerox', 'ricoh',
  'kyocera', 'lexmark', 'konica', 'minolta', 'sharp', 'zebra', 'oki ', 'pantum'
];

const VOIP_PHONE_VENDOR_KEYWORDS = [
  'polycom', 'yealink', 'grandstream', 'snom', 'avaya', 'mitel', 'fanvil', 'audiocodes', 'cisco'
];

const CAMERA_NVR_VENDOR_KEYWORDS = [
  'hikvision', 'dahua', 'hanwha', 'axis', 'vivotek', 'uniview', 'reolink', 'ubiquiti'
];

const NETWORK_GEAR_VENDOR_KEYWORDS = [
  'cisco', 'juniper', 'arista', 'mikrotik', 'tp-link', 'keenetic', 'ubiquiti',
  'netgear', 'fortinet', 'palo alto', 'aruba', 'ruckus', 'd-link', 'huawei', 'xiaomi'
];

/**
 * Checks whether an IPv4 address is in the RFC 3927 APIPA / Link-Local range (169.254.0.0/16),
 * explicitly distinguishing local office APIPA devices from cloud metadata 169.254.169.254.
 */
function analyzeApipaAddress(ipStr) {
  const clean = String(ipStr || '').trim();
  const m = clean.match(/^169\.254\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) {
    return { isApipa: false, isCloudMetadata: false, isRfc3927LinkLocal: false };
  }
  const oct3 = Number(m[1]);
  const oct4 = Number(m[2]);
  if (oct3 === 169 && oct4 === 254) {
    return {
      isApipa: false,
      isCloudMetadata: true,
      isRfc3927LinkLocal: false,
      reason: 'CLOUD_METADATA_SSRF_ENDPOINT_BLOCKED'
    };
  }
  return {
    isApipa: true,
    isCloudMetadata: false,
    isRfc3927LinkLocal: true,
    rfcCitation: 'RFC 3927 (Dynamic Configuration of IPv4 Link-Local Addresses)',
    subnetScope: '169.254.0.0/16'
  };
}

/**
 * Classifies a discovered network host into a human-friendly Office Equipment Category
 * using MAC OUI manufacturer, open TCP service ports, hostname, and IP state.
 */
function classifyOfficeEquipment(host = {}) {
  const ip = String(host.ip || '').trim();
  const mac = String(host.macAddress || host.mac || 'Unknown').trim();
  const vendor = String(host.vendor || host.manufacturer || host.vendorOUI || '— (No MAC Observed)').trim();
  const vendorLower = vendor.toLowerCase();
  const hostname = String(host.hostname || host.netbiosName || '').toLowerCase();
  const openPorts = Array.isArray(host.openServices)
    ? host.openServices.map((s) => Number(typeof s === 'object' ? s.port : s))
    : Array.isArray(host.probedPorts)
      ? host.probedPorts.filter((p) => p.open || p.status === 'OPEN').map((p) => Number(p.port))
      : [];

  const apipaInfo = analyzeApipaAddress(ip);

  // 1. Check Printer signatures (Ports 9100 JetDirect, 631 IPP, 515 LPD, or Printer OUI/Hostname)
  const hasPrinterPort = openPorts.includes(9100) || openPorts.includes(631) || openPorts.includes(515);
  const hasPrinterVendor = PRINTER_VENDOR_KEYWORDS.some((kw) => vendorLower.includes(kw));
  const hasPrinterName = /print|prn|mfp|laserjet|officejet|deskjet|canon|epson|brother|xerox/i.test(hostname);

  if (hasPrinterPort || hasPrinterVendor || hasPrinterName) {
    return {
      equipmentType: 'PRINTER',
      equipmentLabel: 'Office Printer / Multifunction (MFP)',
      icon: '🖨️',
      digitalSignatureMac: mac && mac !== 'Unknown' ? mac : 'Unresolved (No L2 ARP)',
      equipmentBrand: vendor !== '— (No MAC Observed)' ? vendor : (hasPrinterName ? 'Network Printer' : 'Unidentified Printer Brand'),
      isApipaFault: apipaInfo.isApipa,
      confidence: hasPrinterPort && hasPrinterVendor ? 'HIGH (Port + MAC OUI)' : 'MEDIUM (Signature Match)'
    };
  }

  // 2. Check VoIP / IP Phone signatures (Port 5060/5061 SIP or VoIP OUI/Hostname)
  const hasVoipPort = openPorts.includes(5060) || openPorts.includes(5061);
  const hasVoipVendor = VOIP_PHONE_VENDOR_KEYWORDS.some((kw) => vendorLower.includes(kw)) && !host.isGateway;
  const hasVoipName = /sip|voip|phone|yealink|polycom|grandstream|ext-/i.test(hostname);

  if (hasVoipPort || hasVoipName || (hasVoipVendor && !openPorts.includes(80) && !openPorts.includes(443))) {
    return {
      equipmentType: 'VOIP_PHONE',
      equipmentLabel: 'Office VoIP / IP Desk Phone',
      icon: '📞',
      digitalSignatureMac: mac && mac !== 'Unknown' ? mac : 'Unresolved (No L2 ARP)',
      equipmentBrand: vendor,
      isApipaFault: apipaInfo.isApipa,
      confidence: 'HIGH (VoIP Signature)'
    };
  }

  // 3. Check IP Camera / NVR signatures (Port 554 RTSP, 8000, 37777 or Camera OUI)
  const hasCameraPort = openPorts.includes(554) || openPorts.includes(37777);
  const hasCameraVendor = CAMERA_NVR_VENDOR_KEYWORDS.some((kw) => vendorLower.includes(kw));
  if (hasCameraPort || hasCameraVendor || /cam|nvr|dvr|ipc/i.test(hostname)) {
    return {
      equipmentType: 'CAMERA_NVR',
      equipmentLabel: 'Security IP Camera / NVR Recorder',
      icon: '📹',
      digitalSignatureMac: mac && mac !== 'Unknown' ? mac : 'Unresolved (No L2 ARP)',
      equipmentBrand: vendor,
      isApipaFault: apipaInfo.isApipa,
      confidence: 'HIGH (Video/OUI Signature)'
    };
  }

  // 4. Check Gateway / Router / Switch
  const netInfo = getPhysicalNetworkInfo();
  if (host.isGateway || ip === netInfo.defaultGateway || openPorts.includes(53) || NETWORK_GEAR_VENDOR_KEYWORDS.some((kw) => vendorLower.includes(kw))) {
    return {
      equipmentType: 'NETWORK_INFRASTRUCTURE',
      equipmentLabel: ip === netInfo.defaultGateway ? 'Office Default Gateway / DHCP Router' : 'Network Switch / Wireless AP',
      icon: '🌐',
      digitalSignatureMac: mac && mac !== 'Unknown' ? mac : 'Unresolved (No L2 ARP)',
      equipmentBrand: vendor,
      isApipaFault: apipaInfo.isApipa,
      confidence: 'HIGH (Infrastructure Role)'
    };
  }

  // 5. Check Workstation / Server (Ports 445 SMB, 135 RPC, 139 NetBIOS, 3389 RDP, 22 SSH)
  const hasPcPort = openPorts.includes(445) || openPorts.includes(135) || openPorts.includes(139) || openPorts.includes(3389) || openPorts.includes(22);
  if (hasPcPort || host.isLocalHost || ip === netInfo.localIp || (mac && mac !== 'Unknown')) {
    return {
      equipmentType: 'COMPUTER',
      equipmentLabel: ip === netInfo.localIp ? 'This Operator Workstation (Local PC)' : 'Office Computer / Workstation',
      icon: '💻',
      digitalSignatureMac: mac && mac !== 'Unknown' ? mac : 'Unresolved (No L2 ARP)',
      equipmentBrand: vendor,
      isApipaFault: apipaInfo.isApipa,
      confidence: hasPcPort ? 'HIGH (OS Service Ports)' : 'MEDIUM (Active ARP Endpoint)'
    };
  }

  return {
    equipmentType: apipaInfo.isApipa ? 'APIPA_FAULT_DEVICE' : 'UNOCCUPIED_IP',
    equipmentLabel: apipaInfo.isApipa ? 'Self-Assigned Error IP Device (APIPA 169.254.x.x)' : 'Unoccupied / Silent IP Address',
    icon: apipaInfo.isApipa ? '⚠️' : '⚪',
    digitalSignatureMac: mac && mac !== 'Unknown' ? mac : '— (No MAC Observed)',
    equipmentBrand: '— (No MAC Observed)',
    isApipaFault: apipaInfo.isApipa,
    confidence: 'LOW'
  };
}

/**
 * Probes a single TCP port with bounded timeout and returns { open, rttMs, errorCode }.
 */
function probeTcpPortQuick(ip, port, timeoutMs = 900) {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let settled = false;
    const finish = (res) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch (_) {}
      resolve(res);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish({ port, open: true, rttMs: Date.now() - start, errorCode: null }));
    sock.once('timeout', () => finish({ port, open: false, rttMs: Date.now() - start, errorCode: 'ETIMEDOUT' }));
    sock.once('error', (err) => finish({ port, open: false, rttMs: Date.now() - start, errorCode: err.code || 'ERROR' }));
    try {
      sock.connect(port, ip);
    } catch (err) {
      finish({ port, open: false, rttMs: 0, errorCode: err.code || 'ERROR' });
    }
  });
}

const previousDiagnosisMap = new Map();
const MAX_PREVIOUS_DIAGNOSES = 200;

/**
 * Safe HTTP / IPP (Port 631 / Port 80) & JetDirect Application-Layer Banner Introspection
 * Sends a bounded HTTP HEAD / request over a raw TCP socket and parses Server header.
 */
function probeOfficeApplicationBanner(ip, port, timeoutMs = 650) {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = new net.Socket();
    let rawData = '';

    const done = (res) => {
      if (!resolved) {
        resolved = true;
        try { socket.destroy(); } catch (_) {}
        resolve(res);
      }
    };

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      if (Number(port) === 9100) {
        // JetDirect / RAW printer port probe
        socket.write('@PJL INFO ID\r\n');
      } else {
        // Standard HTTP / IPP probe
        const req = `GET / HTTP/1.1\r\nHost: ${ip}\r\nUser-Agent: EJII-OfficeProber/1.0\r\nConnection: close\r\n\r\n`;
        socket.write(req);
      }
    });

    socket.on('data', (chunk) => {
      rawData += chunk.toString('utf8');
      if (rawData.includes('\r\n\r\n') || rawData.includes('\x0c') || rawData.length > 2048) {
        parseAndResolve();
      }
    });

    function parseAndResolve() {
      const isJetDirect = Number(port) === 9100 || rawData.includes('@PJL') || /LaserJet|Printer|DeskJet|Stylus/i.test(rawData);
      if (isJetDirect && !rawData.startsWith('HTTP/')) {
        const cleanBanner = rawData.replace(/[\x00-\x1f\x7f-\x9f]/g, ' ').replace(/\s+/g, ' ').trim();
        done({
          protocol: 'JETDIRECT',
          banner: cleanBanner || 'Raw Printer Socket',
          server: 'JetDirect/9100',
          title: cleanBanner,
          statusCode: 200,
          rawBanner: rawData
        });
        return;
      }

      const firstLine = rawData.split('\r\n')[0] || '';
      const statusMatch = firstLine.match(/HTTP\/\d\.\d\s+(\d{3})/i);
      const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : (rawData.length > 0 ? 200 : 0);
      const serverMatch = rawData.match(/Server:\s*([^\r\n]+)/i);
      const serverHeader = serverMatch ? serverMatch[1].trim() : '';
      const titleMatch = rawData.match(/<title[^>]*>([^<]+)<\/title>/i);
      const title = titleMatch ? titleMatch[1].trim() : '';

      const combinedBanner = [serverHeader, title].filter(Boolean).join(' - ') || firstLine || 'HTTP Service';

      done({
        protocol: 'HTTP_IPP',
        banner: combinedBanner,
        server: serverHeader,
        title,
        statusCode,
        statusLine: firstLine,
        serverHeader,
        rawBanner: rawData
      });
    }

    socket.on('end', () => {
      if (rawData.length > 0) {
        parseAndResolve();
      } else {
        done(null);
      }
    });

    socket.on('timeout', () => {
      done(null);
    });

    socket.on('error', () => {
      done(null);
    });

    socket.connect(port, ip);
  });
}

/**
 * Runs an Automated Plain-Language Diagnostic & Visual Smart Path Trace on any Office Device
 * (e.g., an office printer with a 169.254.x.x APIPA error address, an offline printer on the LAN,
 * or a computer/phone experiencing connectivity drops).
 */
async function diagnoseOfficeDevice({
  targetIp = '',
  deviceTypeHint = 'PRINTER',
  deviceName = '',
  macAddress = '',
  vendor = '',
  isRetest = false
} = {}) {
  const cleanIp = String(targetIp || '').trim();
  const apipa = analyzeApipaAddress(cleanIp);
  if (apipa.isCloudMetadata) {
    throw new Error('SECURITY_VIOLATION: Cloud metadata address 169.254.169.254 is blocked by SSRF policy.');
  }

  const netInfo = getPhysicalNetworkInfo();
  const localIp = netInfo.localIp || '192.168.31.89';
  const gatewayIp = netInfo.defaultGateway || '192.168.31.1';
  const subnetCidr = netInfo.subnetCidr || '192.168.31.0/24';
  const subnetPrefix = gatewayIp.split('.').slice(0, 3).join('.');

  // 1. Check Gateway Reachability from Operator Workstation
  const gwPing = await pingHost(gatewayIp, { timeoutMs: 1000 }).catch(() => ({ alive: false, timeMs: null }));
  const gatewayReachable = Boolean(gwPing && (gwPing.alive || gwPing.success || gwPing.rttMs !== null));
  const gatewayRttMs = gwPing?.rttMs ?? gwPing?.timeMs ?? 2;

  // 2. Check Target Device Reachability & Printer/Office Ports (unless it's an APIPA 169.254.x.x address)
  let targetPing = { alive: false, rttMs: null };
  let portResults = [];
  const sameSubnet = cleanIp.startsWith(subnetPrefix + '.');

  if (!apipa.isApipa && net.isIP(cleanIp)) {
    const pRes = await pingHost(cleanIp, { timeoutMs: 1000 }).catch(() => ({ alive: false }));
    targetPing = {
      alive: Boolean(pRes && (pRes.alive || pRes.success)),
      rttMs: pRes?.rttMs ?? pRes?.timeMs ?? null
    };
    const portsToTest = [9100, 631, 515, 80, 443, 445, 5060];
    portResults = await Promise.all(portsToTest.map((pt) => probeTcpPortQuick(cleanIp, pt, 700)));
  }

  const openPorts = portResults.filter((p) => p.open).map((p) => p.port);
  const rstPorts = portResults.filter((p) => p.errorCode === 'ECONNREFUSED').map((p) => p.port);
  const equipmentProfile = classifyOfficeEquipment({
    ip: cleanIp,
    macAddress,
    vendor,
    hostname: deviceName,
    openServices: openPorts
  });

  // 3. Build Visual Connection Path (Smart Mapping)
  const visualConnectionPath = [
    {
      hopNumber: 1,
      nodeId: 'HOP-WORKSTATION',
      name: 'Your Computer (Operator PC)',
      title: 'Your Computer (Operator PC)',
      icon: '💻',
      ip: localIp,
      adapter: netInfo.adapterName || 'Wi-Fi / Ethernet NIC',
      status: 'HEALTHY',
      statusBadge: '● Connected',
      latencyMs: 0,
      plainSummary: `Your computer (${localIp}) network adapter is active and operational.`
    },
    {
      hopNumber: 2,
      nodeId: 'HOP-OFFICE-SWITCH',
      name: 'Office LAN Switch / Wi-Fi Access Point',
      title: 'Office LAN Switch / Wi-Fi Access Point',
      icon: '🔀',
      ip: subnetCidr,
      adapter: 'Layer 2 Office Distribution',
      status: gatewayReachable ? 'HEALTHY' : 'DEGRADED',
      statusBadge: gatewayReachable ? '● Passing Traffic' : '⚠️ Local LAN Issue',
      latencyMs: 1,
      plainSummary: gatewayReachable
        ? `Office switch/Wi-Fi (${subnetCidr}) is forwarding local traffic normally.`
        : 'Your computer cannot reach the local office switch or Wi-Fi access point.'
    },
    {
      hopNumber: 3,
      nodeId: 'HOP-DEFAULT-GATEWAY',
      name: 'Office Router & DHCP Server (Gateway)',
      title: 'Office Router & DHCP Server (Gateway)',
      icon: '🌐',
      ip: gatewayIp,
      adapter: 'DHCP & Internet Gateway',
      status: gatewayReachable ? 'HEALTHY' : 'BROKEN',
      statusBadge: gatewayReachable ? `● Online (${gatewayRttMs} ms)` : '✕ Unreachable',
      latencyMs: gatewayRttMs,
      plainSummary: gatewayReachable
        ? `Office router (${gatewayIp}) is online and responding in ${gatewayRttMs} ms.`
        : `Office router (${gatewayIp}) is not responding to ping.`
    }
  ];

  // Add Hop 4: Target Office Equipment
  let faultScenario = 'HEALTHY_DEVICE';
  let plainLanguageDiagnosis = null;

  if (apipa.isApipa) {
    faultScenario = 'APIPA_SELF_ASSIGNED_IP_169_254';
    const targetTitle = deviceName || equipmentProfile.equipmentLabel || 'Office Device (169.254.x.x)';
    visualConnectionPath.push({
      hopNumber: 4,
      nodeId: 'HOP-TARGET-DEVICE',
      name: targetTitle,
      title: targetTitle,
      icon: equipmentProfile.icon || '⚠️',
      ip: cleanIp,
      adapter: equipmentProfile.equipmentBrand,
      status: 'BROKEN',
      statusBadge: '✕ APIPA Error IP (169.254.x.x)',
      latencyMs: null,
      linkBreakReason: 'DHCP Lease Failure — Device isolated on 169.254.x.x emergency address',
      plainSummary: `Connection breaks here: The device assigned itself temporary error address ${cleanIp} instead of a valid ${subnetPrefix}.x office IP.`
    });

    const probDesc = `The office ${deviceTypeHint === 'PRINTER' ? 'printer' : 'device'} (${cleanIp}) could not get a valid IP address from the office router (${gatewayIp}) and assigned itself a temporary emergency address starting with 169.254. Because it is on this emergency address, computers on the normal office network (${subnetCidr}) cannot communicate with it or print to it.`;
    const causeDesc = [
      `The device tried to request an IP address using DHCP when it powered on, but never received an answer from the office router (${gatewayIp}).`,
      'Common causes: (1) The network cable or Wi-Fi connection on the printer is loose or plugged into a wall jack on the wrong VLAN, (2) The office router ran out of available DHCP IP addresses (DHCP pool exhaustion), or (3) The printer turned on before the office switch finished booting.'
    ].join(' ');
    const fixSteps = [
      `Step 1 (Check Physical Cable / Wi-Fi): Verify the Ethernet cable is firmly clicked into both the printer and the wall jack (check for solid green/amber link lights), or confirm the printer is connected to the main office Wi-Fi SSID.`,
      `Step 2 (Restart Network Lease on Device): On the printer's front touchscreen/menu, go to Settings -> Network -> TCP/IP -> Set IPv4 to "Automatic (DHCP)" or power-cycle the printer off for 15 seconds and turn it back on.`,
      `Step 3 (Verify Office Router DHCP Pool): Open the office router (${gatewayIp}) DHCP settings and ensure the DHCP pool (${subnetPrefix}.2 – ${subnetPrefix}.254) has free leases available.`,
      `Step 4 (Assign a Static Office IP for Permanent Stability): Once reconnected, assign the printer a permanent reserved IP (for example, ${subnetPrefix}.250 with Subnet Mask 255.255.255.0 and Default Gateway ${gatewayIp}) so it never loses its address again.`
    ];

    plainLanguageDiagnosis = {
      severity: 'CRITICAL',
      badge: 'DHCP / APIPA Address Fault (169.254.x.x)',
      whatTheProblemIs: probDesc,
      whatIsHappening: probDesc,
      whyItHappened: causeDesc,
      whyDidThisHappen: causeDesc,
      stepByStepFixPlan: fixSteps,
      howToFixIt: fixSteps,
      recommendedScript: 'flush-dns-cache.ps1'
    };
  } else if (!sameSubnet && net.isIP(cleanIp) && !cleanIp.startsWith('127.')) {
    faultScenario = 'SUBNET_OR_VLAN_MISMATCH';
    const targetTitle = deviceName || equipmentProfile.equipmentLabel;
    visualConnectionPath.push({
      hopNumber: 4,
      nodeId: 'HOP-TARGET-DEVICE',
      name: targetTitle,
      title: targetTitle,
      icon: equipmentProfile.icon || '🌐',
      ip: cleanIp,
      adapter: equipmentProfile.equipmentBrand,
      status: targetPing.alive || openPorts.length > 0 ? 'WARNING' : 'BROKEN',
      statusBadge: targetPing.alive || openPorts.length > 0 ? '⚠️ Cross-Subnet Reachable' : '✕ Subnet Unreachable',
      latencyMs: targetPing.rttMs,
      linkBreakReason: `Device IP (${cleanIp}) is outside local office subnet (${subnetCidr})`,
      plainSummary: `Device is on a different subnet (${cleanIp}) than your office network (${subnetCidr}).`
    });

    const probDesc = `The device (${cleanIp}) is configured with an IP address from a different network than your office subnet (${subnetCidr}).`;
    const causeDesc = `The device either has an old static IP address hardcoded from a previous office location/router, or it is connected to an isolated guest/VLAN network.`;
    const fixSteps = [
      `Step 1: Open the network configuration menu on the device (${cleanIp}) and check if Static IP is enabled.`,
      `Step 2: Change the IP setting to "DHCP / Automatic" or update its static IP to match your office network (${subnetPrefix}.x, Gateway ${gatewayIp}).`,
      `Step 3: Re-scan the network in EJII Ultra IP Scanner to confirm the device appears on ${subnetCidr}.`
    ];

    plainLanguageDiagnosis = {
      severity: 'WARNING',
      badge: 'Different Network Subnet / VLAN Mismatch',
      whatTheProblemIs: probDesc,
      whatIsHappening: probDesc,
      whyItHappened: causeDesc,
      whyDidThisHappen: causeDesc,
      stepByStepFixPlan: fixSteps,
      howToFixIt: fixSteps,
      recommendedScript: 'flush-dns-cache.ps1'
    };
  } else if (!targetPing.alive && openPorts.length === 0 && rstPorts.length === 0) {
    faultScenario = 'DEVICE_OFFLINE_OR_DISCONNECTED';
    const targetTitle = deviceName || equipmentProfile.equipmentLabel;
    visualConnectionPath.push({
      hopNumber: 4,
      nodeId: 'HOP-TARGET-DEVICE',
      name: targetTitle,
      title: targetTitle,
      icon: equipmentProfile.icon || '🔌',
      ip: cleanIp,
      adapter: equipmentProfile.equipmentBrand,
      status: 'BROKEN',
      statusBadge: '✕ No Response (Offline)',
      latencyMs: null,
      linkBreakReason: 'No ICMP ping or TCP service response from device',
      plainSummary: `Your computer reaches the office router (${gatewayIp}), but ${cleanIp} is not responding.`
    });

    const probDesc = `Your computer and the office router (${gatewayIp}) are working properly, but the target device (${cleanIp}) is completely unresponsive on the network.`;
    const causeDesc = `The equipment is powered off, in deep sleep mode, unplugged from Ethernet/Wi-Fi, or its IP address changed via DHCP.`;
    const fixSteps = [
      `Step 1: Check if the equipment (${deviceName || cleanIp}) is powered on and awake (press the wake button on the control panel).`,
      `Step 2: Check the Ethernet cable or Wi-Fi status light on the device.`,
      `Step 3: Run a full subnet scan in EJII Ultra IP Scanner (View 3) and filter by Brand/MAC (${macAddress || vendor || 'Printer'}) to see if the router assigned it a new IP address.`
    ];

    plainLanguageDiagnosis = {
      severity: 'CRITICAL',
      badge: 'Equipment Offline or Disconnected from LAN',
      whatTheProblemIs: probDesc,
      whatIsHappening: probDesc,
      whyItHappened: causeDesc,
      whyDidThisHappen: causeDesc,
      stepByStepFixPlan: fixSteps,
      howToFixIt: fixSteps,
      recommendedScript: 'flush-dns-cache.ps1'
    };
  } else if ((targetPing.alive || rstPorts.length > 0) && deviceTypeHint === 'PRINTER' && !openPorts.includes(9100) && !openPorts.includes(631) && !openPorts.includes(515)) {
    faultScenario = 'PRINTER_ONLINE_BUT_PRINT_SERVICE_CLOSED';
    const targetTitle = deviceName || 'Office Printer';
    visualConnectionPath.push({
      hopNumber: 4,
      nodeId: 'HOP-TARGET-DEVICE',
      name: targetTitle,
      title: targetTitle,
      icon: '🖨️',
      ip: cleanIp,
      adapter: equipmentProfile.equipmentBrand,
      status: 'DEGRADED',
      statusBadge: '⚠️ Network Online / Print Port Closed',
      latencyMs: targetPing.rttMs || 2,
      linkBreakReason: 'Device responds on network, but printing ports (9100 / 631 / 515) refused connection',
      plainSummary: `The device (${cleanIp}) is connected to the network, but its printing service port is closed or stalled.`
    });

    const probDesc = `The printer (${cleanIp}) is connected to the office network and responds to network checks, but it is refusing print jobs on standard printing ports (RAW Port 9100 / IPP Port 631).`;
    const causeDesc = `Either the printer's internal print server hung (or has a paper/toner error blocking the queue), or the Windows Print Spooler service on the PC is stuck.`;
    const fixSteps = [
      `Step 1: Check the printer's physical display screen for paper jams, empty tray alerts, or error codes.`,
      `Step 2: In EJII View 4 (PC Automation) or View 5 (Core Diagnostics), click "Restart Print Spooler Service & Clear Queue" to clear stuck jobs on the PC.`,
      `Step 3: Power-cycle the printer off and back on to restart its internal JetDirect (Port 9100) / IPP (Port 631) print service.`
    ];

    plainLanguageDiagnosis = {
      severity: 'WARNING',
      badge: 'Printer Network Online — Print Service / Spooler Stalled',
      whatTheProblemIs: probDesc,
      whatIsHappening: probDesc,
      whyItHappened: causeDesc,
      whyDidThisHappen: causeDesc,
      stepByStepFixPlan: fixSteps,
      howToFixIt: fixSteps,
      recommendedScript: 'restart-print-spooler.ps1'
    };
  } else {
    faultScenario = 'HEALTHY_OPERATIONAL';
    const targetTitle = deviceName || equipmentProfile.equipmentLabel;
    visualConnectionPath.push({
      hopNumber: 4,
      nodeId: 'HOP-TARGET-DEVICE',
      name: targetTitle,
      title: targetTitle,
      icon: equipmentProfile.icon || '💻',
      ip: cleanIp,
      adapter: equipmentProfile.equipmentBrand,
      status: 'HEALTHY',
      statusBadge: `● Online (${targetPing.rttMs || 1} ms)`,
      latencyMs: targetPing.rttMs || 1,
      plainSummary: `Equipment (${cleanIp}) is online and responding cleanly (${openPorts.length > 0 ? 'Open ports: ' + openPorts.join(', ') : 'ICMP verified'}).`
    });

    const probDesc = `No network connectivity problem detected. The device (${cleanIp}) is reachable on the office network.`;
    const causeDesc = `All network hops from your computer (${localIp}) through the office switch and router (${gatewayIp}) to ${cleanIp} are operating normally.`;
    const fixSteps = [
      `Step 1: If a user still cannot print or connect, clear the local Windows Print Spooler queue in View 4 ("Restart Print Spooler Service & Clear Queue.bat").`,
      `Step 2: Verify the user's application is pointing to IP address ${cleanIp}.`
    ];

    plainLanguageDiagnosis = {
      severity: 'HEALTHY',
      badge: 'Equipment Online & Healthy',
      whatTheProblemIs: probDesc,
      whatIsHappening: probDesc,
      whyItHappened: causeDesc,
      whyDidThisHappen: causeDesc,
      stepByStepFixPlan: fixSteps,
      howToFixIt: fixSteps,
      recommendedScript: 'ping-diagnostic.ps1'
    };
  }

  try {
    const { equipmentInventoryRepository } = require('../../db/equipment-inventory-repository');
    if (equipmentInventoryRepository) {
      equipmentInventoryRepository.upsertEquipmentRecord({
        macAddress: equipmentProfile.digitalSignatureMac !== 'Unresolved (No L2 ARP)' ? equipmentProfile.digitalSignatureMac : null,
        currentIp: cleanIp,
        hostname: deviceName || equipmentProfile.equipmentLabel,
        equipmentType: equipmentProfile.equipmentType,
        equipmentBrand: equipmentProfile.equipmentBrand,
        openPorts: openPorts.join(','),
        source: 'OFFICE_DEVICE_DIAGNOSTICS'
      });
    }
  } catch (_) {}

  // Application-Layer Printer / HTTP Banner Introspection
  const applicationProtocolBanners = {};
  const bannerCandidatePorts = openPorts.filter((p) => [80, 443, 631, 8080, 9100].includes(p));
  for (const bPort of bannerCandidatePorts) {
    try {
      const banner = await probeOfficeApplicationBanner(cleanIp, bPort, 650);
      if (banner && banner.statusCode > 0) {
        applicationProtocolBanners[bPort] = banner;
      }
    } catch (_) {}
  }

  // Closed-Loop Re-Verification Snapshot Diff
  const prev = previousDiagnosisMap.get(cleanIp) || null;
  let stateChange = 'UNCHANGED';
  if (prev) {
    if (prev.faultScenario !== 'HEALTHY_OPERATIONAL' && faultScenario === 'HEALTHY_OPERATIONAL') {
      stateChange = 'RESOLVED';
    } else if (openPorts.length > (prev.openPorts || []).length) {
      stateChange = 'IMPROVED';
    } else if (openPorts.length < (prev.openPorts || []).length || (prev.faultScenario === 'HEALTHY_OPERATIONAL' && faultScenario !== 'HEALTHY_OPERATIONAL')) {
      stateChange = 'DEGRADED';
    } else {
      stateChange = 'UNCHANGED';
    }
  }

  const fixedAnomalies = prev && prev.faultScenario !== faultScenario && faultScenario === 'HEALTHY_OPERATIONAL'
    ? [`Resolved: ${prev.faultScenario}`]
    : [];
  const newAnomalies = prev && prev.faultScenario !== faultScenario && faultScenario !== 'HEALTHY_OPERATIONAL' && prev.faultScenario === 'HEALTHY_OPERATIONAL'
    ? [`New fault detected: ${faultScenario}`]
    : [];
  const deltaSummary = prev
    ? `State change: ${stateChange} (Scenario: ${prev.faultScenario} → ${faultScenario}, open ports: ${openPorts.length})`
    : 'Initial baseline diagnosis recorded.';

  const reverificationDiff = prev
    ? {
        hasPreviousSnapshot: true,
        previousState: prev.faultScenario,
        currentState: faultScenario,
        previousDiagnosedAt: prev.diagnosedAt,
        previousScenario: prev.faultScenario,
        currentScenario: faultScenario,
        statusImproved: stateChange === 'RESOLVED' || stateChange === 'IMPROVED',
        stateChange,
        deltaSummary,
        fixedAnomalies,
        newAnomalies,
        newlyOpenedPorts: openPorts.filter((p) => !(prev.openPorts || []).includes(p)),
        hopsRecovered: visualConnectionPath
          .filter((h, idx) => h.status === 'HEALTHY' && prev.hopStatuses?.[idx] && prev.hopStatuses[idx] !== 'HEALTHY')
          .map((h) => h.title)
      }
    : {
        hasPreviousSnapshot: false,
        previousState: null,
        currentState: faultScenario,
        statusImproved: false,
        stateChange: 'INITIAL',
        deltaSummary,
        fixedAnomalies: [],
        newAnomalies: [],
        newlyOpenedPorts: [],
        hopsRecovered: []
      };

  if (previousDiagnosisMap.size >= MAX_PREVIOUS_DIAGNOSES) {
    const firstKey = previousDiagnosisMap.keys().next().value;
    previousDiagnosisMap.delete(firstKey);
  }

  previousDiagnosisMap.set(cleanIp, {
    diagnosedAt: new Date().toISOString(),
    faultScenario,
    openPorts,
    hopStatuses: visualConnectionPath.map((h) => h.status)
  });

  return {
    diagnosedAt: new Date().toISOString(),
    targetIp: cleanIp,
    faultScenario,
    apipaAnalysis: apipa,
    equipmentProfile,
    visualConnectionPath,
    plainLanguageDiagnosis,
    applicationProtocolBanners,
    reverificationDiff,
    technicalTelemetry: {
      localWorkstationIp: localIp,
      officeSubnetCidr: subnetCidr,
      defaultGatewayIp: gatewayIp,
      gatewayReachable,
      gatewayRttMs,
      targetPingAlive: targetPing.alive,
      targetRttMs: targetPing.rttMs,
      openPorts,
      refusedPorts: rstPorts
    }
  };
}

/**
 * Inspects local Windows Print Spooler service, installed printers, ports, and job queues.
 * Identifies stuck jobs and problematic WSD ports (prone to disconnects on IP shifts).
 */
async function inspectLocalWindowsPrintSpooler(timeoutMs = 3500) {
  if (process.platform !== 'win32') {
    return {
      available: false,
      spoolerServiceStatus: 'N/A_NON_WINDOWS',
      printers: [],
      ports: [],
      stuckJobsCount: 0,
      wsdPortWarning: false,
      plainSummary: 'Print spooler inspection is only available on Windows operating systems.'
    };
  }

  const { execFile } = require('child_process');
  const psCmd = `
    $ErrorActionPreference = 'SilentlyContinue';
    $svc = Get-Service -Name Spooler | Select-Object -Property Status, StartType;
    $printers = Get-Printer | Select-Object -Property Name, DriverName, PortName, PrinterStatus, JobCount;
    $jobs = Get-PrintJob -PrinterName * | Select-Object -Property Id, DocumentName, JobStatus, TotalPages;
    @{
      SpoolerStatus = $svc.Status.ToString();
      StartType = $svc.StartType.ToString();
      Printers = @($printers);
      Jobs = @($jobs);
    } | ConvertTo-Json -Depth 3 -Compress
  `;

  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', psCmd],
      { timeout: timeoutMs, windowsHide: true },
      (err, stdout, stderr) => {
        if (err || !stdout || !stdout.trim()) {
          return resolve({
            available: true,
            spoolerServiceStatus: 'UNKNOWN_OR_TIMEOUT',
            printers: [],
            ports: [],
            stuckJobsCount: 0,
            wsdPortWarning: false,
            plainSummary: 'Unable to query Print Spooler via PowerShell (query timed out or service offline).'
          });
        }

        try {
          const parsed = JSON.parse(stdout.trim());
          const spoolerStatus = parsed.SpoolerStatus || 'Unknown';
          const rawPrinters = Array.isArray(parsed.Printers) ? parsed.Printers : (parsed.Printers ? [parsed.Printers] : []);
          const rawJobs = Array.isArray(parsed.Jobs) ? parsed.Jobs : (parsed.Jobs ? [parsed.Jobs] : []);

          const printers = rawPrinters.map(p => ({
            name: p.Name || 'Unnamed Printer',
            driverName: p.DriverName || 'Generic',
            portName: p.PortName || 'Unknown',
            printerStatus: p.PrinterStatus || 'Normal',
            jobCount: Number(p.JobCount || 0),
            isWsdPort: String(p.PortName || '').toUpperCase().startsWith('WSD-')
          }));

          const wsdPortWarning = printers.some(p => p.isWsdPort);
          const stuckJobsCount = rawJobs.length;

          let summary = `Spooler service is ${spoolerStatus}. Discovered ${printers.length} local printer(s).`;
          if (stuckJobsCount > 0) {
            summary += ` Warning: ${stuckJobsCount} print job(s) pending or stuck in spooler queue.`;
          }
          if (wsdPortWarning) {
            summary += ` Advisory: Printer uses WSD port, which may fail if device IP changes. Use Standard TCP/IP port for reliable enterprise printing.`;
          }

          resolve({
            available: true,
            spoolerServiceStatus: spoolerStatus,
            printers,
            ports: printers.map(p => p.portName),
            stuckJobsCount,
            wsdPortWarning,
            plainSummary: summary
          });
        } catch (_) {
          resolve({
            available: true,
            spoolerServiceStatus: 'PARSE_ERROR',
            printers: [],
            ports: [],
            stuckJobsCount: 0,
            wsdPortWarning: false,
            plainSummary: 'PowerShell output parsing failed.'
          });
        }
      }
    );
  });
}

module.exports = {
  analyzeApipaAddress,
  classifyOfficeEquipment,
  diagnoseOfficeDevice,
  inspectLocalWindowsPrintSpooler,
  probeOfficeApplicationBanner,
  previousDiagnosisMap
};
