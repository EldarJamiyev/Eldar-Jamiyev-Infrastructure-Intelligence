/**
 * EJII Wireshark-Grade AI Packet Explainer & Natural Language Filter Engine
 * Grounded in RFC standards, Bayesian evidentiary reasoning, and empirical wire metrics.
 * Zero-Simulation Mandate: Evaluates physical packet bytes and protocol headers.
 */

'use strict';

const { validateFilter } = require('./filter-compiler');

class PacketExplainEngine {
  /**
   * Produce an exhaustive, Wireshark-expert breakdown of a network frame.
   * @param {Object} frame The dissected frame object
   * @param {Object} context Context including stream state, flow tables, and learned baselines
   * @returns {Object} Structured diagnostic report
   */
  static explain(frame, context = {}) {
    if (!frame) {
      throw new Error('Frame object required for AI explanation.');
    }

    const {
      allFrames = [],
      flowTable = new Map(),
      tcpStreams = new Map(),
      dnsResolutionMap = new Map(),
      ipToDomainCache = new Map()
    } = context;

    const protocol = (frame.protocol || 'UNKNOWN').toUpperCase();
    const srcIp = frame.srcIp || (frame.ipv4?.srcIp) || (frame.ipv6?.srcIp) || '0.0.0.0';
    const dstIp = frame.dstIp || (frame.ipv4?.dstIp) || (frame.ipv6?.dstIp) || '0.0.0.0';
    const srcPort = frame.srcPort ?? frame.tcp?.srcPort ?? frame.udp?.srcPort ?? null;
    const dstPort = frame.dstPort ?? frame.tcp?.dstPort ?? frame.udp?.dstPort ?? null;
    const wireLen = frame.wireLength || frame.length || 0;
    const tcp = frame.tcp || null;
    const udp = frame.udp || null;
    const icmp = frame.icmp || null;
    const dns = frame.dns || null;
    const http = frame.http || null;
    const tls = frame.tls || null;
    const quic = frame.quic || null;
    const arp = frame.arp || null;

    // 1. Target and Hostname Intelligence
    let hostIntelligence = null;
    if (ipToDomainCache.has(dstIp)) {
      hostIntelligence = ipToDomainCache.get(dstIp);
    } else if (dnsResolutionMap.has(dstIp)) {
      hostIntelligence = dnsResolutionMap.get(dstIp);
    } else if (ipToDomainCache.has(srcIp)) {
      hostIntelligence = ipToDomainCache.get(srcIp);
    }

    const resolvedName = hostIntelligence?.domain || hostIntelligence?.hostname || frame.urlIntelligence?.value || null;

    // 2. Layer Analysis Breakdown
    const layers = [];

    // L2: Ethernet
    if (frame.ethernet) {
      layers.push({
        layer: 'Layer 2 (Data Link)',
        protocol: 'Ethernet II',
        summary: `MAC ${frame.ethernet.srcMac} → ${frame.ethernet.dstMac} (EtherType ${frame.ethernet.ethertype})`,
        rfc: 'RFC 894 / IEEE 802.3',
        details: {
          srcMac: frame.ethernet.srcMac,
          dstMac: frame.ethernet.dstMac,
          ethertype: frame.ethernet.ethertype,
          vlanId: frame.ethernet.vlanId || 'Untagged'
        }
      });
    }

    // L3: IP
    if (frame.ipv4) {
      layers.push({
        layer: 'Layer 3 (Network)',
        protocol: 'IPv4',
        summary: `IPv4 ${srcIp} → ${dstIp} (TTL: ${frame.ipv4.ttl}, Total Len: ${frame.ipv4.totalLength || wireLen} B)`,
        rfc: 'RFC 791',
        details: {
          version: 4,
          headerLength: frame.ipv4.ihl || 20,
          ttl: frame.ipv4.ttl,
          identification: frame.ipv4.identification,
          flags: frame.ipv4.flags || {},
          checksum: frame.ipv4.checksum
        }
      });
    } else if (frame.ipv6) {
      layers.push({
        layer: 'Layer 3 (Network)',
        protocol: 'IPv6',
        summary: `IPv6 ${srcIp} → ${dstIp} (Hop Limit: ${frame.ipv6.hopLimit || 64})`,
        rfc: 'RFC 8200',
        details: {
          version: 6,
          trafficClass: frame.ipv6.trafficClass,
          flowLabel: frame.ipv6.flowLabel
        }
      });
    } else if (arp) {
      layers.push({
        layer: 'Layer 3 (Address Resolution)',
        protocol: 'ARP',
        summary: `ARP ${arp.opcode}: Who has ${arp.targetIp}? Tell ${arp.senderIp} (${arp.senderMac})`,
        rfc: 'RFC 826',
        details: arp
      });
    }

    // L4: Transport
    if (tcp) {
      const flags = tcp.flagNames || [];
      layers.push({
        layer: 'Layer 4 (Transport)',
        protocol: 'TCP',
        summary: `Port ${srcPort} → ${dstPort} [${flags.join(', ')}] Seq=${tcp.seq} Ack=${tcp.ack} Win=${tcp.windowSize}`,
        rfc: 'RFC 793 / RFC 7323',
        details: {
          srcPort,
          dstPort,
          seq: tcp.seq,
          ack: tcp.ack,
          flags,
          windowSize: tcp.windowSize,
          checksum: tcp.checksum,
          headerLength: tcp.headerLengthBytes || 20
        }
      });
    } else if (udp) {
      layers.push({
        layer: 'Layer 4 (Transport)',
        protocol: 'UDP',
        summary: `Port ${srcPort} → ${dstPort} (Length: ${udp.length} B)`,
        rfc: 'RFC 768',
        details: {
          srcPort,
          dstPort,
          length: udp.length,
          checksum: udp.checksum
        }
      });
    } else if (icmp) {
      layers.push({
        layer: 'Layer 4 (Control)',
        protocol: 'ICMP',
        summary: `ICMP Type ${icmp.type} Code ${icmp.code} (${icmp.typeDescription || 'Control Message'})`,
        rfc: 'RFC 792',
        details: icmp
      });
    }

    // L7: Application
    if (tls) {
      layers.push({
        layer: 'Layer 7 (Security / Transport Layer Security)',
        protocol: tls.version || 'TLS',
        summary: `TLS Record ${tls.contentType || 'Handshake'} (SNI: ${tls.sni || 'N/A'}, Cipher: ${tls.cipherSuite || 'Negotiated'})`,
        rfc: 'RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2)',
        details: tls
      });
    } else if (http) {
      layers.push({
        layer: 'Layer 7 (Application)',
        protocol: 'HTTP',
        summary: http.type === 'REQUEST' ? `HTTP ${http.method} ${http.uri} (Host: ${http.host || 'N/A'})` : `HTTP Response ${http.status} ${http.statusText || ''}`,
        rfc: 'RFC 9110 / RFC 9112',
        details: http
      });
    } else if (dns) {
      const q = dns.questions?.[0];
      layers.push({
        layer: 'Layer 7 (Domain Name System)',
        protocol: 'DNS',
        summary: dns.isResponse ? `DNS Response for ${q?.name || 'query'} (${dns.answers?.length || 0} answers)` : `DNS Query for ${q?.name || 'query'} (Type: ${q?.type || 'A'})`,
        rfc: 'RFC 1035',
        details: dns
      });
    } else if (quic) {
      layers.push({
        layer: 'Layer 7 (Encrypted Transport / QUIC)',
        protocol: 'QUIC',
        summary: `QUIC Header ${quic.headerType} (Packet Type: ${quic.packetType || '1-RTT'})`,
        rfc: 'RFC 9000',
        details: quic
      });
    }

    // 3. Anomaly and Red Flag Evaluation
    const anomalies = [];
    let severity = 'NOMINAL';

    // TCP Anomaly Checks
    if (tcp) {
      if (tcp.flags?.rst) {
        anomalies.push({
          type: 'TCP_RST_TERMINATION',
          severity: 'HIGH',
          title: 'TCP Connection Reset by Peer (RST Flag Active)',
          description: `The sending host (${srcIp}:${srcPort}) abruptly aborted or rejected the TCP connection. Common causes: port not listening, firewall intervention, or idle timeout.`
        });
        severity = 'HIGH';
      }

      if (tcp.windowSize === 0) {
        anomalies.push({
          type: 'TCP_ZERO_WINDOW',
          severity: 'CRITICAL',
          title: 'TCP Zero Window Flow Control Freeze',
          description: `Host ${srcIp} advertised a receive window of 0 bytes, signaling that its internal OS TCP buffer is completely full. Transmission is blocked until window update.`
        });
        severity = 'CRITICAL';
      }

      if (frame.tcpAnalysis?.isRetransmission) {
        anomalies.push({
          type: 'TCP_RETRANSMISSION',
          severity: 'MEDIUM',
          title: 'TCP Segment Retransmission Detected',
          description: `This segment carries sequence number ${tcp.seq} which was previously observed in the stream. Suggests wire packet loss, routing blackhole, or excessive jitter.`
        });
        if (severity === 'NOMINAL') severity = 'MEDIUM';
      }

      if (tcp.flags?.syn && !tcp.flags?.ack) {
        // SYN packet
        if (tcp.windowSize < 1024 && tcp.windowSize > 0) {
          anomalies.push({
            type: 'ANOMALOUS_SYN_WINDOW',
            severity: 'LOW',
            title: 'Unusually Low SYN Window Size',
            description: `SYN advertised window size of ${tcp.windowSize} bytes (normal OS baseline is 64240 or 65535). May indicate embedded microcontroller or severe resource limitation.`
          });
        }
      }
    }

    // DNS Anomaly Checks
    if (dns && dns.isResponse) {
      if (dns.rcode === 3 || dns.status === 'NXDOMAIN') {
        anomalies.push({
          type: 'DNS_NXDOMAIN',
          severity: 'MEDIUM',
          title: 'Non-Existent Domain (NXDOMAIN)',
          description: `The upstream DNS resolver reported that the queried domain name does not exist in the DNS root/authoritative zone.`
        });
        if (severity === 'NOMINAL') severity = 'MEDIUM';
      } else if (dns.rcode !== 0) {
        anomalies.push({
          type: 'DNS_ERROR',
          severity: 'MEDIUM',
          title: `DNS Resolution Failure (RCODE: ${dns.rcode})`,
          description: `Upstream DNS server returned error code ${dns.rcode} (e.g. Server Failure or Refused).`
        });
        if (severity === 'NOMINAL') severity = 'MEDIUM';
      }
    }

    // HTTP Security Checks
    if (http && http.type === 'REQUEST') {
      if (dstPort === 80) {
        anomalies.push({
          type: 'UNENCRYPTED_HTTP',
          severity: 'LOW',
          title: 'Unencrypted HTTP Cleartext Transmission',
          description: `HTTP payload is transmitted in cleartext over port 80 without TLS encryption, vulnerable to on-path interception or tampering.`
        });
      }
    }

    // 4. Construct Plain-English Synthesis
    let plainEnglish = '';
    if (arp) {
      plainEnglish = `Address Resolution Protocol broadcast: Host ${arp.senderIp} (${arp.senderMac}) is resolving the physical hardware address for ${arp.targetIp}.`;
    } else if (dns) {
      if (dns.isResponse) {
        const answersStr = (dns.answers || []).map(a => a.ip || a.data || a.cname).filter(Boolean).join(', ');
        plainEnglish = `DNS Name Resolution Reply: The DNS server answered query for "${dns.questions?.[0]?.name || 'host'}" with target addresses [${answersStr || 'None'}].`;
      } else {
        plainEnglish = `DNS Name Lookup: Client ${srcIp} is querying DNS server ${dstIp} to translate domain name "${dns.questions?.[0]?.name || 'host'}" into an IP address.`;
      }
    } else if (tls) {
      const targetHost = tls.sni || resolvedName || dstIp;
      plainEnglish = `Encrypted TLS Session with ${targetHost}: Frame carries ${tls.contentType || 'TLS record'} encrypted traffic over port ${dstPort}.`;
    } else if (quic) {
      const targetHost = resolvedName || dstIp;
      plainEnglish = `Modern UDP-based QUIC / HTTP/3 traffic exchanged with ${targetHost}:${dstPort}. Payload is protected with 1-RTT authenticated encryption.`;
    } else if (tcp) {
      const sId = frame.tcpAnalysis?.streamId ?? frame.streamId;
      const streamText = sId !== undefined && sId !== null ? ` (TCP Stream #${sId})` : '';
      if (tcp.flags?.syn && !tcp.flags?.ack) {
        plainEnglish = `TCP Handshake Initiation: Client ${srcIp} is initiating a new connection to ${dstIp}:${dstPort} with initial sequence number ${tcp.seq}${streamText}.`;
      } else if (tcp.flags?.syn && tcp.flags?.ack) {
        plainEnglish = `TCP Handshake Response: Server ${srcIp} accepted the connection and acknowledged client sequence with SYN-ACK${streamText}.`;
      } else if (tcp.flags?.fin) {
        plainEnglish = `TCP Connection Teardown: Host ${srcIp} has finished sending application data and is gracefully closing its half of the connection (FIN)${streamText}.`;
      } else if (tcp.flags?.rst) {
        plainEnglish = `TCP Hard Reset: Connection on port ${srcPort} ↔ ${dstPort} was forcibly severed by ${srcIp} with a RST flag${streamText}.`;
      } else {
        plainEnglish = `TCP Data / Acknowledgment Transfer: ${wireLen} bytes transferred between ${srcIp}:${srcPort} and ${dstIp}:${dstPort}${streamText}.`;
      }
    } else if (icmp) {
      plainEnglish = `Internet Control Message Protocol: ${icmp.typeDescription || 'Diagnostic message'} exchanged between ${srcIp} and ${dstIp}.`;
    } else {
      plainEnglish = `Raw L2/L3 Network Frame: ${wireLen} bytes observed on physical wire between ${srcIp} and ${dstIp}.`;
    }

    // 5. Recommended Wireshark Display Filter
    let recommendedFilter = '';
    const sId = frame.tcpAnalysis?.streamId ?? frame.streamId;
    if (sId !== undefined && sId !== null) {
      recommendedFilter = `tcp.stream == ${sId}`;
    } else if (srcIp && dstIp && srcPort && dstPort) {
      recommendedFilter = `(ip.src == ${srcIp} && ip.dst == ${dstIp} && tcp.port == ${dstPort}) || (ip.src == ${dstIp} && ip.dst == ${srcIp} && tcp.port == ${srcPort})`;
    } else if (srcIp && dstIp) {
      recommendedFilter = `ip.addr == ${srcIp} && ip.addr == ${dstIp}`;
    } else {
      recommendedFilter = `frame.number == ${frame.frameNumber}`;
    }

    // 6. Actionable Next Steps / Engineering Remediation
    const remediation = [];
    if (anomalies.some(a => a.type === 'TCP_RST_TERMINATION')) {
      remediation.push({
        step: 1,
        action: 'Inspect Target Service Availability',
        detail: `Run 'Test-NetConnection -ComputerName ${dstIp} -Port ${dstPort}' or netstat to verify the destination service is actively listening on port ${dstPort}.`
      });
      remediation.push({
        step: 2,
        action: 'Review Firewall and EDR Drops',
        detail: `Check Windows Filtering Platform (WFP) or hardware firewall event logs for active drop/reject rules matching ${srcIp} → ${dstIp}:${dstPort}.`
      });
    } else if (anomalies.some(a => a.type === 'TCP_RETRANSMISSION')) {
      remediation.push({
        step: 1,
        action: 'Measure Path MTU and Hop Latency',
        detail: `Execute ICMP ping sweep with Don't Fragment flag: 'ping -f -l 1472 ${dstIp}' to identify MTU blackholes along the route.`
      });
      remediation.push({
        step: 2,
        action: 'Monitor Wire Loss Counters',
        detail: `Inspect Npcap and NIC dropped packet counters to confirm whether loss is happening in local OS queue or upstream ISP transit.`
      });
    } else {
      remediation.push({
        step: 1,
        action: 'Stream Conversation Tracking',
        detail: `Apply recommended display filter '${recommendedFilter}' or click 'Follow Stream' to inspect full bidirectional application conversation.`
      });
    }

    return {
      success: true,
      frameNumber: frame.frameNumber,
      timestamp: frame.timestamp,
      protocol,
      wireLength: wireLen,
      endpoints: {
        source: `${srcIp}${srcPort ? ':' + srcPort : ''}`,
        destination: `${dstIp}${dstPort ? ':' + dstPort : ''}`,
        resolvedTarget: resolvedName
      },
      plainEnglish,
      severity,
      layers,
      anomalies,
      recommendedFilter,
      remediation,
      rfcStandards: layers.map(l => l.rfc).filter(Boolean)
    };
  }

  /**
   * Translate a natural language query into a valid Wireshark AST display filter.
   * @param {string} prompt Natural language request
   * @returns {Object} { filter: string, valid: boolean, explanation: string }
   */
  static translateNaturalLanguageToFilter(prompt = '') {
    const raw = String(prompt || '').trim();
    if (!raw) {
      return { filter: '', valid: true, explanation: 'Empty filter expression.' };
    }

    const lower = raw.toLowerCase();
    let filter = '';
    let explanation = '';

    // Regex matchers for IP addresses and ports
    const ipMatch = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    const portMatch = raw.match(/\bport\s*(\d+)\b/i) || raw.match(/:(\d+)\b/);
    const domainMatch = raw.match(/\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:gov\.az|az|com|net|org|io|local))\b/i);

    // 1. Specific Anomaly / Protocol Pattern Mappings
    if (lower.includes('reset') || lower.includes('rst') || lower.includes('rejected')) {
      filter = 'tcp.flags.reset == 1';
      explanation = 'Filters for all packets where the TCP RST (Reset) flag is set to 1.';
    } else if (lower.includes('retrans') || lower.includes('lost packet') || lower.includes('dropped')) {
      filter = 'tcp.analysis.retransmission';
      explanation = 'Filters for packets identified by the TCP stream analyzer as retransmissions.';
    } else if (lower.includes('syn-ack') || lower.includes('syn ack')) {
      filter = 'tcp.flags.syn == 1 && tcp.flags.ack == 1';
      explanation = 'Filters for second step of the TCP 3-way handshake (SYN+ACK).';
    } else if (lower.includes('syn') && !lower.includes('ack')) {
      filter = 'tcp.flags.syn == 1 && tcp.flags.ack == 0';
      explanation = 'Filters for TCP connection initiation packets (SYN without ACK).';
    } else if (lower.includes('zero window') || lower.includes('window full')) {
      filter = 'tcp.window_size == 0';
      explanation = 'Filters for TCP packets advertising a zero receive window.';
    } else if (lower.includes('tls handshake') || lower.includes('client hello') || lower.includes('clienthello')) {
      filter = 'tls.handshake.type == 1';
      explanation = 'Filters for TLS ClientHello handshake messages.';
    } else if (lower.includes('tls') || lower.includes('ssl') || lower.includes('https')) {
      filter = 'tls || tcp.port == 443';
      explanation = 'Filters for TLS records or traffic targeting TCP port 443.';
    } else if (lower.includes('http error') || lower.includes('404') || lower.includes('500') || lower.includes('bad request')) {
      filter = 'http.response.code >= 400';
      explanation = 'Filters for HTTP responses with status code 400 or higher (client/server errors).';
    } else if (lower.includes('http')) {
      filter = 'http || tcp.port == 80';
      explanation = 'Filters for cleartext HTTP application traffic or port 80.';
    } else if (lower.includes('dns quer') || lower.includes('dns lookup')) {
      if (domainMatch) {
        filter = `dns.qry.name contains "${domainMatch[1]}"`;
        explanation = `Filters for DNS queries containing target domain "${domainMatch[1]}".`;
      } else {
        filter = 'dns.flags.response == 0';
        explanation = 'Filters for DNS standard query requests.';
      }
    } else if (lower.includes('dns')) {
      filter = 'dns || udp.port == 53';
      explanation = 'Filters for Domain Name System (DNS) traffic.';
    } else if (lower.includes('quic') || lower.includes('http/3') || lower.includes('http3')) {
      filter = 'quic || (udp.port == 443 && frame.len > 80)';
      explanation = 'Filters for QUIC / HTTP/3 encrypted UDP frames on port 443.';
    } else if (lower.includes('arp') || lower.includes('mac address lookup')) {
      filter = 'arp';
      explanation = 'Filters for Address Resolution Protocol (ARP) packets.';
    } else if (lower.includes('icmp') || lower.includes('ping')) {
      filter = 'icmp';
      explanation = 'Filters for Internet Control Message Protocol (ICMP) echo and control packets.';
    } else if (lower.includes('large packet') || lower.includes('jumbo') || lower.includes('big frame')) {
      filter = 'frame.len > 1400';
      explanation = 'Filters for large frames exceeding 1400 bytes.';
    }

    // 2. Combine with IP Address if specified
    if (ipMatch) {
      const ip = ipMatch[0];
      if (lower.includes('from') || lower.includes('src') || lower.includes('source')) {
        filter = filter ? `${filter} && ip.src == ${ip}` : `ip.src == ${ip}`;
      } else if (lower.includes('to') || lower.includes('dst') || lower.includes('dest')) {
        filter = filter ? `${filter} && ip.dst == ${ip}` : `ip.dst == ${ip}`;
      } else {
        filter = filter ? `${filter} && ip.addr == ${ip}` : `ip.addr == ${ip}`;
      }
      explanation += ` Scoped to IP address ${ip}.`;
    }

    // 3. Combine with Port if specified
    if (portMatch) {
      const port = portMatch[1];
      filter = filter ? `${filter} && (tcp.port == ${port} || udp.port == ${port})` : `tcp.port == ${port} || udp.port == ${port}`;
      explanation += ` Scoped to port ${port}.`;
    }

    // Fallback if no specific rule matched
    if (!filter) {
      // If user typed raw field expression, attempt to preserve it
      if (raw.includes('==') || raw.includes('>') || raw.includes('<') || raw.includes('contains') || raw.includes('&&') || raw.includes('||')) {
        filter = raw;
        explanation = 'Direct Wireshark display filter passed through.';
      } else {
        filter = `frame contains "${raw}"`;
        explanation = `Fallback string search for "${raw}" across frame payloads.`;
      }
    }

    // Validate the generated filter against the AST compiler
    const validation = validateFilter(filter);
    return {
      success: true,
      query: raw,
      filter,
      valid: validation.valid,
      error: validation.error || null,
      explanation
    };
  }
}

module.exports = {
  PacketExplainEngine
};
