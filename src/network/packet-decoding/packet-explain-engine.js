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
        capturedLength: frame.capturedLength || wireLen,
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
        rfcStandards: layers.map(l => l.rfc).filter(Boolean),
        // Comprehensive Field-Level Citations across all OSI Layers (Task 5)
        fieldCitations: {
          frameNumber: frame.frameNumber,
          timestamp: frame.timestamp,
          wireLengthBytes: wireLen,
          capturedLengthBytes: frame.capturedLength || wireLen,
          l2Ethernet: frame.ethernet ? {
            sourceMac: frame.ethernet.srcMac,
            destMac: frame.ethernet.dstMac,
            etherType: frame.ethernet.ethertype,
            vlanId: frame.ethernet.vlanId || null
          } : null,
          l3Network: frame.ipv4 ? {
            version: 4,
            sourceIp: frame.ipv4.srcIp || srcIp,
            destIp: frame.ipv4.dstIp || dstIp,
            ttl: frame.ipv4.ttl,
            headerLengthBytes: frame.ipv4.ihl || 20,
            totalLengthBytes: frame.ipv4.totalLength || wireLen,
            identification: frame.ipv4.identification,
            flags: frame.ipv4.flags || {},
            checksum: frame.ipv4.checksum
          } : (frame.ipv6 ? {
            version: 6,
            sourceIp: frame.ipv6.srcIp || srcIp,
            destIp: frame.ipv6.dstIp || dstIp,
            hopLimit: frame.ipv6.hopLimit || 64,
            trafficClass: frame.ipv6.trafficClass,
            flowLabel: frame.ipv6.flowLabel
          } : (arp ? {
            protocol: 'ARP',
            opcode: arp.opcode,
            senderIp: arp.senderIp,
            senderMac: arp.senderMac,
            targetIp: arp.targetIp,
            targetMac: arp.targetMac
          } : null)),
          l4Transport: tcp ? {
            protocol: 'TCP',
            sourcePort: srcPort,
            destPort: dstPort,
            sequenceNumber: tcp.seq,
            ackNumber: tcp.ack,
            windowSize: tcp.windowSize,
            flags: tcp.flags || {},
            flagNames: tcp.flagNames || [],
            checksum: tcp.checksum,
            headerLengthBytes: tcp.headerLengthBytes || 20,
            streamId: frame.tcpAnalysis?.streamId ?? frame.streamId ?? null
          } : (udp ? {
            protocol: 'UDP',
            sourcePort: srcPort,
            destPort: dstPort,
            lengthBytes: udp.length,
            checksum: udp.checksum
          } : (icmp ? {
            protocol: 'ICMP',
            type: icmp.type,
            code: icmp.code,
            description: icmp.typeDescription || null
          } : null)),
          l7Application: tls ? {
            protocol: tls.version || 'TLS',
            contentType: tls.contentType || 'Application Data',
            sni: tls.sni || null,
            cipherSuite: tls.cipherSuite || null
          } : (http ? {
            protocol: 'HTTP',
            type: http.type,
            method: http.method || null,
            uri: http.uri || null,
            statusCode: http.status || null,
            host: http.host || null
          } : (dns ? {
            protocol: 'DNS',
            isResponse: Boolean(dns.isResponse),
            questions: dns.questions || [],
            answers: dns.answers || [],
            rcode: dns.rcode ?? null
          } : (quic ? {
            protocol: 'QUIC',
            headerType: quic.headerType,
            packetType: quic.packetType || null
          } : null)))
        },
        // Physical Wire Boundary: Cleartext Headers vs Encrypted TLS 1.3 Payload (Task 5)
        encryptionBoundary: {
          isEncryptedSession: Boolean(tls || quic),
          protocol: tls ? (tls.version || 'TLS 1.3') : (quic ? 'QUIC' : 'CLEARTEXT'),
          standard: (tls?.version === 'TLSv1.3' || tls?.version === 'TLS 1.3') ? 'RFC 8446 (TLS 1.3)' : (tls ? 'RFC 5246 (TLS 1.2)' : 'N/A'),
          observableCleartextHeaders: [
            `Layer 2 Ethernet: Source MAC (${frame.ethernet?.srcMac || 'observable'}), Destination MAC (${frame.ethernet?.dstMac || 'observable'})`,
            `Layer 3 IP: Source IP (${srcIp}), Destination IP (${dstIp}), TTL, Header Length, Identification`,
            `Layer 4 TCP: Source Port (${srcPort}), Destination Port (${dstPort}), Seq (${tcp?.seq}), Ack (${tcp?.ack}), Window (${tcp?.windowSize}), Flags (${(tcp?.flagNames || []).join(',') || 'none'})`,
            `Layer 7 TLS Record Header: ContentType (${tls?.contentType || 'Application Data'}), Record Version (${tls?.version || 'TLS'}), Record Length`
          ].concat(tls?.sni ? [`Layer 7 TLS ClientHello Extension: SNI Server Name Indication ("${tls.sni}") observable in pre-handshake hello`] : []),
          encryptedPayloadBoundary: (tls || quic) ? {
            isOpaqueCiphertext: true,
            cipherSuite: tls?.cipherSuite || 'AEAD (Authenticated Encryption with Associated Data)',
            explanation: (tls?.version === 'TLSv1.3' || tls?.version === 'TLS 1.3')
              ? 'TLS 1.3 AEAD Encrypted Payload (RFC 8446): All inner application data, encrypted extensions, certificate messages, and HTTP/2 or HTTP/3 frames are cryptographically opaque on the physical wire. Cleartext packet payload cannot be recovered or inspected without ephemeral forward-secret session keys (Zero-Simulation Integrity).'
              : 'TLS Encrypted Payload (RFC 5246): Application data payload is symmetric ciphertext (AES-GCM / AES-CBC) and cannot be decrypted without private session keys.'
          } : {
            isOpaqueCiphertext: false,
            explanation: 'Cleartext Transmission: Application payload is transmitted unencrypted and fully observable on the physical wire.'
          }
        }
      };
  }

  /**
   * Alias for explain() to satisfy external contract callers
   */
  static explainPacket(frame, context = {}) {
    return this.explain(frame, context);
  }

  /**
   * Translate a natural language query into a valid Wireshark AST display filter.
   * Supports multi-condition combinations: IPs, ports, protocols, TCP flags (SYN/ACK/RST/FIN/PSH),
   * anomalies, and latency/length thresholds (Task 5).
   * @param {string} prompt Natural language request
   * @returns {Object} { filter: string, valid: boolean, explanation: string }
   */
  static translateNaturalLanguageToFilter(prompt = '') {
    const raw = String(prompt || '').trim();
    if (!raw) {
      return { filter: '', valid: true, explanation: 'Empty filter expression.' };
    }

    const lower = raw.toLowerCase();

    // If user provided a raw Wireshark display filter expression (e.g. contains ==, &&, ||, contains), check it directly
    if (raw.includes('==') || raw.includes('>') || raw.includes('<') || raw.includes('!=') || (raw.includes('&&') && raw.includes('.'))) {
      const v = validateFilter(raw);
      if (v.valid) {
        return {
          success: true,
          query: raw,
          filter: raw,
          valid: true,
          error: null,
          explanation: 'Direct Wireshark display filter validated and applied directly.'
        };
      }
    }

    const conditions = [];
    const explanations = [];

    // 1. TCP Flags & Special States
    if (lower.includes('syn-ack') || lower.includes('syn ack')) {
      conditions.push('tcp.flags.syn == 1 && tcp.flags.ack == 1');
      explanations.push('TCP 3-way handshake SYN-ACK response packets');
    } else {
      if (lower.includes('syn') && !lower.includes('ack') && !lower.includes('async')) {
        conditions.push('tcp.flags.syn == 1 && tcp.flags.ack == 0');
        explanations.push('TCP connection initiation SYN packets');
      } else if (lower.includes('syn')) {
        conditions.push('tcp.flags.syn == 1');
        explanations.push('TCP SYN flag set');
      }
      if (lower.includes('ack') && !lower.includes('syn') && !lower.includes('dup ack') && !lower.includes('duplicate ack') && !lower.includes('pack')) {
        conditions.push('tcp.flags.ack == 1');
        explanations.push('TCP ACK flag set');
      }
    }

    if (lower.includes('reset') || lower.includes('rst') || lower.includes('rejected')) {
      conditions.push('tcp.flags.reset == 1');
      explanations.push('TCP connection reset (RST flag)');
    }

    if (lower.includes('fin') && !lower.includes('find') && !lower.includes('defined') && !lower.includes('finish')) {
      conditions.push('tcp.flags.fin == 1');
      explanations.push('TCP connection graceful termination (FIN flag)');
    }

    if (lower.includes('psh') || lower.includes('push flag') || lower.includes('push packet')) {
      conditions.push('tcp.flags.psh == 1');
      explanations.push('TCP PUSH (PSH flag)');
    }

    // 2. Network / TCP / Protocol Anomalies
    if (lower.includes('retrans') || lower.includes('lost packet') || lower.includes('dropped')) {
      conditions.push('tcp.analysis.retransmission');
      explanations.push('TCP wire retransmissions');
    }

    if (lower.includes('zero window') || lower.includes('window full')) {
      conditions.push('tcp.window_size == 0');
      explanations.push('TCP zero receive window flow control freeze');
    }

    if (lower.includes('dup ack') || lower.includes('duplicate ack')) {
      conditions.push('tcp.analysis.duplicate_ack');
      explanations.push('TCP duplicate acknowledgments');
    }

    if (lower.includes('keep alive') || lower.includes('keepalive') || lower.includes('keep-alive')) {
      conditions.push('tcp.analysis.keep_alive || (tcp.flags.ack == 1 && tcp.len == 0)');
      explanations.push('TCP Keep-Alive probes and zero-length acknowledgments (RFC 1122)');
    }

    // 3. Application Protocols & Specific Handshakes
    if (lower.includes('tls handshake') || lower.includes('client hello') || lower.includes('clienthello')) {
      conditions.push('tls.handshake.type == 1');
      explanations.push('TLS ClientHello handshake negotiation');
    } else if (lower.includes('tls') || lower.includes('ssl') || lower.includes('https')) {
      if (!conditions.some(c => c.includes('tcp.flags'))) {
        conditions.push('tls || tcp.port == 443');
        explanations.push('TLS / SSL HTTPS traffic');
      }
    }

    if (lower.includes('http error') || lower.includes('404') || lower.includes('500') || lower.includes('bad request')) {
      conditions.push('http.response.code >= 400');
      explanations.push('HTTP 4xx/5xx client and server errors');
    } else if (lower.includes('http') && !lower.includes('http/3') && !lower.includes('http3') && !lower.includes('https')) {
      if (!conditions.some(c => c.includes('tcp.flags'))) {
        conditions.push('http || tcp.port == 80');
        explanations.push('HTTP application traffic');
      }
    }

    const domainMatch = raw.match(/\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:gov\.az|az|com|net|org|io|local))\b/i);
    if (lower.includes('dns quer') || lower.includes('dns lookup')) {
      if (domainMatch) {
        conditions.push(`dns.qry.name contains "${domainMatch[1]}"`);
        explanations.push(`DNS queries containing domain "${domainMatch[1]}"`);
      } else {
        conditions.push('dns.flags.response == 0');
        explanations.push('DNS standard query lookups');
      }
    } else if (lower.includes('dns')) {
      conditions.push('dns || udp.port == 53');
      explanations.push('Domain Name System (DNS) traffic');
    }

    if (lower.includes('quic') || lower.includes('http/3') || lower.includes('http3')) {
      conditions.push('quic || (udp.port == 443 && frame.len > 80)');
      explanations.push('QUIC / HTTP/3 encrypted UDP transport');
    }

    if (lower.includes('arp') || lower.includes('mac address lookup')) {
      conditions.push('arp');
      explanations.push('Address Resolution Protocol (ARP)');
    }

    if (lower.includes('icmp') || lower.includes('ping')) {
      conditions.push('icmp');
      explanations.push('ICMP diagnostic and echo packets');
    }

    // 4. Length & Latency Thresholds
    const lenGtMatch = raw.match(/(?:length|len|size|frame\.len)\s*(?:>=|>)\s*(\d+)/i) ||
                       raw.match(/(?:larger than|greater than|exceeding|over)\s*(\d+)\s*(?:bytes)?/i);
    const lenLtMatch = raw.match(/(?:length|len|size|frame\.len)\s*(?:<=|<)\s*(\d+)/i) ||
                       raw.match(/(?:smaller than|less than|under)\s*(\d+)\s*(?:bytes)?/i);

    if (lenGtMatch) {
      const lenVal = lenGtMatch[1];
      conditions.push(`frame.len > ${lenVal}`);
      explanations.push(`Frame wire length exceeding ${lenVal} bytes`);
    } else if (lenLtMatch) {
      const lenVal = lenLtMatch[1];
      conditions.push(`frame.len < ${lenVal}`);
      explanations.push(`Frame wire length under ${lenVal} bytes`);
    } else if (lower.includes('large packet') || lower.includes('jumbo') || lower.includes('big frame')) {
      conditions.push('frame.len > 1400');
      explanations.push('Large wire frames exceeding 1400 bytes');
    }

    const rttMatch = raw.match(/(?:rtt|latency)\s*(?:>=|>)\s*(\d+)/i) || raw.match(/(?:high latency|slow rtt)/i);
    if (rttMatch) {
      const rttVal = rttMatch[1] || '100';
      conditions.push(`tcp.analysis.ack_rtt > ${rttVal}`);
      explanations.push(`TCP ACK round-trip time exceeding ${rttVal} ms`);
    }

    // 5. IP Addresses & Directions (from, to, src, dst, or general ip.addr)
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const allIps = [...raw.matchAll(ipPattern)];
    for (const match of allIps) {
      const ip = match[0];
      const idx = match.index;
      const preceding = raw.substring(Math.max(0, idx - 25), idx).toLowerCase();
      if (preceding.includes('from') || preceding.includes('src') || preceding.includes('source')) {
        conditions.push(`ip.src == ${ip}`);
        explanations.push(`Source IP ${ip}`);
      } else if (preceding.includes('to') || preceding.includes('dst') || preceding.includes('dest') || preceding.includes('towards')) {
        conditions.push(`ip.dst == ${ip}`);
        explanations.push(`Destination IP ${ip}`);
      } else {
        conditions.push(`ip.addr == ${ip}`);
        explanations.push(`Host IP ${ip}`);
      }
    }

    // 6. Ports & Directions
    const portPattern = /\b(?:port\s*(\d+)|:(\d{2,5})\b)/gi;
    const portMatches = [...raw.matchAll(portPattern)];
    for (const pm of portMatches) {
      const portNum = pm[1] || pm[2];
      if (portNum) {
        const idx = pm.index;
        const preceding = raw.substring(Math.max(0, idx - 25), idx).toLowerCase();
        if (preceding.includes('from') || preceding.includes('src') || preceding.includes('source')) {
          conditions.push(`(tcp.srcport == ${portNum} || udp.srcport == ${portNum})`);
          explanations.push(`Source port ${portNum}`);
        } else if (preceding.includes('to') || preceding.includes('dst') || preceding.includes('dest')) {
          conditions.push(`(tcp.dstport == ${portNum} || udp.dstport == ${portNum})`);
          explanations.push(`Destination port ${portNum}`);
        } else {
          conditions.push(`(tcp.port == ${portNum} || udp.port == ${portNum})`);
          explanations.push(`Port ${portNum}`);
        }
      }
    }

    // Deduplicate conditions while maintaining order
    const uniqueConditions = Array.from(new Set(conditions));

    let filter = '';
    let explanation = '';

    if (uniqueConditions.length > 0) {
      filter = uniqueConditions.join(' && ');
      explanation = 'Constructed multi-condition Wireshark AST filter: ' + explanations.join('; ') + '.';
    } else {
      filter = `frame contains "${raw}"`;
      explanation = `Fallback payload text search for "${raw}".`;
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
