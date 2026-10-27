// src/security/zero-trust-policy-synthesizer.ts
/**
 * Zero-Trust Micro-Segmentation Firewall Policy Synthesizer
 * Generates least-privilege policies in Windows netsh, Linux nftables, and Kubernetes NetworkPolicy YAML.
 * Detects unauthorized lateral movement, shadow admin port access, and abnormal egress.
 */

export interface ObservedHostAsset {
  readonly ip: string;
  readonly hostname?: string;
  readonly role?: string;
  readonly openPorts?: readonly number[];
  readonly mac?: string;
}

export interface ObservedSocketFlow {
  readonly protocol: 'TCP' | 'UDP';
  readonly localIp: string;
  readonly localPort: number;
  readonly remoteIp: string;
  readonly remotePort: number;
  readonly processName?: string;
  readonly processId?: number;
}

export interface LateralMovementViolation {
  readonly flow: ObservedSocketFlow;
  readonly severity: 'HIGH' | 'CRITICAL';
  readonly reason: string;
  readonly violationType: 'SHADOW_ADMIN_PORT' | 'WORKSTATION_LATERAL_SMB_RDP' | 'UNEXPECTED_PROCESS_EGRESS';
}

export interface ZeroTrustPolicyBundle {
  readonly generatedAt: string;
  readonly targetSubnet: string;
  readonly assetCount: number;
  readonly windowsNetshRules: readonly string[];
  readonly linuxNftablesManifest: string;
  readonly kubernetesNetworkPolicyYaml: string;
  readonly lateralMovementViolations: readonly LateralMovementViolation[];
  readonly shadowAdminPortsBlocked: readonly number[];
}

const SHADOW_ADMIN_PORTS = [22, 445, 135, 139, 3389, 5985, 5986];

export class ZeroTrustPolicySynthesizer {
  /**
   * Synthesizes 3-format firewall policies and analyzes flow violations
   */
  public static synthesize(
    assets: readonly ObservedHostAsset[],
    flows: readonly ObservedSocketFlow[] = [],
    targetSubnet = '192.168.31.0/24'
  ): ZeroTrustPolicyBundle {
    const timestamp = new Date().toISOString();
    const netshRules: string[] = [];

    // Base hardening: Block untrusted inbound by default
    netshRules.push('netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound');
    netshRules.push('netsh advfirewall firewall add rule name="EJII-Allow-Loopback" dir=in action=allow localip=127.0.0.1 enable=yes');
    netshRules.push('netsh advfirewall firewall add rule name="EJII-Allow-ICMPv4" protocol=icmpv4:8,any dir=in action=allow enable=yes');

    // Block shadow admin ports from untrusted hosts
    for (const port of SHADOW_ADMIN_PORTS) {
      netshRules.push(
        `netsh advfirewall firewall add rule name="EJII-Block-ShadowAdmin-${port}" protocol=TCP localport=${port} dir=in action=block remoteip=any enable=yes`
      );
    }

    // Add allow rules for discovered server endpoints
    for (const asset of assets) {
      if (asset.openPorts && asset.openPorts.length > 0) {
        for (const port of asset.openPorts) {
          if (!SHADOW_ADMIN_PORTS.includes(port)) {
            netshRules.push(
              `netsh advfirewall firewall add rule name="EJII-Allow-${asset.hostname || asset.ip}-P${port}" protocol=TCP localport=${port} dir=in action=allow remoteip=${targetSubnet} enable=yes`
            );
          }
        }
      }
    }

    // Synthesize Linux nftables ruleset
    const nftablesLines: string[] = [
      '#!/usr/sbin/nft -f',
      '# EJII Sovereign-Singularity Zero-Trust Micro-Segmentation Table',
      'flush table inet ejii_zerotrust',
      '',
      'table inet ejii_zerotrust {',
      '  chain inbound {',
      '    type filter hook input priority 0; policy drop;',
      '    ct state established,related accept',
      '    iif "lo" accept',
      '    ip protocol icmp accept',
      '    ip6 nexthdr icmpv6 accept',
      ''
    ];

    for (const port of SHADOW_ADMIN_PORTS) {
      nftablesLines.push(`    tcp dport ${port} counter log prefix "[EJII-BLOCK-SHADOW] " drop`);
    }

    // Allow legitimate services
    for (const asset of assets) {
      for (const port of asset.openPorts || []) {
        if (!SHADOW_ADMIN_PORTS.includes(port)) {
          nftablesLines.push(`    ip saddr ${targetSubnet} tcp dport ${port} accept`);
        }
      }
    }

    nftablesLines.push('  }');
    nftablesLines.push('  chain outbound {', '    type filter hook output priority 0; policy accept;', '  }');
    nftablesLines.push('}');
    const linuxNftablesManifest = nftablesLines.join('\n');

    // Synthesize Kubernetes NetworkPolicy YAML
    const k8sManifest = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ejii-zerotrust-microsegmentation
  namespace: default
  labels:
    app.kubernetes.io/managed-by: ejii-sovereign-singularity
    security.ejii.io/policy: zero-trust-least-privilege
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/part-of: ejii
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - ipBlock:
            cidr: ${targetSubnet}
            except:
              - 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 8443
        - protocol: TCP
          port: 53
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
      ports:
        - protocol: TCP
          port: 443
        - protocol: UDP
          port: 53
`;

    // Detect lateral movement & shadow admin access in live flows
    const violations: LateralMovementViolation[] = [];
    for (const flow of flows) {
      const isShadowPort = SHADOW_ADMIN_PORTS.includes(flow.remotePort) || SHADOW_ADMIN_PORTS.includes(flow.localPort);
      if (isShadowPort) {
        violations.push({
          flow,
          severity: 'CRITICAL',
          reason: `Shadow admin port access detected: Port ${flow.remotePort || flow.localPort} (${flow.protocol}) between ${flow.localIp} -> ${flow.remoteIp}`,
          violationType: 'SHADOW_ADMIN_PORT'
        });
      }

      // Workstation to workstation lateral movement
      const isLocalSubnetSource = flow.localIp.startsWith('192.168.') || flow.localIp.startsWith('10.');
      const isLocalSubnetDest = flow.remoteIp.startsWith('192.168.') || flow.remoteIp.startsWith('10.');
      if (isLocalSubnetSource && isLocalSubnetDest && !flow.remoteIp.endsWith('.1')) {
        if (flow.remotePort === 445 || flow.remotePort === 3389 || flow.remotePort === 22) {
          violations.push({
            flow,
            severity: 'CRITICAL',
            reason: `Peer-to-peer lateral workstation traversal on Port ${flow.remotePort} (${flow.processName || 'unknown'})`,
            violationType: 'WORKSTATION_LATERAL_SMB_RDP'
          });
        }
      }

      // Unexpected process egress
      if (flow.processName) {
        const suspiciousExecutables = ['powershell.exe', 'cmd.exe', 'certutil.exe', 'rundll32.exe', 'wmic.exe', 'bash', 'nc'];
        if (suspiciousExecutables.includes(flow.processName.toLowerCase()) && !isLocalSubnetDest && flow.remotePort !== 53) {
          violations.push({
            flow,
            severity: 'HIGH',
            reason: `Suspicious system binary [${flow.processName}] performing direct outbound egress to ${flow.remoteIp}:${flow.remotePort}`,
            violationType: 'UNEXPECTED_PROCESS_EGRESS'
          });
        }
      }
    }

    return {
      generatedAt: timestamp,
      targetSubnet,
      assetCount: assets.length,
      windowsNetshRules: netshRules,
      linuxNftablesManifest,
      kubernetesNetworkPolicyYaml: k8sManifest,
      lateralMovementViolations: violations,
      shadowAdminPortsBlocked: SHADOW_ADMIN_PORTS
    };
  }
}
