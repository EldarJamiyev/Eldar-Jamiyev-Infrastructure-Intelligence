/**
 * EJI Enterprise IP Address Management (IPAM) Service
 * Authoritative CIDR arithmetic, next-free-IP allocation, and conflict detection.
 */

const { db } = require('../../database/database');

class IpamService {
  /**
   * Convert dotted decimal IP string to 32-bit unsigned integer
   */
  static ipToInt(ip) {
    return ip.split('.').reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0);
  }

  /**
   * Convert 32-bit integer back to dotted decimal IP string
   */
  static intToIp(int) {
    return [
      (int >>> 24) & 255,
      (int >>> 16) & 255,
      (int >>> 8) & 255,
      int & 255
    ].join('.');
  }

  /**
   * Calculate subnet boundaries from CIDR (e.g. 192.168.31.0/24)
   */
  static parseCidr(cidr) {
    const parts = cidr.trim().split('/');
    if (parts.length !== 2) throw new Error(`Invalid CIDR format: ${cidr}`);

    const ip = parts[0];
    const prefix = parseInt(parts[1], 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) throw new Error(`Invalid prefix length: ${prefix}`);

    const ipInt = this.ipToInt(ip);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const networkInt = (ipInt & mask) >>> 0;
    const broadcastInt = (networkInt | (~mask >>> 0)) >>> 0;

    const totalHosts = prefix === 32 ? 1 : prefix === 31 ? 2 : Math.pow(2, 32 - prefix);
    const usableHosts = prefix >= 31 ? totalHosts : totalHosts - 2;

    const firstUsableInt = prefix >= 31 ? networkInt : networkInt + 1;
    const lastUsableInt = prefix >= 31 ? broadcastInt : broadcastInt - 1;

    return {
      cidr,
      networkAddress: this.intToIp(networkInt),
      broadcastAddress: this.intToIp(broadcastInt),
      netmask: this.intToIp(mask),
      prefix,
      totalHosts,
      usableHosts,
      firstUsableIp: this.intToIp(firstUsableInt),
      lastUsableIp: this.intToIp(lastUsableInt)
    };
  }

  /**
   * Generate reverse DNS PTR record name (e.g. 192.168.31.10 -> 10.31.168.192.in-addr.arpa)
   */
  static generatePtrName(ip) {
    const octets = ip.trim().split('.');
    if (octets.length !== 4) throw new Error(`Invalid IPv4 address: ${ip}`);
    return `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;
  }

  /**
   * Get allocated IPs for a subnet from CMDB interfaces
   */
  static getAllocatedIps(networkCidr) {
    const info = this.parseCidr(networkCidr);
    const netInt = this.ipToInt(info.networkAddress);
    const bcastInt = this.ipToInt(info.broadcastAddress);

    const rows = db.prepare('SELECT ipv4_address, interface_name, ci_id FROM cmdb_interfaces WHERE ipv4_address IS NOT NULL').all();
    const allocated = [];

    for (const r of rows) {
      try {
        const ipInt = this.ipToInt(r.ipv4_address);
        if (ipInt >= netInt && ipInt <= bcastInt) {
          allocated.push({
            ip: r.ipv4_address,
            ciId: r.ci_id,
            interfaceName: r.interface_name
          });
        }
      } catch (e) {
        // Skip invalid IP strings
      }
    }

    return allocated;
  }

  /**
   * Find next available IP address in a subnet
   */
  static findNextFreeIp(networkCidr) {
    const info = this.parseCidr(networkCidr);
    const allocated = new Set(this.getAllocatedIps(networkCidr).map(a => a.ip));

    const firstInt = this.ipToInt(info.firstUsableIp);
    const lastInt = this.ipToInt(info.lastUsableIp);

    for (let current = firstInt; current <= lastInt; current++) {
      const candidate = this.intToIp(current);
      if (!allocated.has(candidate)) {
        return {
          allocated: false,
          nextFreeIp: candidate,
          subnet: networkCidr,
          usableHosts: info.usableHosts,
          assignedCount: allocated.size
        };
      }
    }

    throw new Error(`Subnet ${networkCidr} is completely exhausted (0 free IPs).`);
  }
}

module.exports = IpamService;
