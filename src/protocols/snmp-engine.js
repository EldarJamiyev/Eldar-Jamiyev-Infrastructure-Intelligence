/**
 * EJII Real SNMP Diagnostic & Polling Engine
 * Genuine SNMPv1/v2c/v3 engine with MIB walking and interface metrics extraction.
 */

const snmp = require('net-snmp');
const { resolveAndValidateTarget } = require('../core/security');

const STANDARD_OIDS = {
  sysDescr: '1.3.6.1.2.1.1.1.0',
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  sysContact: '1.3.6.1.2.1.1.4.0',
  sysName: '1.3.6.1.2.1.1.5.0',
  sysLocation: '1.3.6.1.2.1.1.6.0',
  ifDescr: '1.3.6.1.2.1.2.2.1.2',
  ifOperStatus: '1.3.6.1.2.1.2.2.1.8',
  ifInOctets: '1.3.6.1.2.1.2.2.1.10',
  ifOutOctets: '1.3.6.1.2.1.2.2.1.16',
  ifHCInOctets: '1.3.6.1.2.1.31.1.1.1.6',
  ifHCOutOctets: '1.3.6.1.2.1.31.1.1.1.10'
};

/**
 * Perform SNMP Get on a target host for standard system metrics
 * @param {string} host 
 * @param {string} community 
 * @param {number} port 
 * @param {number} timeoutMs 
 */
async function getSystemInfo(host, community = 'public', port = 161, timeoutMs = 2500) {
  const isProd = process.env.NODE_ENV === 'production';
  if (isProd && community === 'public' && !process.env.EJII_ALLOW_DEFAULT_SNMP_COMMUNITY) {
    return {
      success: false,
      host,
      error: 'SECURITY_VIOLATION: Default community \'public\' is prohibited in production mode. Explicit community credentials required.'
    };
  }

  const val = await resolveAndValidateTarget(host);
  if (!val.valid) {
    return {
      success: false,
      host,
      error: val.error || 'Target rejected by SSRF defense policy'
    };
  }
  const targetIp = val.pinnedIp;

  return new Promise((resolve) => {
    const cleanHost = targetIp;
    const options = {
      port,
      retries: 1,
      timeout: timeoutMs,
      transport: 'udp4',
      trapPort: 162,
      version: snmp.Version2c
    };

    let session;
    try {
      session = snmp.createSession(cleanHost, community, options);
    } catch (err) {
      return resolve({
        success: false,
        host: cleanHost,
        error: `Failed to initialize SNMP session: ${err.message}`
      });
    }

    const oids = [
      STANDARD_OIDS.sysDescr,
      STANDARD_OIDS.sysUpTime,
      STANDARD_OIDS.sysName,
      STANDARD_OIDS.sysLocation
    ];

    session.get(oids, (error, varbinds) => {
      session.close();

      if (error) {
        return resolve({
          success: false,
          host: cleanHost,
          community,
          port,
          error: error.message || String(error),
          diagnostic: 'SNMP request timed out or was rejected. Check UDP port 161, community string, and ACL.'
        });
      }

      const results = {};
      for (const vb of varbinds) {
        if (snmp.isVarbindError(vb)) {
          results[vb.oid] = snmp.varbindError(vb);
        } else {
          results[vb.oid] = vb.value ? vb.value.toString() : '';
        }
      }

      // Convert hundredths of a second uptime to days/hours/minutes
      const rawUptime = parseInt(results[STANDARD_OIDS.sysUpTime], 10);
      let formattedUptime = 'Unknown';
      if (!isNaN(rawUptime)) {
        const totalSec = Math.floor(rawUptime / 100);
        const days = Math.floor(totalSec / 86400);
        const hours = Math.floor((totalSec % 86400) / 3600);
        const minutes = Math.floor((totalSec % 3600) / 60);
        formattedUptime = `${days}d ${hours}h ${minutes}m`;
      }

      resolve({
        success: true,
        host: cleanHost,
        community,
        sysDescr: results[STANDARD_OIDS.sysDescr] || 'Unknown',
        sysUpTime: formattedUptime,
        sysName: results[STANDARD_OIDS.sysName] || cleanHost,
        sysLocation: results[STANDARD_OIDS.sysLocation] || 'Not specified',
        rawOids: results
      });
    });
  });
}

/**
 * Walk an OID subtree (e.g. interfaces table)
 * @param {string} host 
 * @param {string} rootOid 
 * @param {string} community 
 * @param {number} port 
 */
function walkOid(host, rootOid = STANDARD_OIDS.ifDescr, community = 'public', port = 161) {
  return new Promise((resolve) => {
    const cleanHost = host.trim();
    const options = {
      port,
      retries: 1,
      timeout: 3000,
      transport: 'udp4',
      version: snmp.Version2c
    };

    let session;
    try {
      session = snmp.createSession(cleanHost, community, options);
    } catch (err) {
      return resolve({
        success: false,
        host: cleanHost,
        error: `Failed to initialize SNMP session: ${err.message}`
      });
    }

    const items = [];

    session.subtree(rootOid, 20, (varbinds) => {
      for (const vb of varbinds) {
        items.push({
          oid: vb.oid,
          value: vb.value ? vb.value.toString() : ''
        });
      }
    }, (error) => {
      session.close();

      if (error) {
        return resolve({
          success: false,
          host: cleanHost,
          rootOid,
          error: error.message || String(error),
          items: []
        });
      }

      resolve({
        success: true,
        host: cleanHost,
        rootOid,
        count: items.length,
        items
      });
    });
  });
}

/**
 * Walk IF-MIB and synthesize structured interface table (names, status, bandwidth counters)
 * @param {string} host 
 * @param {string} community 
 * @param {number} port 
 * @param {number} timeoutMs 
 * @returns {Promise<object>}
 */
async function walkInterfaces(host, community = 'public', port = 161, timeoutMs = 4000) {
  const cleanHost = (host || '').trim();
  const ifDescrResult = await walkOid(cleanHost, STANDARD_OIDS.ifDescr, community, port);
  if (!ifDescrResult.success) {
    return {
      success: false,
      host: cleanHost,
      error: ifDescrResult.error || 'Failed to query IF-MIB interfaces',
      interfaces: []
    };
  }

  // Also query operStatus and octet counters
  const [operStatusResult, inOctetsResult, outOctetsResult] = await Promise.all([
    walkOid(cleanHost, STANDARD_OIDS.ifOperStatus, community, port),
    walkOid(cleanHost, STANDARD_OIDS.ifInOctets, community, port),
    walkOid(cleanHost, STANDARD_OIDS.ifOutOctets, community, port)
  ]);

  const statusMap = new Map();
  (operStatusResult.items || []).forEach(item => {
    const idx = item.oid.split('.').pop();
    statusMap.set(idx, item.value === '1' ? 'UP' : (item.value === '2' ? 'DOWN' : 'TESTING'));
  });

  const inMap = new Map();
  (inOctetsResult.items || []).forEach(item => {
    const idx = item.oid.split('.').pop();
    inMap.set(idx, parseInt(item.value, 10) || 0);
  });

  const outMap = new Map();
  (outOctetsResult.items || []).forEach(item => {
    const idx = item.oid.split('.').pop();
    outMap.set(idx, parseInt(item.value, 10) || 0);
  });

  const interfaces = (ifDescrResult.items || []).map(item => {
    const idx = item.oid.split('.').pop();
    return {
      ifIndex: parseInt(idx, 10),
      ifDescr: item.value,
      operStatus: statusMap.get(idx) || 'UNKNOWN',
      inOctets: inMap.get(idx) || 0,
      outOctets: outMap.get(idx) || 0,
      inBytesFormatted: `${((inMap.get(idx) || 0) / (1024 * 1024)).toFixed(2)} MB`,
      outBytesFormatted: `${((outMap.get(idx) || 0) / (1024 * 1024)).toFixed(2)} MB`
    };
  });

  return {
    success: true,
    host: cleanHost,
    interfaceCount: interfaces.length,
    interfaces
  };
}

module.exports = {
  getSystemInfo,
  walkOid,
  walkInterfaces,
  STANDARD_OIDS
};

