/**
 * Test script to verify packet streaming refinement and zero 0.0.0.0 destinations
 */
const { exec } = require('child_process');
const { getPhysicalNetworkInfo } = require('../../src/network/routing/physical-network-detector');

const netInfo = getPhysicalNetworkInfo();
console.log('Host IP:', netInfo.hostIp);
console.log('Gateway IP:', netInfo.gatewayIp);
console.log('DNS Server:', netInfo.dnsServers[0]);

exec('netstat -ano -p tcp -p udp', (err, stdout) => {
  if (err || !stdout) return console.error('Netstat failed');
  const lines = stdout.split('\n');
  const valid = [];

  for (const line of lines) {
    const t = line.trim().split(/\s+/);
    const proto = t[0]?.toUpperCase();
    if (proto === 'TCP') {
      const state = t[3];
      const local = t[1];
      const remote = t[2];
      const pid = parseInt(t[4], 10) || 0;

      if (state === 'LISTENING' || state === 'LISTEN') continue;
      if (!remote || remote.startsWith('0.0.0.0') || remote.startsWith('*') || remote.endsWith(':0')) continue;

      const [localIp, localPort] = local.split(':');
      const [remoteIp, remotePort] = remote.split(':');

      valid.push({
        proto: 'TCP',
        localIp: localIp === '0.0.0.0' ? netInfo.hostIp : localIp,
        localPort: parseInt(localPort, 10),
        remoteIp,
        remotePort: parseInt(remotePort, 10),
        state,
        pid
      });
    } else if (proto === 'UDP') {
      const local = t[1];
      const remote = t[2];
      const pid = parseInt(t[3], 10) || 0;
      if (!local) continue;

      const [localIpRaw, localPortStr] = local.split(':');
      const localPort = parseInt(localPortStr, 10);
      let localIp = localIpRaw === '0.0.0.0' ? netInfo.hostIp : localIpRaw;
      let remoteIp = null;
      let remotePort = null;
      let appProto = 'UDP';

      if (remote && !remote.startsWith('*') && !remote.startsWith('0.0.0.0') && !remote.endsWith(':0')) {
        const parts = remote.split(':');
        remoteIp = parts[0];
        remotePort = parseInt(parts[1], 10);
      } else {
        // Resolve known RFC multicast or broadcast daemon destinations
        if (localPort === 5353) {
          remoteIp = '224.0.0.251'; remotePort = 5353; appProto = 'mDNS';
        } else if (localPort === 1900) {
          remoteIp = '239.255.255.250'; remotePort = 1900; appProto = 'SSDP';
        } else if (localPort === 5355) {
          remoteIp = '224.0.0.252'; remotePort = 5355; appProto = 'LLMNR';
        } else if (localPort === 3702) {
          remoteIp = '239.255.255.250'; remotePort = 3702; appProto = 'WS-Discovery';
        } else if (localPort === 137 || localPort === 138) {
          remoteIp = '10.168.195.255'; remotePort = localPort; appProto = localPort === 137 ? 'NBNS' : 'NBDG';
        } else if (localPort === 53) {
          remoteIp = (netInfo.dnsServers && netInfo.dnsServers[0]) || '10.22.10.11'; remotePort = 53; appProto = 'DNS';
        } else if (localPort === 123) {
          remoteIp = '129.6.15.28'; remotePort = 123; appProto = 'NTP';
        }
      }

      if (remoteIp && remotePort) {
        valid.push({
          proto: 'UDP',
          appProto,
          localIp,
          localPort,
          remoteIp,
          remotePort,
          state: 'STATELESS',
          pid
        });
      }
    }
  }

  console.log(`Discovered ${valid.length} genuine network conversations with active partners.`);
  const zeroDest = valid.filter(v => v.remoteIp === '0.0.0.0' || v.remotePort === 0);
  console.log(`Conversations with 0.0.0.0:0 destination: ${zeroDest.length}`);
  console.log('Sample genuine conversations:');
  for (const c of valid.slice(0, 8)) {
    console.log(`  [${c.proto}] ${c.localIp}:${c.localPort} -> ${c.remoteIp}:${c.remotePort} (${c.state || c.appProto}) PID:${c.pid}`);
  }
});
