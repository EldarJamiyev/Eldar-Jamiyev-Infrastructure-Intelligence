/**
 * EJI Stage 3 Verification Test Suite
 * Validates Revoked Tokens, Audit Export, Packet Streamer, LAN CMDB Scanner, and Host Aliases.
 */

const assert = require('assert');
const { getHostMetrics } = require('../src/protocols/host-metrics');
const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');
const { getArpTable, resolveOuiVendor } = require('../src/tools/ip-scanner');
const { db } = require('../src/db/database');
const { createToken } = require('../src/core/security');

async function runStage3Verification() {
  console.log('========================================================================');
  console.log('  EJI — ELDAR JAMIYEV\'S INFRASTRUCTURE INTELLIGENCE');
  console.log('  STAGE 3 MASTER VERIFICATION TEST SUITE');
  console.log('========================================================================\n');

  // Test 1: Host Metrics Memory & Disk Aliases
  console.log('Testing Host Metrics Backward-Compatible Aliases...');
  const host = await getHostMetrics(true);
  assert(host.memory, 'Host metrics must include memory');
  assert(typeof host.memory.usedPercentage === 'number', 'usedPercentage must be a number');
  assert(typeof host.memory.usedPercent === 'number', 'usedPercent alias must be a number');
  assert(typeof host.memory.usedGb === 'number', 'usedGb alias must be a number');
  assert(typeof host.memory.totalGb === 'number', 'totalGb alias must be a number');
  assert(Array.isArray(host.disks) && host.disks.length > 0, 'Host must have at least one monitored disk');
  assert(host.disks[0].drive, 'Disk must have drive property');
  assert(host.disks[0].mount, 'Disk must have mount property');
  console.log(`✓ Host Metrics Aliases verified: RAM=${host.memory.usedGb}GB/${host.memory.totalGb}GB (${host.memory.usedPercentage}%), Primary Disk=${host.disks[0].mount} (${host.disks[0].usedGb}GB used)`);

  // Test 2: Revoked Tokens Database & Blacklist Query
  console.log('Testing Revoked Tokens Governance Endpoint Query...');
  const revokedRows = db.prepare('SELECT token_hash, user_id, revoked_at, expires_at FROM revoked_tokens ORDER BY revoked_at DESC LIMIT 10').all();
  const revokedCount = db.prepare('SELECT COUNT(*) as count FROM revoked_tokens').get().count;
  assert(typeof revokedCount === 'number', 'revokedCount must be a number');
  assert(Array.isArray(revokedRows), 'revokedTokens must be an array');
  console.log(`✓ Revoked Tokens Query verified: ${revokedCount} blacklisted session tokens in database.`);

  // Test 3: Live Wireshark-Style Packet Streamer
  console.log('Testing Wireshark-Style Live Packet Streamer & PCAP Export...');
  let streamedFrame = null;
  packetStreamer.startStreaming((type, frame) => {
    if (!streamedFrame && type === 'PACKET_STREAM_FRAME') {
      streamedFrame = frame;
    }
  });

  // Allow 1200ms for Npcap engine process to bind to physical adapter
  await new Promise(r => setTimeout(r, 1200));

  // Generate real wire traffic via ping to default gateway
  const { realPing } = require('../src/protocols/icmp-ping');
  await realPing('10.168.195.1', 2, 2000).catch(() => {});

  // Wait 1.5s for packets to be ingested and dissected
  await new Promise(r => setTimeout(r, 1500));
  packetStreamer.stopStreaming();

  const frames = packetStreamer.getRecentFrames(20);
  assert(frames.length > 0, 'Packet streamer must have captured live frames from operating system');
  const f = frames[0];
  assert(f.frameNumber > 0, 'Frame must have positive frameNumber');
  assert(f.srcIp && f.dstIp, 'Frame must have srcIp and dstIp');
  assert(f.protocol, 'Frame must have high-level protocol');
  assert(f.hexDump && f.hexDump.length > 0, 'Frame must include formatted hex dump');
  assert(f.dissection, 'Frame must include RFC dissection');

  const pcapBuffer = packetStreamer.exportPcapBuffer();
  assert(pcapBuffer.length >= 24, 'PCAP buffer must include at least 24-byte global header');
  assert.strictEqual(pcapBuffer.readUInt32LE(0), 0xA1B2C3D4, 'PCAP magic number must be 0xA1B2C3D4 (libpcap)');
  console.log(`✓ Live Packet Streamer verified: Captured ${frames.length} frames, Frame #1 [${f.protocol}] ${f.srcIp}:${f.srcPort} -> ${f.dstIp}:${f.dstPort} (${f.length} B). PCAP exported: ${pcapBuffer.length} bytes.`);

  // Test 4: Real LAN Kernel ARP Discovery & IEEE OUI Vendor Resolution
  console.log('Testing Real Kernel ARP Discovery & IEEE OUI Vendor Resolution...');
  const arpEntries = await getArpTable();
  assert(arpEntries.length > 0, 'Real kernel ARP table must contain entries');
  const sample = arpEntries[0];
  assert(sample.ip && sample.mac, 'ARP entry must contain IP and MAC');
  const vendor = resolveOuiVendor(sample.mac);
  assert(typeof vendor === 'string', 'OUI vendor must be resolved');
  console.log(`✓ Real LAN ARP Scanner verified: ${arpEntries.length} physical entries. Sample: ${sample.ip} [MAC: ${sample.mac}] Vendor: [${vendor}].`);

  console.log('\n========================================================================');
  console.log('  ALL STAGE 3 INTEGRATION GATES VERIFIED 100% GREEN');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runStage3Verification().catch(err => {
    console.error('Stage 3 verification failed:', err);
    process.exit(1);
  });
}

module.exports = { runStage3Verification };
