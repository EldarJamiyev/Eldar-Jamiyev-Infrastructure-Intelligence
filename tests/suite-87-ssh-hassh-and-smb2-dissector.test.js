// tests/suite-87-ssh-hassh-and-smb2-dissector.test.js
/**
 * EJII Test Suite 87: SSH RFC 4253 HASSH & SMBv2/3 Lateral Movement Dissector
 * Verifies SSH-2.0 banner extraction, SSH_MSG_KEXINIT parsing, HASSH MD5/SHA256,
 * SMB2 header structure, Tree Connect/Create opcodes, and ADMIN$/IPC$ lateral movement heuristics.
 */

'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { L7DeepProtocolDissector } = require('../src/sniffer/l7-deep-protocol-dissector');

async function runSuite87SshHasshAndSmb2Dissector() {
  console.log('========================================================================');
  console.log('  === [SUITE 87] SSH HASSH & SMBv2/3 LATERAL MOVEMENT DISSECTOR ===     ');
  console.log('========================================================================\n');

  // [87.1] SSH-2.0 Identification Banner
  console.log('[Test 87.1] Parsing SSH-2.0 banner identification string...');
  const bannerString = 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n';
  const bannerBuf = Buffer.from(bannerString, 'utf8');

  const sshBanner = L7DeepProtocolDissector.dissectSshPacket(bannerBuf);
  assert.ok(sshBanner, 'Must detect SSH banner');
  assert.strictEqual(sshBanner.isSsh, true);
  assert.strictEqual(sshBanner.isKexInit, false);
  assert.strictEqual(sshBanner.banner, 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13');
  console.log(`  ✓ SSH banner parsed: "${sshBanner.banner}"`);

  // [87.2] SSH_MSG_KEXINIT and HASSH Fingerprint Calculation
  console.log('[Test 87.2] Parsing SSH_MSG_KEXINIT packet and calculating HASSH fingerprint...');
  // Construct a binary SSH packet with msgCode = 20 (SSH_MSG_KEXINIT)
  // Format:
  // uint32 packet_length
  // uint8 padding_length
  // byte SSH_MSG_KEXINIT (20)
  // byte[16] cookie
  // name-list kex_algorithms
  // name-list server_host_key_algorithms
  // name-list encryption_algorithms_client_to_server
  // name-list encryption_algorithms_server_to_client
  // name-list mac_algorithms_client_to_server
  // name-list mac_algorithms_server_to_client
  // name-list compression_algorithms_client_to_server
  // name-list compression_algorithms_server_to_client

  function encodeNameList(list) {
    const str = list.join(',');
    const b = Buffer.alloc(4 + str.length);
    b.writeUInt32BE(str.length, 0);
    b.write(str, 4, 'ascii');
    return b;
  }

  const kexAlgos = ['curve25519-sha256', 'ecdh-sha2-nistp256'];
  const hostKeyAlgos = ['ssh-ed25519', 'rsa-sha2-512'];
  const encAlgos = ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'];
  const macAlgos = ['umac-128-etm@openssh.com'];
  const compAlgos = ['none'];

  const cookie = Buffer.alloc(16, 0x42);
  const body = Buffer.concat([
    Buffer.from([20]), // msgCode 20
    cookie,
    encodeNameList(kexAlgos),
    encodeNameList(hostKeyAlgos),
    encodeNameList(encAlgos),
    encodeNameList(encAlgos),
    encodeNameList(macAlgos),
    encodeNameList(macAlgos),
    encodeNameList(compAlgos),
    encodeNameList(compAlgos)
  ]);

  const paddingLength = 4;
  const packetLength = body.length + 1 + paddingLength;
  const padding = Buffer.alloc(paddingLength, 0x00);

  const kexInitPacket = Buffer.concat([
    Buffer.alloc(4),
    Buffer.from([paddingLength]),
    body,
    padding
  ]);
  kexInitPacket.writeUInt32BE(packetLength, 0);

  const sshKex = L7DeepProtocolDissector.dissectSshPacket(kexInitPacket);
  assert.ok(sshKex, 'Must detect SSH KEXINIT');
  assert.strictEqual(sshKex.isSsh, true);
  assert.strictEqual(sshKex.isKexInit, true);
  assert.ok(sshKex.hasshString, 'HASSH string must be non-empty');
  assert.ok(sshKex.hasshMd5 && sshKex.hasshMd5.length === 32, 'HASSH MD5 must be 32 chars');
  assert.ok(sshKex.hasshSha256 && sshKex.hasshSha256.length === 64, 'HASSH SHA256 must be 64 chars');
  assert.deepStrictEqual(sshKex.kexAlgorithms, kexAlgos);
  console.log(`  ✓ HASSH MD5: ${sshKex.hasshMd5}`);
  console.log(`  ✓ HASSH String: "${sshKex.hasshString}"`);

  // [87.3] SMBv2 Header Structure & TREE_CONNECT Command
  console.log('[Test 87.3] Parsing SMBv2 Header (0xFE SMB) and TREE_CONNECT...');
  // SMB2 Header is 64 bytes
  const smbHeader = Buffer.alloc(64, 0);
  smbHeader[0] = 0xfe;
  smbHeader[1] = 0x53; // 'S'
  smbHeader[2] = 0x4d; // 'M'
  smbHeader[3] = 0x42; // 'B'
  smbHeader.writeUInt16LE(64, 4);   // StructureSize = 64
  smbHeader.writeUInt16LE(1, 6);    // CreditCharge = 1
  smbHeader.writeUInt32LE(0, 8);    // Status = STATUS_SUCCESS
  smbHeader.writeUInt16LE(0x0003, 12); // Command = 3 (TREE_CONNECT)
  smbHeader.writeUInt16LE(1, 14);   // Credits = 1
  smbHeader.writeUInt32LE(0x00000000, 16); // Flags (0 = Request)
  smbHeader.writeBigUInt64LE(101n, 24);    // MessageId = 101
  smbHeader.writeUInt32LE(0x00000001, 36); // TreeId = 1
  smbHeader.writeBigUInt64LE(0x0000000000001234n, 40); // SessionId

  const smbDissect = L7DeepProtocolDissector.dissectSmb2Packet(smbHeader);
  assert.ok(smbDissect, 'Must detect SMB2 header');
  assert.strictEqual(smbDissect.isSmb2, true);
  assert.strictEqual(smbDissect.commandName, 'TREE_CONNECT');
  assert.strictEqual(smbDissect.commandCode, 3);
  assert.strictEqual(smbDissect.isResponse, false);
  assert.strictEqual(smbDissect.messageId, '101');
  assert.strictEqual(smbDissect.lateralMovementSuspected, false);
  console.log(`  ✓ SMB2 Header verified: command=${smbDissect.commandName}, messageId=${smbDissect.messageId}`);

  // [87.4] SMB2 Lateral Movement Heuristics (ADMIN$, IPC$, PsExec)
  console.log('[Test 87.4] Detecting SMB2 lateral movement signatures (IPC$ and PsExec)...');
  const payloadAdmin = Buffer.from('\\\\192.168.1.10\\ADMIN$\\system32\\psexec.exe', 'utf8');
  const smbLateralPacket = Buffer.concat([smbHeader, payloadAdmin]);

  const smbLateral = L7DeepProtocolDissector.dissectSmb2Packet(smbLateralPacket);
  assert.ok(smbLateral, 'Must parse SMB2 packet with payload');
  assert.strictEqual(smbLateral.lateralMovementSuspected, true, 'Must flag ADMIN$/psexec as lateral movement');
  assert.strictEqual(smbLateral.lateralTargetOrShare, 'ADMIN$+PIPE');
  console.log(`  ✓ Lateral movement detected: suspected=${smbLateral.lateralMovementSuspected}, target=${smbLateral.lateralTargetOrShare}`);

  // [87.5] Universal Dissector Integration
  console.log('[Test 87.5] Verifying universal dissector routes to SSH and SMB2...');
  const uniSsh = L7DeepProtocolDissector.dissect(bannerBuf);
  assert.strictEqual(uniSsh.identifiedProtocol, 'SSH');
  assert.strictEqual(uniSsh.protocol, 'SSH');
  assert.ok(uniSsh.ssh);

  const uniSmb = L7DeepProtocolDissector.dissect(smbLateralPacket);
  assert.strictEqual(uniSmb.identifiedProtocol, 'SMB2/3');
  assert.strictEqual(uniSmb.protocol, 'SMB2/3');
  assert.ok(uniSmb.smb2);
  console.log('  ✓ Universal L7 router correctly categorized SSH and SMB2 payloads.');

  console.log('\n========================================================================');
  console.log('  SUITE 87 PASSED: SSH HASSH & SMBv2/3 DISSECTOR 100% GREEN             ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite87SshHasshAndSmb2Dissector().catch((err) => {
    console.error('Suite 87 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite87SshHasshAndSmb2Dissector,
  runSuite87: runSuite87SshHasshAndSmb2Dissector
};
