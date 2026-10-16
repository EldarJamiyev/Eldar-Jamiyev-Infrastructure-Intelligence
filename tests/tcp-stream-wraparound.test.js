/**
 * Test Suite 20: TCP Stream Reassembler Sequence Wraparound & Boundary Test Suite
 * Verifies RFC 1982 modular sequence arithmetic, 32-bit boundary transitions (0xFFFFFFFF -> 0x00000000),
 * out-of-order segment buffering, partial overlap trimming, duplicate suppression, and RST teardown.
 */

'use strict';

const assert = require('node:assert/strict');
const TcpStreamReassembler = require('../src/network/packet-decoding/stream-reassembler');

async function runTcpStreamWraparoundTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 20: TCP STREAM WRAPAROUND & 32-BIT BOUNDARY VERIFICATION       ');
  console.log('  RFC 1982 Modular Sequence Arithmetic, Overlap Trimming & RST Tear-down');
  console.log('========================================================================');

  const baseTime = Date.now();

  // 1. Direct In-Order Sequence Wraparound Across 0xFFFFFFFF -> 0x00000000
  console.log('[20.1] Testing in-order 32-bit sequence wraparound across boundary...');
  const part1 = Buffer.from('ABCDEFGHIJKLMNOP'); // 16 bytes: 0xFFFFFFF0 -> 0x00000000
  const part2 = Buffer.from('QRSTUVWXYZ012345'); // 16 bytes: 0x00000000 -> 0x00000010

  const framesInOrder = [
    {
      frameNumber: 1,
      timestamp: new Date(baseTime).toISOString(),
      srcIp: '192.168.1.50',
      srcPort: 54321,
      dstIp: '10.0.0.1',
      dstPort: 80,
      protocol: 'TCP',
      tcp: {
        seq: 0xFFFFFFF0,
        ack: 100,
        flags: { syn: false, ack: true }
      },
      payload: part1
    },
    {
      frameNumber: 2,
      timestamp: new Date(baseTime + 10).toISOString(),
      srcIp: '192.168.1.50',
      srcPort: 54321,
      dstIp: '10.0.0.1',
      dstPort: 80,
      protocol: 'TCP',
      tcp: {
        seq: 0x00000000,
        ack: 100,
        flags: { syn: false, ack: true }
      },
      payload: part2
    }
  ];

  const streamInOrder = TcpStreamReassembler.reconstructStream(framesInOrder);
  assert.strictEqual(streamInOrder.totalClientBytes, 32);
  assert.strictEqual(streamInOrder.chunks.length, 1);
  assert.strictEqual(streamInOrder.chunks[0].dataAscii, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345');
  console.log('  ✓ In-order 32-bit boundary transition reassembled 32 bytes seamlessly.');

  // 2. Out-of-Order Segment Arrival Across 32-bit Boundary
  console.log('[20.2] Testing out-of-order segment arrival across 32-bit wraparound...');
  // Frame 2 (seq 0x00000000) arrives BEFORE Frame 1 (seq 0xFFFFFFF0)
  const framesOutOfOrder = [
    {
      frameNumber: 2,
      timestamp: new Date(baseTime + 10).toISOString(),
      srcIp: '192.168.1.50',
      srcPort: 54321,
      dstIp: '10.0.0.1',
      dstPort: 80,
      protocol: 'TCP',
      tcp: {
        seq: 0x00000000,
        ack: 100,
        flags: { syn: false, ack: true }
      },
      payload: part2
    },
    {
      frameNumber: 1,
      timestamp: new Date(baseTime).toISOString(),
      srcIp: '192.168.1.50',
      srcPort: 54321,
      dstIp: '10.0.0.1',
      dstPort: 80,
      protocol: 'TCP',
      tcp: {
        seq: 0xFFFFFFF0,
        ack: 100,
        flags: { syn: false, ack: true }
      },
      payload: part1
    }
  ];

  const streamOutOfOrder = TcpStreamReassembler.reconstructStream(framesOutOfOrder);
  assert.strictEqual(streamOutOfOrder.totalClientBytes, 32);
  assert.strictEqual(streamOutOfOrder.chunks.length, 1);
  assert.strictEqual(streamOutOfOrder.chunks[0].dataAscii, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345');
  console.log('  ✓ RFC 1982 modular sort correctly reordered segments across 32-bit wraparound.');

  // 3. Partial Overlap Trimming Across 32-bit Boundary
  console.log('[20.3] Testing partial overlap trimming across 32-bit boundary...');
  // Seg A: seq 0xFFFFFFF8, len 16 (0xFFFFFFF8 -> 0x00000008) = "0123456789ABCDEF"
  // Seg B: seq 0x00000000, len 16 (0x00000000 -> 0x00000010) = "89ABCDEFGHJKLMNO"
  // Overlap: 8 bytes ("89ABCDEF") already seen in Seg A from 0x00000000 to 0x00000008.
  // Seg B should be trimmed by 8 bytes, appending only "GHJKLMNO".
  const segA = Buffer.from('0123456789ABCDEF');
  const segB = Buffer.from('89ABCDEFGHJKLMNO');

  const framesOverlap = [
    {
      frameNumber: 1,
      timestamp: new Date(baseTime).toISOString(),
      srcIp: '192.168.1.50',
      srcPort: 54321,
      dstIp: '10.0.0.1',
      dstPort: 80,
      protocol: 'TCP',
      tcp: { seq: 0xFFFFFFF8, ack: 100, flags: { ack: true } },
      payload: segA
    },
    {
      frameNumber: 2,
      timestamp: new Date(baseTime + 5).toISOString(),
      srcIp: '192.168.1.50',
      srcPort: 54321,
      dstIp: '10.0.0.1',
      dstPort: 80,
      protocol: 'TCP',
      tcp: { seq: 0x00000000, ack: 100, flags: { ack: true } },
      payload: segB
    }
  ];

  const streamOverlap = TcpStreamReassembler.reconstructStream(framesOverlap);
  assert.strictEqual(streamOverlap.totalClientBytes, 24); // 16 + 8 trimmed
  assert.strictEqual(streamOverlap.retransmissions, 1);
  assert.strictEqual(streamOverlap.chunks[0].dataAscii, '0123456789ABCDEFGHJKLMNO');
  console.log('  ✓ Partial overlap across boundary trimmed 8 redundant bytes; retransmission counted.');

  // 4. Complete Duplicate Retransmission Suppression
  console.log('[20.4] Testing complete duplicate retransmission suppression...');
  const framesDuplicate = [
    {
      frameNumber: 1,
      timestamp: new Date(baseTime).toISOString(),
      srcIp: '192.168.1.50',
      srcPort: 54321,
      dstIp: '10.0.0.1',
      dstPort: 80,
      protocol: 'TCP',
      tcp: { seq: 1000, ack: 500, flags: { ack: true } },
      payload: Buffer.from('HELLO_WORLD_DATA')
    },
    {
      frameNumber: 2, // Complete duplicate
      timestamp: new Date(baseTime + 15).toISOString(),
      srcIp: '192.168.1.50',
      srcPort: 54321,
      dstIp: '10.0.0.1',
      dstPort: 80,
      protocol: 'TCP',
      tcp: { seq: 1000, ack: 500, flags: { ack: true } },
      payload: Buffer.from('HELLO_WORLD_DATA')
    }
  ];

  const streamDup = TcpStreamReassembler.reconstructStream(framesDuplicate);
  assert.strictEqual(streamDup.totalClientBytes, 16);
  assert.strictEqual(streamDup.retransmissions, 1);
  assert.strictEqual(streamDup.chunks[0].dataAscii, 'HELLO_WORLD_DATA');
  console.log('  ✓ Full duplicate retransmission discarded cleanly.');

  // 5. TCP RST Connection Teardown
  console.log('[20.5] Testing TCP RST teardown detection...');
  const framesWithRst = [
    {
      frameNumber: 1,
      timestamp: new Date(baseTime).toISOString(),
      srcIp: '192.168.1.50',
      srcPort: 54321,
      dstIp: '10.0.0.1',
      dstPort: 80,
      protocol: 'TCP',
      tcp: { seq: 100, ack: 0, flags: { syn: true, ack: false } },
      payload: Buffer.alloc(0)
    },
    {
      frameNumber: 2,
      timestamp: new Date(baseTime + 5).toISOString(),
      srcIp: '10.0.0.1',
      srcPort: 80,
      dstIp: '192.168.1.50',
      dstPort: 54321,
      protocol: 'TCP',
      tcp: { seq: 0, ack: 101, flags: { rst: true, ack: true } },
      payload: Buffer.alloc(0)
    }
  ];

  const streamRst = TcpStreamReassembler.reconstructStream(framesWithRst);
  assert.strictEqual(streamRst.isReset, true, 'isReset must be true when RST frame is present');
  console.log('  ✓ TCP RST flag identified and connection marked as reset.');

  console.log('\n>>> ALL SUITE 20 TCP STREAM WRAPAROUND TESTS COMPLETED SUCCESSFULLY.\n');
}

if (require.main === module) {
  runTcpStreamWraparoundTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 20 failed:', err);
    process.exit(1);
  });
}

module.exports = { runTcpStreamWraparoundTests };
