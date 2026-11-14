/**
 * Test Suite: Phase 5.0 Track 4 Lock-Free SharedArrayBuffer Ring Pipeline & Verified BPF JIT Engine
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  SharedRingPipeline,
  VerifiedBpfJitEngine
} = require('../src/network/packet-streaming/shared-ring-pipeline');
const {
  encodeBinaryPacketFrame,
  decodeBinaryPacketFrame,
  createSharedRingPipeline
} = require('../src/network/packet-streaming/binary-frame-codec');

describe('Phase 5.0 Track 4: Lock-Free SharedArrayBuffer Ring Pipeline & Verified BPF JIT', () => {

  test('Ring Buffer: power-of-2 validation and atomic cache-aligned initialization', () => {
    // Non power of 2 must throw
    assert.throws(() => new SharedRingPipeline(100), /power of 2/);
    assert.throws(() => new SharedRingPipeline(0), /power of 2/);

    const pipeline = new SharedRingPipeline(64, 128);
    const stats = pipeline.getStats();
    assert.equal(stats.capacity, 64);
    assert.equal(stats.occupancy, 0);
    assert.equal(stats.dropCount, 0);
    assert.equal(stats.utilizationPct, 0);
  });

  test('High-throughput atomic FIFO enqueue/dequeue with 100% byte fidelity', () => {
    const pipeline = new SharedRingPipeline(512, 128);
    const packetCount = 2000;

    const startNs = process.hrtime.bigint();
    for (let i = 0; i < packetCount; i++) {
      const payload = Buffer.from(`packet_seq_${i}_payload_data_${i * 7}`);
      const ok = pipeline.enqueuePacket(payload);
      assert.equal(ok, true, `Enqueue must succeed for packet ${i}`);

      const dequeued = pipeline.dequeuePacket();
      assert.ok(dequeued, `Dequeued packet ${i} must not be null`);
      assert.equal(Buffer.from(dequeued).toString(), payload.toString());
    }
    const elapsedMs = Number(process.hrtime.bigint() - startNs) / 1e6;

    const stats = pipeline.getStats();
    assert.equal(stats.occupancy, 0);
    assert.equal(stats.dropCount, 0);
    assert.ok(elapsedMs < 100.0, `2000 packets enqueue/dequeue should complete in < 100ms, took ${elapsedMs.toFixed(2)}ms`);
  });

  test('Overflow handling: non-blocking frame drop and atomic drop counter', () => {
    const smallPipeline = new SharedRingPipeline(16, 64);

    // Fill ring completely
    for (let i = 0; i < 16; i++) {
      const ok = smallPipeline.enqueuePacket(Buffer.from(`p_${i}`));
      assert.equal(ok, true);
    }

    assert.equal(smallPipeline.getStats().occupancy, 16);
    assert.equal(smallPipeline.getStats().utilizationPct, 100);

    // 17th enqueue must fail and increment drop counter
    const dropOk = smallPipeline.enqueuePacket(Buffer.from('dropped_frame'));
    assert.equal(dropOk, false);
    assert.equal(smallPipeline.getStats().dropCount, 1);

    // Dequeue 4 packets
    for (let i = 0; i < 4; i++) {
      const pkt = smallPipeline.dequeuePacket();
      assert.equal(Buffer.from(pkt).toString(), `p_${i}`);
    }

    assert.equal(smallPipeline.getStats().occupancy, 12);

    // Now enqueue should succeed again
    const recoveryOk = smallPipeline.enqueuePacket(Buffer.from('recovered_frame'));
    assert.equal(recoveryOk, true);
    assert.equal(smallPipeline.getStats().dropCount, 1);
  });

  test('Verified BPF JIT: safety checks reject backward loops, out-of-bounds, and malformed filters', () => {
    // 1. Backward loop branch rejection (prevents infinite loop hangs)
    const loopProgram = [
      { opcode: 'LD_B', offset: 0 },
      { opcode: 'JEQ', val: 0x45, jt: 0, jf: 2 }, // jt=0 branches backward to instruction 0!
      { opcode: 'RET', val: 1 }
    ];
    const loopCheck = VerifiedBpfJitEngine.validateProgram(loopProgram);
    assert.equal(loopCheck.valid, false);
    assert.ok(loopCheck.error.includes('Backward or loop branch'));

    // 2. Out-of-bounds memory load offset rejection
    const oobProgram = [
      { opcode: 'LD_W', offset: 2000 }, // offset 2000 > max expected packet length 1518
      { opcode: 'RET', val: 1 }
    ];
    const oobCheck = VerifiedBpfJitEngine.validateProgram(oobProgram, 1518);
    assert.equal(oobCheck.valid, false);
    assert.ok(oobCheck.error.includes('Out-of-bounds'));

    // 3. Missing terminal RET instruction
    const noRetProgram = [
      { opcode: 'LD_B', offset: 9 }
    ];
    const noRetCheck = VerifiedBpfJitEngine.validateProgram(noRetProgram);
    assert.equal(noRetCheck.valid, false);
    assert.ok(noRetCheck.error.includes('lacks terminal RET'));
  });

  test('Verified BPF JIT: validates forward DAG filter and executes high-speed packet classification', () => {
    // Filter: Match IPv4 TCP packets destined for port 443 (HTTPS)
    // In raw IPv4 packet (assuming Ethernet stripped):
    // Offset 9: IP Protocol (6 = TCP)
    // Offset 22..23: TCP Destination Port (443 = 0x01BB)
    const httpsFilter = [
      { opcode: 'LD_B', offset: 9 },                 // Load IP protocol byte
      { opcode: 'JEQ', val: 6, jt: 2, jf: 4 },      // If TCP (6), jump to inst 2; else jump to 4
      { opcode: 'LD_H', offset: 22 },                // Load 16-bit destination port
      { opcode: 'JEQ', val: 443, jt: 5, jf: 4 },    // If port 443, jump to 5 (accept); else jump to 4 (drop)
      { opcode: 'RET', val: 0 },                    // Drop packet
      { opcode: 'RET', val: 1 }                     // Accept packet
    ];

    const validation = VerifiedBpfJitEngine.validateProgram(httpsFilter);
    assert.equal(validation.valid, true);
    assert.equal(validation.isForwardAcyclicDag, true);
    assert.equal(validation.instructionCount, 6);

    // Matching packet (TCP port 443)
    const matchingPacket = new Uint8Array(40);
    matchingPacket[9] = 6;      // TCP
    matchingPacket[22] = 0x01;  // Port 443 MSB
    matchingPacket[23] = 0xBB;  // Port 443 LSB

    // Non-matching packet (UDP port 53)
    const nonMatchingPacket = new Uint8Array(40);
    nonMatchingPacket[9] = 17;   // UDP
    nonMatchingPacket[22] = 0x00;
    nonMatchingPacket[23] = 0x35; // Port 53

    const matchVerdict = VerifiedBpfJitEngine.execute(httpsFilter, matchingPacket);
    assert.equal(matchVerdict, true, 'Filter should accept TCP 443 packet');

    const nonMatchVerdict = VerifiedBpfJitEngine.execute(httpsFilter, nonMatchingPacket);
    assert.equal(nonMatchVerdict, false, 'Filter should reject UDP 53 packet');

    // Microbenchmark: 10,000 executions should run in < 15ms
    const startBench = process.hrtime.bigint();
    for (let i = 0; i < 10000; i++) {
      VerifiedBpfJitEngine.execute(httpsFilter, matchingPacket);
    }
    const benchMs = Number(process.hrtime.bigint() - startBench) / 1e6;
    assert.ok(benchMs < 30.0, `10,000 BPF filter executions took ${benchMs.toFixed(2)}ms (should be < 30ms)`);
  });

  test('Integration with binary-frame-codec: round-trip binary packet frames across SharedRingPipeline', () => {
    const ring = createSharedRingPipeline(128, 256);

    const frameData = {
      timestamp: Date.now(),
      protocol: 'TCP',
      srcIp: '192.168.1.50',
      dstIp: '10.0.0.1',
      srcPort: 54321,
      dstPort: 443,
      wireLength: 64,
      payloadSlice: Buffer.from('CLIENT_HELLO_TLS_PAYLOAD')
    };

    const encoded = encodeBinaryPacketFrame(frameData);
    assert.ok(encoded.length > 32);

    const enqueued = ring.enqueuePacket(encoded);
    assert.equal(enqueued, true);

    const dequeued = ring.dequeuePacket();
    assert.ok(dequeued);

    const decoded = decodeBinaryPacketFrame(Buffer.from(dequeued));
    assert.equal(decoded.protocolName, 'TCP');
    assert.equal(decoded.srcIp, '192.168.1.50');
    assert.equal(decoded.dstIp, '10.0.0.1');
    assert.equal(decoded.srcPort, 54321);
    assert.equal(decoded.dstPort, 443);
    assert.equal(Buffer.from(decoded.payloadSlice).toString('utf-8'), 'CLIENT_HELLO_TLS_PAYLOAD');
  });

});
