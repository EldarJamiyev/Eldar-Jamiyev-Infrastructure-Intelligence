"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.runSuite74PcapngBinaryEngine = runSuite74PcapngBinaryEngine;
// tests/suite-74-pcapng-binary-engine.test.ts
const assert = __importStar(require("node:assert"));
const pcapng_engine_1 = require("../src/sniffer/pcapng-engine");
async function runSuite74PcapngBinaryEngine() {
    console.log('=== [SUITE 74] PCAPNG BINARY WRITER, PARSER & REPLAY ENGINE VERIFICATION ===');
    // 1. Serialization with SHB, IDB, EPB & 4-byte padding
    console.log('[74.1] Verifying Section Header Block (SHB), Interface Description Block (IDB) & EPB framing...');
    const sampleFrame1 = {
        timestampMs: 1710000000123,
        rawBytes: new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00]), // 14 bytes Ethernet frame
        metadata: {
            ja4: 't13d1516h2_8daaf6152771_b32607106037',
            flowId: 'flow-101',
            protocol: 'TCP'
        }
    };
    const sampleFrame2 = {
        timestampMs: 1710000000456,
        rawBytes: new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x06, 0x00, 0x01]), // 16 bytes ARP
        metadata: {
            ja4: 'a00d0000h0_000000000000_000000000000',
            anomaly: false
        }
    };
    const pcapngBinary = pcapng_engine_1.PcapngEngine.serializeFramesToPcapng([sampleFrame1, sampleFrame2]);
    assert.ok(pcapngBinary instanceof Uint8Array, 'Serialized output must be Uint8Array');
    assert.ok(pcapngBinary.length > 100, `Serialized binary length must exceed 100 bytes, got ${pcapngBinary.length}`);
    // Check SHB Magic: 0x0A0D0D0A (Little Endian bytes: 0x0A, 0x0D, 0x0D, 0x0A)
    const view = new DataView(pcapngBinary.buffer, pcapngBinary.byteOffset, pcapngBinary.byteLength);
    const shbMagic = view.getUint32(0, true);
    assert.strictEqual(shbMagic, pcapng_engine_1.PcapngEngine.SHB_MAGIC, 'First 4 bytes must be SHB Block Type (0x0A0D0D0A)');
    // Byte Order Magic at offset 8: 0x1A2B3C4D
    const bomMagic = view.getUint32(8, true);
    assert.strictEqual(bomMagic, pcapng_engine_1.PcapngEngine.BYTE_ORDER_MAGIC, 'Offset 8 must be Byte Order Magic (0x1A2B3C4D)');
    // 2. Deserialization & Integrity Verification
    console.log('[74.2] Verifying round-trip parsePcapng() decoding and metadata fidelity...');
    const parseResult = pcapng_engine_1.PcapngEngine.parsePcapng(pcapngBinary);
    assert.strictEqual(parseResult.valid, true, 'Parsed result must be valid');
    assert.strictEqual(parseResult.packets.length, 2, 'Must parse exactly 2 EPB packets');
    assert.strictEqual(parseResult.linkType, 1, 'LinkType must be 1 (LINKTYPE_ETHERNET)');
    assert.strictEqual(parseResult.snapLen, 65535, 'SnapLen must be 65535');
    assert.ok(parseResult.shbInfo.comment?.includes('EJII'), 'SHB comment must contain EJII reference');
    // Verify packet 1 properties
    const p1 = parseResult.packets[0];
    assert.strictEqual(p1.capturedLen, 14, 'Packet 1 captured length must be 14');
    assert.strictEqual(p1.originalLen, 14, 'Packet 1 original length must be 14');
    assert.strictEqual(p1.rawBytes.length, 14, 'Packet 1 raw bytes length must be 14');
    assert.deepStrictEqual(Array.from(p1.rawBytes), Array.from(sampleFrame1.rawBytes), 'Packet 1 payload bytes must match exactly');
    assert.strictEqual(p1.timestampMs, 1710000000123, 'Packet 1 timestamp ms must match exactly');
    assert.ok(p1.commentMetadata, 'Packet 1 must contain embedded comment metadata');
    assert.strictEqual(p1.commentMetadata?.ja4, 't13d1516h2_8daaf6152771_b32607106037', 'JA4 hash in metadata must match');
    assert.strictEqual(p1.commentMetadata?.flowId, 'flow-101', 'FlowId in metadata must match');
    // Verify packet 2 properties
    const p2 = parseResult.packets[1];
    assert.strictEqual(p2.capturedLen, 16, 'Packet 2 captured length must be 16');
    assert.strictEqual(p2.originalLen, 16, 'Packet 2 original length must be 16');
    assert.strictEqual(p2.timestampMs, 1710000000456, 'Packet 2 timestamp ms must match');
    assert.strictEqual(p2.commentMetadata?.anomaly, false, 'Packet 2 metadata must match');
    // 3. Corrupt Data & Truncation Invariants
    console.log('[74.3] Verifying corruption handling and boundary rejection...');
    const invalidBuf = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    const invalidParse = pcapng_engine_1.PcapngEngine.parsePcapng(invalidBuf);
    assert.strictEqual(invalidParse.valid, false, 'Invalid header must be rejected');
    assert.strictEqual(invalidParse.packets.length, 0, 'No packets returned from corrupt buffer');
    // 4. Verification of 4-byte padding invariant
    console.log('[74.4] Verifying 4-byte padding alignment across odd-length frames...');
    const oddFrame = {
        timestampMs: 1710000000999,
        rawBytes: new Uint8Array([0x01, 0x02, 0x03]), // 3 bytes -> needs 1 byte pad to 4
        metadata: { key: 'val' } // JSON = 13 bytes -> needs 3 bytes pad to 16
    };
    const oddPcapng = pcapng_engine_1.PcapngEngine.serializeFramesToPcapng([oddFrame]);
    assert.strictEqual(oddPcapng.length % 4, 0, 'Every PCAPNG block and overall buffer must be a multiple of 4 bytes');
    const oddParsed = pcapng_engine_1.PcapngEngine.parsePcapng(oddPcapng);
    assert.strictEqual(oddParsed.valid, true, 'Odd frame must parse cleanly');
    assert.strictEqual(oddParsed.packets[0].rawBytes.length, 3, 'Payload should preserve unpadded length (3 bytes)');
    console.log('✓ Suite 74 passed: PCAPNG Binary Engine 100% verified.\n');
}
if (require.main === module) {
    runSuite74PcapngBinaryEngine().then(() => process.exit(0)).catch(err => {
        console.error(err);
        process.exit(1);
    });
}
//# sourceMappingURL=suite-74-pcapng-binary-engine.test.js.map