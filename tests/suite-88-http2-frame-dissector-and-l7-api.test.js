// tests/suite-88-http2-frame-dissector-and-l7-api.test.js
/**
 * EJII Test Suite 88: HTTP/2 (RFC 9113) Frame Dissector & Deep L7 REST API Contract
 * Verifies HTTP/2 connection preface (PRI * HTTP/2.0), 9-byte frame header dissection,
 * SETTINGS/DATA/HEADERS frame types, and live REST API endpoints /api/network/dissect-l7 & /api/network/l7-protocol-stats.
 */

'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { L7DeepProtocolDissector } = require('../src/sniffer/l7-deep-protocol-dissector');

async function runSuite88Http2FrameDissectorAndL7Api() {
  console.log('========================================================================');
  console.log('  === [SUITE 88] HTTP/2 FRAME DISSECTOR & DEEP L7 REST API ===          ');
  console.log('========================================================================\n');

  // [88.1] HTTP/2 Client Connection Preface Dissection
  console.log('[Test 88.1] Dissecting RFC 9113 HTTP/2 Client Connection Preface (24 bytes)...');
  const prefaceStr = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
  const prefaceBuf = Buffer.from(prefaceStr, 'ascii');

  const h2Preface = L7DeepProtocolDissector.dissectHttp2Frame(prefaceBuf);
  assert.ok(h2Preface, 'Must dissect HTTP/2 preface');
  assert.strictEqual(h2Preface.isHttp2, true);
  assert.strictEqual(h2Preface.hasConnectionPreface, true);
  console.log('  ✓ 24-byte HTTP/2 client preface validated.');

  // [88.2] HTTP/2 SETTINGS Frame (Type 0x4) Following Preface
  console.log('[Test 88.2] Dissecting HTTP/2 SETTINGS frame on Stream 0...');
  // 9-byte header:
  // Length (24-bit): 6 bytes (one setting: SETTINGS_HEADER_TABLE_SIZE = 4096)
  // Type: 0x4 (SETTINGS)
  // Flags: 0x0
  // Stream ID: 0x00000000
  // Payload (6 bytes): ID 0x0001 (16-bit), Value 0x00001000 (32-bit: 4096)
  const settingsFrame = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x06]), // Length = 6
    Buffer.from([0x04]),             // Type = SETTINGS
    Buffer.from([0x00]),             // Flags = 0
    Buffer.from([0x00, 0x00, 0x00, 0x00]), // Stream ID = 0
    Buffer.from([0x00, 0x01, 0x00, 0x00, 0x10, 0x00]) // Payload: 4096
  ]);

  const h2SettingsOnly = L7DeepProtocolDissector.dissectHttp2Frame(settingsFrame);
  assert.ok(h2SettingsOnly, 'Must parse stand-alone SETTINGS frame');
  assert.strictEqual(h2SettingsOnly.isHttp2, true);
  assert.strictEqual(h2SettingsOnly.frames.length, 1);
  assert.strictEqual(h2SettingsOnly.frames[0].typeName, 'SETTINGS');
  assert.strictEqual(h2SettingsOnly.frames[0].streamId, 0);
  assert.strictEqual(h2SettingsOnly.frames[0].length, 6);
  console.log(`  ✓ SETTINGS frame parsed: stream=${h2SettingsOnly.frames[0].streamId}, len=${h2SettingsOnly.frames[0].length}`);

  // [88.3] Combined Preface + SETTINGS + HEADERS Multi-Frame Dissection
  console.log('[Test 88.3] Dissecting combined Preface + SETTINGS + HEADERS frame stream...');
  // HEADERS frame on stream 1: Length = 12, Type = 0x1, Flags = 0x5 (END_STREAM | END_HEADERS), Stream ID = 1
  const headersFrame = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x0c]), // Length = 12
    Buffer.from([0x01]),             // Type = HEADERS
    Buffer.from([0x05]),             // Flags = 0x05
    Buffer.from([0x00, 0x00, 0x00, 0x01]), // Stream ID = 1
    Buffer.alloc(12, 0x82)           // HPACK payload dummy
  ]);

  const multiFrameStream = Buffer.concat([prefaceBuf, settingsFrame, headersFrame]);
  const h2Multi = L7DeepProtocolDissector.dissectHttp2Frame(multiFrameStream);
  assert.ok(h2Multi, 'Must parse multi-frame stream');
  assert.strictEqual(h2Multi.hasConnectionPreface, true);
  assert.strictEqual(h2Multi.frames.length, 2);
  assert.strictEqual(h2Multi.frames[0].typeName, 'SETTINGS');
  assert.strictEqual(h2Multi.frames[1].typeName, 'HEADERS');
  assert.strictEqual(h2Multi.frames[1].streamId, 1);
  console.log(`  ✓ Multi-frame sequence parsed: ${h2Multi.frames.map(f => f.typeName).join(' -> ')}`);

  // [88.4] REST API Endpoint: POST /api/network/dissect-l7
  console.log('[Test 88.4] Testing REST API POST /api/network/dissect-l7 via Express router stack...');
  const routesNetwork = require('../src/api/routes-network');
  const dissectLayer = routesNetwork.stack.find(s => s.route && s.route.path === '/dissect-l7');
  assert.ok(dissectLayer, 'Route /dissect-l7 must be registered in routes-network.js');

  let postResponseData = null;
  const mockReqPost = {
    body: { hex: multiFrameStream.toString('hex') }
  };
  const mockResPost = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(data) { postResponseData = data; return this; }
  };

  const postHandler = dissectLayer.route.stack[dissectLayer.route.stack.length - 1].handle;
  await postHandler(mockReqPost, mockResPost, () => {});

  assert.ok(postResponseData, 'Route must respond with JSON');
  assert.strictEqual(postResponseData.success, true);
  assert.strictEqual(postResponseData.identifiedProtocol, 'HTTP/2');
  assert.ok(postResponseData.http2, 'HTTP/2 data must be present in response');
  assert.strictEqual(postResponseData.http2.frames.length, 2);
  console.log(`  ✓ POST /api/network/dissect-l7 returned: protocol=${postResponseData.identifiedProtocol}, frames=${postResponseData.http2.frames.length}`);

  // [88.5] REST API Endpoint: GET /api/network/l7-protocol-stats
  console.log('[Test 88.5] Testing REST API GET /api/network/l7-protocol-stats via Express router stack...');
  const statsLayer = routesNetwork.stack.find(s => s.route && s.route.path === '/l7-protocol-stats');
  assert.ok(statsLayer, 'Route /l7-protocol-stats must be registered in routes-network.js');

  let getResponseData = null;
  const mockReqGet = { query: {} };
  const mockResGet = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(data) { getResponseData = data; return this; }
  };

  const getHandler = statsLayer.route.stack[statsLayer.route.stack.length - 1].handle;
  await getHandler(mockReqGet, mockResGet, () => {});

  assert.ok(getResponseData, 'Route must respond with JSON');
  assert.strictEqual(getResponseData.success, true);
  assert.ok(getResponseData.protocols, 'Protocols map must be present');
  assert.ok(getResponseData.protocols.quicRfc9000, 'QUIC stats present');
  assert.ok(getResponseData.protocols.sshHassh, 'SSH stats present');
  assert.ok(getResponseData.protocols.smb2Smb3, 'SMB stats present');
  assert.ok(getResponseData.protocols.http2Rfc9113, 'HTTP/2 stats present');
  console.log(`  ✓ GET /api/network/l7-protocol-stats returned with all 4 deep protocol categories.`);

  console.log('\n========================================================================');
  console.log('  SUITE 88 PASSED: HTTP/2 FRAME DISSECTOR & L7 API 100% GREEN           ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite88Http2FrameDissectorAndL7Api().catch((err) => {
    console.error('Suite 88 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite88Http2FrameDissectorAndL7Api,
  runSuite88: runSuite88Http2FrameDissectorAndL7Api
};
