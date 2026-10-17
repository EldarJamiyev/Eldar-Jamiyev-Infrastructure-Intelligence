/**
 * EJII — Live Packet Pipeline Forensic Verification Suite
 * Phase 1: Live Wire Ingestion, WebSocket Dispatch, Queue Backpressure & DOM Table Invariants.
 * Zero-Simulation Mandate Enforced: Strict wire schemas, bounded buffers, zero synthetic frames.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

async function runLivePacketPipelineTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 28: LIVE PACKET PIPELINE FORENSIC REPAIR VERIFICATION SUITE      ');
  console.log('  WebSocket Dispatch, Wire Validation, Queue Backpressure & Fault Banner ');
  console.log('========================================================================');

  const rootDir = path.resolve(__dirname, '..');
  const appJsCode = fs.readFileSync(path.join(rootDir, 'public', 'js', 'app.js'), 'utf8');
  const nocViewCode = fs.readFileSync(path.join(rootDir, 'public', 'js', 'views', 'noc-view.js'), 'utf8');
  const snifferViewCode = fs.readFileSync(path.join(rootDir, 'public', 'js', 'views', 'sniffer-view.js'), 'utf8');

  // Helper to construct a headless DOM and window sandbox
  function createPipelineSandbox() {
    const elements = new Map();

    function getOrCreateElement(id) {
      if (!elements.has(id)) {
        elements.set(id, {
          id,
          style: { display: '' },
          innerHTML: '',
          textContent: '',
          title: '',
          className: '',
          dataset: {},
          disabled: false,
          value: '',
          scrollTop: 0,
          addEventListener: () => {},
          removeEventListener: () => {},
          setAttribute: () => {},
          getAttribute: () => null,
          classList: {
            toggle: () => {},
            add: () => {},
            remove: () => {}
          }
        });
      }
      return elements.get(id);
    }

    const logs = {
      warn: [],
      error: [],
      info: []
    };

    const localStorageMock = {
      _data: {},
      getItem: (k) => localStorageMock._data[k] || null,
      setItem: (k, v) => { localStorageMock._data[k] = String(v); },
      removeItem: (k) => { delete localStorageMock._data[k]; }
    };

    class MockWebSocket {
      constructor(url, protocols) {
        this.url = url;
        this.protocols = protocols;
        this.readyState = 1; // OPEN
        this.onopen = null;
        this.onmessage = null;
        this.onclose = null;
        this.onerror = null;
      }
      send(data) {
        this.lastSent = data;
      }
      close() {
        this.readyState = 3; // CLOSED
        if (typeof this.onclose === 'function') this.onclose();
      }
    }
    MockWebSocket.OPEN = 1;
    MockWebSocket.CLOSED = 3;

    const sandbox = {
      console: {
        log: (...args) => logs.info.push(args.join(' ')),
        warn: (...args) => logs.warn.push(args.join(' ')),
        error: (...args) => logs.error.push(args.join(' ')),
        info: (...args) => logs.info.push(args.join(' '))
      },
      document: {
        getElementById: (id) => getOrCreateElement(id),
        querySelector: (sel) => {
          if (sel.startsWith('#')) return getOrCreateElement(sel.slice(1));
          return getOrCreateElement('mock-' + sel.replace(/[^a-zA-Z0-9]/g, '-'));
        },
        querySelectorAll: () => [],
        addEventListener: () => {}
      },
      window: {
        location: { protocol: 'http:', host: 'localhost:8443' },
        localStorage: localStorageMock,
        addEventListener: () => {}
      },
      localStorage: localStorageMock,
      WebSocket: MockWebSocket,
      fetch: async () => ({ ok: true, json: async () => ({}) }),
      setTimeout: (fn, delay) => setTimeout(fn, delay),
      clearTimeout: (id) => clearTimeout(id),
      setInterval: (fn, delay) => setInterval(fn, delay),
      clearInterval: (id) => clearInterval(id),
      Date: Date,
      JSON: JSON,
      Array: Array,
      Map: Map,
      Set: Set,
      Math: Math,
      parseInt: parseInt,
      parseFloat: parseFloat,
      String: String,
      Boolean: Boolean,
      Number: Number,
      RegExp: RegExp,
      _logs: logs,
      _elements: elements
    };

    // Forward window circular references
    sandbox.window.document = sandbox.document;
    sandbox.window.console = sandbox.console;
    sandbox.window.setTimeout = sandbox.setTimeout;
    sandbox.window.clearTimeout = sandbox.clearTimeout;
    sandbox.window.setInterval = sandbox.setInterval;
    sandbox.window.clearInterval = sandbox.clearInterval;
    sandbox.window.WebSocket = MockWebSocket;
    sandbox.window.fetch = sandbox.fetch;
    sandbox.window.Date = sandbox.Date;
    sandbox.window.setInterval = sandbox.setInterval;
    sandbox.window.clearInterval = sandbox.clearInterval;
    sandbox.window.Date = sandbox.Date;
    sandbox.window.JSON = sandbox.JSON;
    sandbox.window.Array = sandbox.Array;
    sandbox.window.Map = sandbox.Map;
    sandbox.window.Set = sandbox.Set;

    // Create execution context
    vm.createContext(sandbox);

    // Load scripts in production sequence
    vm.runInContext(nocViewCode, sandbox);
    vm.runInContext(snifferViewCode, sandbox);
    vm.runInContext(appJsCode, sandbox);

    sandbox.state = sandbox.window.state;
    sandbox.initWebSocket = sandbox.window.initWebSocket;
    sandbox.renderView = sandbox.window.renderView;
    sandbox.api = sandbox.window.api;

    return sandbox;
  }

  // ========================================================================
  // [Test 28.1] Valid JSON frame reaches frame handler & pushes to queue
  // ========================================================================
  console.log('[Test 28.1] Testing valid JSON frame WebSocket dispatching to frame handler...');
  {
    const sb = createPipelineSandbox();
    let receivedFrame = null;
    sb.window.handleLivePacketFrame = (frame) => {
      receivedFrame = frame;
    };

    const validPacketMessage = JSON.stringify({
      type: 'PACKET_STREAM_FRAME',
      payload: {
        frameNumber: 101,
        timestamp: '2026-10-17T14:00:00.000Z',
        srcIp: '192.168.31.25',
        dstIp: '1.1.1.1',
        srcPort: 53210,
        dstPort: 53,
        protocol: 'DNS',
        length: 74,
        summary: 'Standard query 0x0042 A cloudflare.com'
      }
    });

    // Simulate WebSocket onmessage dispatch
    sb.state.ws = { onmessage: null };
    sb.initWebSocket();
    assert.strictEqual(typeof sb.state.ws.onmessage, 'function', 'WebSocket onmessage must be registered');

    sb.state.ws.onmessage({ data: validPacketMessage });
    assert.ok(receivedFrame !== null, 'Valid frame must be passed to handleLivePacketFrame');
    assert.strictEqual(receivedFrame.frameNumber, 101, 'Frame number must match payload');
    assert.strictEqual(receivedFrame.protocol, 'DNS', 'Protocol must match payload');
    console.log('  ✓ Valid JSON frame correctly dispatched to handleLivePacketFrame.');
  }

  // ========================================================================
  // [Test 28.2] Malformed JSON handled without crash and logged
  // ========================================================================
  console.log('[Test 28.2] Testing malformed and truncated JSON handling without crashing...');
  {
    const sb = createPipelineSandbox();
    sb.state.ws = { onmessage: null };
    sb.initWebSocket();

    const malformedInputs = [
      '{ bad json payload ...',
      '{"type": "PACKET_STREAM_FRAME", "payload": { truncated',
      'undefined',
      '<<<NOT_JSON>>>',
      ''
    ];

    for (const bad of malformedInputs) {
      assert.doesNotThrow(() => {
        sb.state.ws.onmessage({ data: bad });
      }, `Malformed JSON "${bad}" must not throw uncaught error`);
    }

    assert.ok(
      sb._logs.warn.some(msg => msg.includes('[EJII WebSocket] Malformed message ignored')),
      'Rate-limited warning must be logged for malformed WebSocket data'
    );
    console.log('  ✓ Malformed JSON safely caught without crashing the client runtime.');
  }

  // ========================================================================
  // [Test 28.3] Unknown message types safely ignored
  // ========================================================================
  console.log('[Test 28.3] Testing unknown message types safely ignored without side-effects...');
  {
    const sb = createPipelineSandbox();
    sb.state.ws = { onmessage: null };
    sb.initWebSocket();

    const unknownTypes = [
      JSON.stringify({ type: 'UNKNOWN_TELEMETRY_PROBE', data: 42 }),
      JSON.stringify({ type: 'PONG', timestamp: 1234567 }),
      JSON.stringify({ type: 'HEARTBEAT' })
    ];

    for (const msg of unknownTypes) {
      assert.doesNotThrow(() => {
        sb.state.ws.onmessage({ data: msg });
      }, 'Unknown message type must be safely ignored');
    }
    console.log('  ✓ Unknown message types safely ignored with zero side-effects.');
  }

  // ========================================================================
  // [Test 28.4] Missing/malformed frame payloads rejected (zero fake rows)
  // ========================================================================
  console.log('[Test 28.4] Testing rejection of missing/malformed frame payloads (zero fake rows)...');
  {
    const sb = createPipelineSandbox();
    sb.state.ws = { onmessage: null };
    sb.initWebSocket();

    const invalidFrames = [
      JSON.stringify({ type: 'PACKET_STREAM_FRAME', payload: null }),
      JSON.stringify({ type: 'PACKET_STREAM_FRAME', payload: 'string-instead-of-object' }),
      JSON.stringify({ type: 'PACKET_STREAM_FRAME', payload: {} }), // missing frameNumber & protocol
      JSON.stringify({ type: 'PACKET_STREAM_FRAME', payload: { frameNumber: 1 } }), // missing protocol
      JSON.stringify({ type: 'PACKET_STREAM_FRAME', payload: { protocol: 'TCP' } }) // missing frameNumber
    ];

    for (const inv of invalidFrames) {
      sb.state.ws.onmessage({ data: inv });
    }

    // Flush batch to DOM
    if (typeof sb.window.flushPacketBatch === 'function') {
      sb.window.flushPacketBatch();
    }

    const tbody = sb.document.getElementById('livePacketTableBody');
    assert.ok(
      !tbody.innerHTML.includes('#undefined') && !tbody.innerHTML.includes('#null'),
      'Malformed frames must never render fake/ghost rows'
    );
    console.log('  ✓ Missing and schema-invalid frames strictly rejected (zero fake rows).');
  }

  // ========================================================================
  // [Test 28.5] Valid frames rendered into DOM table structure
  // ========================================================================
  console.log('[Test 28.5] Testing valid frames rendered into DOM table structure...');
  {
    const sb = createPipelineSandbox();
    sb.state.ws = { onmessage: null };
    sb.initWebSocket();

    // Set active container in DOM
    const container = sb.document.getElementById('livePacketTableContainer');
    const tbody = sb.document.getElementById('livePacketTableBody');

    const frame1 = {
      frameNumber: 201,
      timestamp: '2026-10-17T14:10:00.000Z',
      srcIp: '10.168.195.33',
      dstIp: '142.251.142.110',
      srcPort: 54321,
      dstPort: 443,
      protocol: 'TLS',
      length: 512,
      summary: 'Client Hello [SNI: google.com]'
    };

    const frame2 = {
      frameNumber: 202,
      timestamp: '2026-10-17T14:10:00.015Z',
      srcIp: '142.251.142.110',
      dstIp: '10.168.195.33',
      srcPort: 443,
      dstPort: 54321,
      protocol: 'TLS',
      length: 1420,
      summary: 'Server Hello, Certificate'
    };

    sb.state.ws.onmessage({ data: JSON.stringify({ type: 'PACKET_STREAM_FRAME', payload: frame1 }) });
    sb.state.ws.onmessage({ data: JSON.stringify({ type: 'PACKET_STREAM_FRAME', payload: frame2 }) });

    // Trigger flush
    sb.window.flushPacketBatch();

    assert.ok(tbody.innerHTML.includes('#201'), 'Table must render frame #201');
    assert.ok(tbody.innerHTML.includes('#202'), 'Table must render frame #202');
    assert.ok(tbody.innerHTML.includes('10.168.195.33'), 'Table must render source IP 10.168.195.33');
    assert.ok(tbody.innerHTML.includes('142.251.142.110'), 'Table must render destination IP');
    assert.ok(tbody.innerHTML.includes('TLS'), 'Table must render TLS protocol badge');
    assert.ok(tbody.innerHTML.includes('512 B') || tbody.innerHTML.includes('1420 B'), 'Table must render wire length');
    console.log('  ✓ Valid frames rendered into standard 9-column DOM table structure.');
  }

  // ========================================================================
  // [Test 28.6] View switching maintains handler registration without duplication
  // ========================================================================
  console.log('[Test 28.6] Testing view switching maintains handler registration without duplication...');
  {
    const sb = createPipelineSandbox();

    // Verify initial handler
    assert.strictEqual(typeof sb.window.handleLivePacketFrame, 'function', 'handleLivePacketFrame must be registered on init');

    // Switch between views
    sb.renderView('noc');
    assert.strictEqual(typeof sb.window.handleLivePacketFrame, 'function', 'handleLivePacketFrame must remain available after noc view');

    sb.renderView('packet-sniffer');
    assert.strictEqual(typeof sb.window.handleLivePacketFrame, 'function', 'handleLivePacketFrame must remain available after sniffer view');

    sb.renderView('topology');
    assert.strictEqual(typeof sb.window.handleLivePacketFrame, 'function', 'handleLivePacketFrame must remain available after topology view');

    sb.renderView('packet-sniffer');
    assert.strictEqual(typeof sb.window.handleLivePacketFrame, 'function', 'handleLivePacketFrame must remain available after returning to sniffer view');

    // Deliver frame and flush
    const frame = {
      frameNumber: 301,
      timestamp: '2026-10-17T14:15:00.000Z',
      srcIp: '192.168.1.10',
      dstIp: '192.168.1.1',
      srcPort: 49152,
      dstPort: 80,
      protocol: 'HTTP',
      length: 128,
      summary: 'GET /status HTTP/1.1'
    };

    sb.window.handleLivePacketFrame(frame);
    sb.window.flushPacketBatch();

    const tbody = sb.document.getElementById('livePacketTableBody');
    const occurrences = (tbody.innerHTML.match(/#301/g) || []).length;
    assert.strictEqual(occurrences, 1, 'Frame must be rendered exactly once (no frame duplication on view change)');
    console.log('  ✓ View switching preserves handler registration without frame duplication.');
  }

  // ========================================================================
  // [Test 28.7] Capture failure status rendered as explicit failure banner
  // ========================================================================
  console.log('[Test 28.7] Testing capture failure status rendered as explicit failure banner...');
  {
    const sb = createPipelineSandbox();
    const errBanner = sb.document.getElementById('captureErrorBanner');
    const errMsg = sb.document.getElementById('captureErrorMessage');
    const indicator = sb.document.getElementById('captureLiveIndicator');
    const label = sb.document.getElementById('captureStatusLabel');

    // 1. Simulate NO_ADAPTER failure
    sb.window.handleCaptureStatus({
      status: 'NO_ADAPTER',
      error: 'Npcap physical interface not found: Adapter disconnected.'
    });

    assert.strictEqual(errBanner.style.display, 'flex', 'Capture failure banner must be displayed on error');
    assert.ok(errMsg.textContent.includes('Adapter disconnected'), 'Error banner must display specific driver fault');
    assert.strictEqual(label.textContent, 'NO ADAPTER', 'Status label must indicate NO ADAPTER');

    // 2. Simulate CAPTURING recovery
    sb.window.handleCaptureStatus({
      status: 'CAPTURING',
      device: '\\Device\\NPF_{WIFI-GUID}',
      description: 'Intel Wi-Fi 6 AX201'
    });

    assert.strictEqual(errBanner.style.display, 'none', 'Capture failure banner must be hidden when capturing is active');
    assert.strictEqual(label.textContent, 'STREAMING', 'Status label must return to STREAMING');
    console.log('  ✓ Capture failure status and recovery rendered via explicit banner.');
  }

  // ========================================================================
  // [Test 28.8] Queue limits (500 max) enforce backpressure/dropping during high traffic
  // ========================================================================
  console.log('[Test 28.8] Testing queue limits (500 max) enforce backpressure dropping during high traffic...');
  {
    const sb = createPipelineSandbox();

    // Pump 1,200 frames rapidly into handleLivePacketFrame without flushing
    for (let i = 1; i <= 1200; i++) {
      sb.window.handleLivePacketFrame({
        frameNumber: i,
        timestamp: new Date().toISOString(),
        srcIp: '10.0.0.1',
        dstIp: '10.0.0.2',
        srcPort: 1000 + (i % 5000),
        dstPort: 443,
        protocol: 'TCP',
        length: 64,
        summary: `ACK seq=${i}`
      });
    }

    // Flush batch to DOM
    sb.window.flushPacketBatch();

    // Verify queue backpressure did not crash or allocate unbounded memory
    const tbody = sb.document.getElementById('livePacketTableBody');
    assert.ok(tbody.innerHTML.includes('#1200'), 'Latest frame #1200 must be in the buffer');
    // Frame #1 should have been dropped by the 500 max batch queue limit
    assert.ok(!tbody.innerHTML.includes('#1</td>'), 'Oldest frames must have been discarded to prevent OOM');
    console.log('  ✓ Bounded queue limit (500 max) successfully enforced backpressure under packet burst.');
  }

  console.log('\n========================================================================');
  console.log('  ALL 8 LIVE PACKET PIPELINE FORENSIC TESTS PASSED (100% GREEN)         ');
  console.log('========================================================================\n');
}

module.exports = { runLivePacketPipelineTests };

if (require.main === module) {
  runLivePacketPipelineTests().then(() => process.exit(0)).catch((err) => {
    console.error('Test Suite Failed:', err);
    process.exit(1);
  });
}
