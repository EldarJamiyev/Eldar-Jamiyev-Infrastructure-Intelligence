const { packetStreamer } = require('../../src/network/packet-streaming/packet-streamer');

packetStreamer.startStreaming((type, frame) => {});

setTimeout(() => {
  packetStreamer.stopStreaming();
  const frames = packetStreamer.getRecentFrames(50);
  console.log('Total frames captured:', frames.length);
  
  let zeroDest = 0;
  let zeroSrc = 0;
  let fakePayloads = 0;

  for (const f of frames) {
    if (f.dstIp === '0.0.0.0' || f.dstPort === 0) zeroDest++;
    if (f.srcIp === '0.0.0.0' || f.srcPort === 0) zeroSrc++;
    if (f.hexDump && f.hexDump.includes('traffic [')) fakePayloads++;
  }

  console.log('Frames with 0.0.0.0 or 0 destination:', zeroDest);
  console.log('Frames with 0.0.0.0 or 0 source:', zeroSrc);
  console.log('Frames with synthetic string payload:', fakePayloads);

  console.log('\nSample captured wire frames:');
  for (const f of frames.slice(0, 8)) {
    console.log(`  Frame #${f.frameNumber} [${f.protocol}] ${f.srcIp}:${f.srcPort} -> ${f.dstIp}:${f.dstPort} (${f.length} B) [${f.processName}] Info: ${f.info}`);
  }
  process.exit(0);
}, 2500);
