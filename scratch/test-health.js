const http = require('http');
console.log('Sending request to 127.0.0.1:8443/api/health...');
const req = http.request({
  host: '127.0.0.1',
  port: 8443,
  path: '/api/health',
  method: 'GET',
  headers: {
    'Connection': 'close'
  }
}, (res) => {
  console.log('STATUS:', res.statusCode);
  res.on('data', c => console.log('CHUNK:', c.toString()));
  res.on('end', () => {
    console.log('DONE');
    process.exit(0);
  });
});
req.on('error', e => console.error('ERROR:', e.message));
req.end();
