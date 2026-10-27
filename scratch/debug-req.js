const { app } = require('../src/server');
const http = require('http');

const server = http.createServer(app);
server.listen(9999, '127.0.0.1', () => {
  console.log('Listening on 9999');
  http.get('http://127.0.0.1:9999/api/health', (res) => {
    console.log('Got response:', res.statusCode);
    let d = '';
    res.on('data', c => d += c);
    res.on('end', () => {
      console.log('Body:', d);
      server.close();
      process.exit(0);
    });
  }).on('error', err => {
    console.error('Req error:', err);
    process.exit(1);
  });
});
