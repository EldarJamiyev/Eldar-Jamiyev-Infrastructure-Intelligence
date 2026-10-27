const { app } = require('../src/server');

console.log('Router layers:');
app._router.stack.forEach((layer, idx) => {
  const name = layer.name || (layer.route ? `Route: ${layer.route.path}` : 'anonymous');
  console.log(`  [${idx}] ${name}`);
});
process.exit(0);
