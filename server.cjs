const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = '0.0.0.0';
const BUILD_DIR = path.join(__dirname, 'build');

const mime = {
  '.html':'text/html','.js':'application/javascript',
  '.css':'text/css','.json':'application/json',
  '.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml',
  '.ico':'image/x-icon','.woff2':'font/woff2','.woff':'font/woff',
  '.ttf':'font/ttf','.webmanifest':'application/manifest+json'
};

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0].split('#')[0];
  let file = path.join(BUILD_DIR, url === '/' ? 'index.html' : url);

  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    file = path.join(BUILD_DIR, 'index.html');
  }

  const ext = path.extname(file);
  const type = mime[ext] || 'application/octet-stream';

  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, {
      'Content-Type': type,
      'Cache-Control': ext === '.html' ? 'no-cache, no-store' : 'public,max-age=31536000,immutable',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(data);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`LearnThreatOps running on ${HOST}:${PORT}`);
});

server.on('error', (e) => {
  console.error('Server error:', e);
  process.exit(1);
});
