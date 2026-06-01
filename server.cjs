const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;
const DIR = path.join(__dirname, 'build');

console.log('Build dir:', DIR);
console.log('Build exists:', fs.existsSync(DIR));
if (fs.existsSync(DIR)) {
  console.log('Build contents:', fs.readdirSync(DIR).join(', '));
}

const mime = {
  '.html':'text/html;charset=utf-8',
  '.js':'application/javascript',
  '.css':'text/css',
  '.json':'application/json',
  '.png':'image/png',
  '.ico':'image/x-icon',
  '.svg':'image/svg+xml',
  '.woff2':'font/woff2',
};

http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  let file = path.join(DIR, url === '/' ? 'index.html' : url);
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    file = path.join(DIR, 'index.html');
  }
  const type = mime[path.extname(file)] || 'application/octet-stream';
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, {'Content-Type': type});
    res.end(data);
  });
}).listen(PORT, '0.0.0.0', () => {
  console.log('Server on port ' + PORT);
});
