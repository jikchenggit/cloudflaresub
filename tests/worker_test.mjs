import assert from 'node:assert/strict';
import worker from '../src/worker.js';

// Mock KV Store
const mockKv = {
  store: {},
  async get(key) {
    return this.store[key] || null;
  },
  async put(key, value) {
    this.store[key] = value;
  }
};

const env = {
  SUB_STORE: mockKv,
  SUB_ACCESS_TOKEN: 'test-token',
  ASSETS: {
    async fetch() {
      return new Response('assets');
    }
  }
};

// Test /api/generate
const generateReq = new Request('http://localhost/api/generate', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    nodeLinks: 'vless://f2c661f3-3c54-4e08-aa43-3bff1f4beb4c@104.20.43.246:443?encryption=mlkem768x25519plus.random.0rtt&security=tls&sni=avghost.959515.xyz&type=xhttp&host=avghost.959515.xyz&path=%2Favghost&mode=auto&fp=chrome&alpn=h2%2Chttp%2F1.1%2Ch3&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#VLESS-XHTTP-TEST',
    preferredIps: '1.1.1.1#CF-IP',
    namePrefix: 'CF',
    keepOriginalHost: true
  })
});

const genRes = await worker.fetch(generateReq, env);
assert.equal(genRes.status, 200);
const genData = await genRes.json();
assert.equal(genData.ok, true);

const shortId = genData.shortId;
assert.ok(shortId);

// Test GET /sub/:id?target=clash&token=test-token
const clashUrl = new URL(genData.urls.clash);
const clashReq = new Request(clashUrl);
const clashRes = await worker.fetch(clashReq, env);
assert.equal(clashRes.status, 200);
const clashText = await clashRes.text();

assert.ok(clashText.includes('network: xhttp'));
assert.ok(clashText.includes('xhttp-opts:'));
assert.ok(clashText.includes('path: "/avghost"'));
assert.ok(clashText.includes('host: "avghost.959515.xyz"'));
assert.ok(clashText.includes('mode: "auto"'));
assert.ok(clashText.includes('extra:'));
assert.ok(clashText.includes('xPaddingBytes: "100-1000"'));
assert.ok(clashText.includes('client-fingerprint: "chrome"'));
assert.ok(clashText.includes('alpn: ["h2", "http/1.1", "h3"]'));
assert.ok(clashText.includes('skip-cert-verify: false'));

// Test GET /sub/:id?token=test-token (raw/base64)
const rawUrl = new URL(genData.urls.raw);
const rawReq = new Request(rawUrl);
const rawRes = await worker.fetch(rawReq, env);
assert.equal(rawRes.status, 200);
const rawBase64 = await rawRes.text();
const rawText = Buffer.from(rawBase64, 'base64').toString('utf8');

assert.ok(rawText.includes('encryption=mlkem768x25519plus.random.0rtt'));
assert.ok(rawText.includes('type=xhttp'));
assert.ok(rawText.includes('mode=auto'));
// Test KV missing check
const missingKvEnv = { ...env, SUB_STORE: undefined };
const missingRes = await worker.fetch(generateReq, missingKvEnv);
assert.equal(missingRes.status, 500);
const missingData = await missingRes.json();
assert.equal(missingData.ok, false);
assert.ok(missingData.error.includes('未检测到名为 SUB_STORE 的 KV'));

// Test IPv6 preferred IP parsing in handleGenerate
const ipv6GenerateReq = new Request('http://localhost/api/generate', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    nodeLinks: 'vless://f2c661f3-3c54-4e08-aa43-3bff1f4beb4c@104.20.43.246:443?type=ws#VLESS-TEST',
    preferredIps: '2606:4700:3001:7e68:af84:b71f:1571#IPv6-Bare\n[2a06:98c1:3100:a699:a7c2:b6ba:db02]:8405#IPv6-Bracketed',
    namePrefix: 'CF',
    keepOriginalHost: true
  })
});
const ipv6GenRes = await worker.fetch(ipv6GenerateReq, env);
assert.equal(ipv6GenRes.status, 200);
const ipv6GenData = await ipv6GenRes.json();
assert.equal(ipv6GenData.ok, true);

assert.equal(ipv6GenData.preview.length, 2);
assert.equal(ipv6GenData.preview[0].server, '2606:4700:3001:7e68:af84:b71f:1571');
assert.equal(ipv6GenData.preview[0].port, 443);
assert.equal(ipv6GenData.preview[1].server, '2a06:98c1:3100:a699:a7c2:b6ba:db02');
assert.equal(ipv6GenData.preview[1].port, 8405);

// Test that invalid IPv6 in preferred IP doesn't crash subscription generation
const invalidIpv6Req = new Request('http://localhost/api/generate', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    nodeLinks: 'vless://f2c661f3-3c54-4e08-aa43-3bff1f4beb4c@104.20.43.246:443?type=ws#VLESS-TEST',
    preferredIps: '2606:4700:3001:7e68:af84:b71f:1571#IPv6-Invalid-7-Blocks\n1.1.1.1#IPv4-Valid',
    namePrefix: 'CF',
    keepOriginalHost: true
  })
});
const invalidIpv6GenRes = await worker.fetch(invalidIpv6Req, env);
assert.equal(invalidIpv6GenRes.status, 200);
const invalidIpv6GenData = await invalidIpv6GenRes.json();
assert.equal(invalidIpv6GenData.ok, true);

const subId = invalidIpv6GenData.shortId;
const subUrl = new URL(`${clashUrl.origin}/sub/${subId}?token=test-token`);
const subRes = await worker.fetch(new Request(subUrl), env);
assert.equal(subRes.status, 200);
const subBase64 = await subRes.text();
const subDecoded = Buffer.from(subBase64, 'base64').toString('utf8');
assert.ok(subDecoded.includes('1.1.1.1'));
assert.ok(!subDecoded.includes('2606:4700:3001:7e68:af84:b71f:1571'));

// Test Clash list / provider format
const clashListUrl = new URL(`${clashUrl.origin}/sub/${shortId}?target=clash&list=true&token=test-token`);
const clashListRes = await worker.fetch(new Request(clashListUrl), env);
assert.equal(clashListRes.status, 200);
const clashListText = await clashListRes.text();
assert.ok(clashListText.startsWith('proxies:'));
assert.ok(!clashListText.includes('proxy-groups:'));
assert.ok(!clashListText.includes('rules:'));

console.log('worker test passed');
