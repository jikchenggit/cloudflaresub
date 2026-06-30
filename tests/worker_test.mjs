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
    nodeLinks: 'vless://f2c661f3-3c54-4e08-aa43-3bff1f4beb4c@104.20.43.246:443?encryption=mlkem768x25519plus.random.0rtt&security=tls&sni=avghost.959515.xyz&type=xhttp&host=avghost.959515.xyz&path=%2Favghost&mode=auto&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#VLESS-XHTTP-TEST',
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

console.log('worker test passed');
