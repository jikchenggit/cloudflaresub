import assert from 'node:assert/strict';
import {
  decryptPayload,
  encryptPayload,
  expandNodes,
  parseNodeLinks,
  parsePreferredEndpoints,
  renderClashSubscription,
  renderRawSubscription,
  renderSurgeSubscription,
} from '../src/core.js';

const vmess = 'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJkZW1vLXdzLXRscyIsCiAgImFkZCI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAicG9ydCI6ICI0NDMiLAogICJpZCI6ICIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLAogICJzY3kiOiAiYXV0byIsCiAgIm5ldCI6ICJ3cyIsCiAgInRscyI6ICJ0bHMiLAogICJwYXRoIjogIi93cyIsCiAgImhvc3QiOiAiZWRnZS5leGFtcGxlLmNvbSIsCiAgInNuaSI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAiZnAiOiAiY2hyb21lIiwKICAiYWxwbiI6ICJoMixodHRwLzEuMSIKfQ==';

const { nodes } = parseNodeLinks(vmess);
assert.equal(nodes.length, 1);
assert.equal(nodes[0].type, 'vmess');
assert.equal(nodes[0].server, 'edge.example.com');

const { endpoints } = parsePreferredEndpoints('104.16.1.2#HK\n104.17.2.3:2053#US');
assert.equal(endpoints.length, 2);

const expanded = expandNodes(nodes, endpoints, { keepOriginalHost: true, namePrefix: 'CF' });
assert.equal(expanded.nodes.length, 2);
assert.equal(expanded.nodes[0].server, '104.16.1.2');
assert.equal(expanded.nodes[0].hostHeader, 'edge.example.com');
assert.equal(expanded.nodes[1].port, 2053);

const raw = renderRawSubscription(expanded.nodes);
assert.ok(raw.length > 10);

const clash = renderClashSubscription(expanded.nodes);
assert.match(clash, /proxies:/);
assert.match(clash, /edge\.example\.com/);

const surge = renderSurgeSubscription(expanded.nodes, 'https://sub.example.com/sub/demo?target=surge');
assert.match(surge, /\[Proxy]/);
assert.match(surge, /vmess/);

const secret = 'this-is-a-very-secret-key';
const token = await encryptPayload({ nodes: expanded.nodes }, secret);
const payload = await decryptPayload(token, secret);
assert.equal(payload.nodes.length, 2);

// Test VLESS xhttp node parsing and rendering
const vlessXhttp = 'vless://f2c661f3-3c54-4e08-aa43-3bff1f4beb4c@104.20.43.246:443?encryption=mlkem768x25519plus.random.0rtt&security=tls&sni=avghost.959515.xyz&type=xhttp&host=avghost.959515.xyz&path=%2Favghost&mode=auto&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#VLESS-XHTTP-TEST';
const parsedXhttp = parseNodeLinks(vlessXhttp);
assert.equal(parsedXhttp.nodes.length, 1);
assert.equal(parsedXhttp.nodes[0].type, 'vless');
assert.equal(parsedXhttp.nodes[0].network, 'xhttp');
assert.equal(parsedXhttp.nodes[0].params.encryption, 'mlkem768x25519plus.random.0rtt');

const endpointsXhttp = parsePreferredEndpoints('1.1.1.1#CF-IP');
const expandedXhttp = expandNodes(parsedXhttp.nodes, endpointsXhttp.endpoints, { keepOriginalHost: true });
assert.equal(expandedXhttp.nodes[0].server, '1.1.1.1');
assert.equal(expandedXhttp.nodes[0].params.sni, 'avghost.959515.xyz');
assert.equal(expandedXhttp.nodes[0].params.host, 'avghost.959515.xyz');
assert.equal(expandedXhttp.nodes[0].params.encryption, 'mlkem768x25519plus.random.0rtt');

const renderedXhttpRaw = renderRawSubscription(expandedXhttp.nodes);
const decodedXhttpRaw = Buffer.from(renderedXhttpRaw, 'base64').toString('utf8');
assert.ok(decodedXhttpRaw.includes('encryption=mlkem768x25519plus.random.0rtt'));
assert.ok(decodedXhttpRaw.includes('type=xhttp'));
assert.ok(decodedXhttpRaw.includes('mode=auto'));
assert.ok(decodedXhttpRaw.includes('extra='));

const renderedXhttpClash = renderClashSubscription(expandedXhttp.nodes);
assert.ok(renderedXhttpClash.includes('network: xhttp'));
assert.ok(renderedXhttpClash.includes('xhttp-opts:'));
assert.ok(renderedXhttpClash.includes('path: "/avghost"'));
assert.ok(renderedXhttpClash.includes('host: "avghost.959515.xyz"'));
assert.ok(renderedXhttpClash.includes('mode: "auto"'));
assert.ok(renderedXhttpClash.includes('x-padding-bytes: "100-1000"'));

console.log('smoke test passed');
