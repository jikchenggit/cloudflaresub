// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = '') {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, ' ');
}

function parsePreferredEndpoints(input) {
  return String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [raw, remark = ''] = line.split('#');
      const value = raw.trim();
      const hashRemark = remark.trim();
      
      let server = value;
      let port = undefined;
      
      if (value.startsWith('[')) {
        const match = value.match(/^\[([^\]]+)](?::(\d+))?$/);
        if (match) {
          server = match[1];
          if (match[2]) {
            port = Number(match[2]);
          }
        }
      } else {
        const colonCount = (value.match(/:/g) || []).length;
        if (colonCount === 1) {
          const parts = value.split(':');
          if (/^\d+$/.test(parts[1])) {
            server = parts[0];
            port = Number(parts[1]);
          }
        }
      }
      
      return {
        server,
        port,
        remark: hashRemark,
      };
    });
}

function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));
  return {
    type: 'vmess',
    name: obj.ps || 'vmess',
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || 'auto',
    network: obj.net || 'ws',
    tls: obj.tls === 'tls',
    host: obj.host || '',
    path: obj.path || '/',
    sni: obj.sni || obj.host || '',
    alpn: obj.alpn || '',
    fp: obj.fp || '',
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  const params = {};
  for (const [k, v] of u.searchParams.entries()) {
    params[k] = v;
  }
  const network = u.searchParams.get('type') || 'tcp';
  const security = (u.searchParams.get('security') || '').toLowerCase();
  return {
    type,
    name: decodeURIComponent(u.hash.replace(/^#/, '')) || type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === 'trojan' ? decodeURIComponent(u.username) : undefined,
    uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined,
    network,
    tls: security === 'tls' || security === 'reality',
    security,
    host: u.searchParams.get('host') || u.searchParams.get('sni') || '',
    path: u.searchParams.get('path') || '/',
    sni: u.searchParams.get('sni') || u.searchParams.get('host') || '',
    fp: u.searchParams.get('fp') || '',
    alpn: u.searchParams.get('alpn') || '',
    flow: u.searchParams.get('flow') || '',
    params,
  };
}

function parseRawLinks(input) {
  const lines = String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const result = [];
  for (const line of lines) {
    try {
      if (line.startsWith('vmess://')) {
        result.push(parseVmess(line));
        continue;
      }
      if (line.startsWith('vless://')) {
        result.push(parseUrlLike(line, 'vless'));
        continue;
      }
      if (line.startsWith('trojan://')) {
        result.push(parseUrlLike(line, 'trojan'));
        continue;
      }
      const decoded = b64DecodeUtf8(line);
      if (/^(vmess|vless|trojan):\/\//m.test(decoded)) {
        result.push(...parseRawLinks(decoded));
      }
    } catch (e) {
      // Skip invalid node links without crashing the entire request
    }
  }
  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark);
      else nameParts.push(String(counter));
      
      const host = options.keepOriginalHost ? (node.host || node.server) : '';
      const sni = options.keepOriginalHost ? (node.sni || node.server) : '';
      
      const clone = {
        ...node,
        name: nameParts.join(' | '),
        server: ep.server,
        port: ep.port || node.port,
        host,
        sni,
      };

      if (clone.params) {
        clone.params = { ...node.params };
        if (options.keepOriginalHost) {
          if (host) clone.params.host = host;
          if (sni) clone.params.sni = sni;
        } else {
          delete clone.params.host;
          delete clone.params.sni;
        }
      }

      output.push(clone);
    }
  }
  return output;
}

function encodeVmess(node) {
  const obj = {
    v: '2',
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: '0',
    scy: node.cipher || 'auto',
    net: node.network || 'ws',
    type: 'none',
    host: node.host || '',
    path: node.path || '/',
    tls: node.tls ? 'tls' : '',
    sni: node.sni || '',
    alpn: node.alpn || '',
    fp: node.fp || '',
  };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}

function formatHostForUrl(host) {
  if (String(host).includes(':') && !String(host).startsWith('[')) {
    return `[${host}]`;
  }
  return host;
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${formatHostForUrl(node.server)}:${node.port}`);
  if (node.params) {
    for (const [k, v] of Object.entries(node.params)) {
      url.searchParams.set(k, v);
    }
  }
  url.searchParams.set('type', node.network || 'ws');
  if (node.tls) {
    url.searchParams.set('security', node.security || 'tls');
  } else {
    url.searchParams.delete('security');
  }
  if (node.host) {
    url.searchParams.set('host', node.host);
  } else {
    url.searchParams.delete('host');
  }
  if (node.sni) {
    url.searchParams.set('sni', node.sni);
  } else {
    url.searchParams.delete('sni');
  }
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  if (node.flow) url.searchParams.set('flow', node.flow);
  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${formatHostForUrl(node.server)}:${node.port}`);
  if (node.network) url.searchParams.set('type', node.network);
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  url.hash = node.name;
  return url.toString();
}

function renderRaw(nodes) {
  const lines = nodes
    .map((node) => {
      try {
        if (node.type === 'vmess') return encodeVmess(node);
        if (node.type === 'vless') return encodeVless(node);
        if (node.type === 'trojan') return encodeTrojan(node);
      } catch (e) {
        // Skip nodes with malformed hosts (e.g. invalid IPv6) rather than crashing the subscription
      }
      return '';
    })
    .filter(Boolean);
  return b64EncodeUtf8(lines.join('\n'));
}

function renderClash(nodes) {
  const proxies = nodes
    .map((node) => {
      if (node.type === 'vmess') {
        const network = node.network || 'ws';
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vmess`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    alterId: 0`,
          `    cipher: ${node.cipher || 'auto'}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${network}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if (network === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        } else if (network === 'grpc') {
          lines.push(
            `    grpc-opts:`,
            `      grpc-service-name: "${escapeYaml(node.serviceName || node.params?.serviceName || '')}"`
          );
        } else if (network === 'http' || network === 'h2') {
          lines.push(
            `    http-opts:`,
            `      path: ["${escapeYaml(node.path || '/')}"]`,
            `      headers:`,
            `        Host: ["${escapeYaml(node.host || node.sni || '')}"]`
          );
        } else if (network === 'xhttp') {
          lines.push(
            `    xhttp-opts:`,
            `      path: "${escapeYaml(node.path || '')}"`,
            `      host: "${escapeYaml(node.host || node.sni || '')}"`,
            `      mode: "${escapeYaml(node.params?.mode || 'auto')}"`
          );
          if (node.params?.extra) {
            try {
              const extraVal = typeof node.params.extra === 'string'
                ? JSON.parse(decodeURIComponent(node.params.extra))
                : node.params.extra;
              lines.push(
                `      extra:`,
                `        mode: "${escapeYaml(extraVal.mode || 'auto')}"`,
                `        xPaddingBytes: "${escapeYaml(extraVal.xPaddingBytes || '100-1000')}"`
              );
            } catch (e) {
              lines.push(`      extra: "${escapeYaml(String(node.params.extra))}"`);
            }
          }
        } else if (network === 'httpupgrade') {
          lines.push(
            `    httpupgrade-opts:`,
            `      path: "${escapeYaml(node.path || '')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'vless') {
        const network = node.network || 'ws';
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vless`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${network}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if (network === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        } else if (network === 'grpc') {
          lines.push(
            `    grpc-opts:`,
            `      grpc-service-name: "${escapeYaml(node.serviceName || node.params?.serviceName || '')}"`
          );
        } else if (network === 'http' || network === 'h2') {
          lines.push(
            `    http-opts:`,
            `      path: ["${escapeYaml(node.path || '/')}"]`,
            `      headers:`,
            `        Host: ["${escapeYaml(node.host || node.sni || '')}"]`
          );
        } else if (network === 'xhttp') {
          lines.push(
            `    xhttp-opts:`,
            `      path: "${escapeYaml(node.path || '')}"`,
            `      host: "${escapeYaml(node.host || node.sni || '')}"`,
            `      mode: "${escapeYaml(node.params?.mode || 'auto')}"`
          );
          if (node.params?.extra) {
            try {
              const extraVal = typeof node.params.extra === 'string'
                ? JSON.parse(decodeURIComponent(node.params.extra))
                : node.params.extra;
              lines.push(
                `      extra:`,
                `        mode: "${escapeYaml(extraVal.mode || 'auto')}"`,
                `        xPaddingBytes: "${escapeYaml(extraVal.xPaddingBytes || '100-1000')}"`
              );
            } catch (e) {
              lines.push(`      extra: "${escapeYaml(String(node.params.extra))}"`);
            }
          }
        } else if (network === 'httpupgrade') {
          lines.push(
            `    httpupgrade-opts:`,
            `      path: "${escapeYaml(node.path || '')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'trojan') {
        const network = node.network || 'tcp';
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: trojan`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    password: "${escapeYaml(node.password || '')}"`,
          `    udp: true`,
        ];

        if (node.sni) {
          lines.push(`    sni: "${escapeYaml(node.sni)}"`);
        }

        if (node.tls !== false) {
          lines.push(`    tls: true`);
        }

        lines.push(`    network: ${network}`);

        if (network === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        } else if (network === 'grpc') {
          lines.push(
            `    grpc-opts:`,
            `      grpc-service-name: "${escapeYaml(node.serviceName || node.params?.serviceName || '')}"`
          );
        } else if (network === 'http' || network === 'h2') {
          lines.push(
            `    http-opts:`,
            `      path: ["${escapeYaml(node.path || '/')}"]`,
            `      headers:`,
            `        Host: ["${escapeYaml(node.host || node.sni || '')}"]`
          );
        } else if (network === 'xhttp') {
          lines.push(
            `    xhttp-opts:`,
            `      path: "${escapeYaml(node.path || '')}"`,
            `      host: "${escapeYaml(node.host || node.sni || '')}"`,
            `      mode: "${escapeYaml(node.params?.mode || 'auto')}"`
          );
          if (node.params?.extra) {
            try {
              const extraVal = typeof node.params.extra === 'string'
                ? JSON.parse(decodeURIComponent(node.params.extra))
                : node.params.extra;
              lines.push(
                `      extra:`,
                `        mode: "${escapeYaml(extraVal.mode || 'auto')}"`,
                `        xPaddingBytes: "${escapeYaml(extraVal.xPaddingBytes || '100-1000')}"`
              );
            } catch (e) {
              lines.push(`      extra: "${escapeYaml(String(node.params.extra))}"`);
            }
          }
        } else if (network === 'httpupgrade') {
          lines.push(
            `    httpupgrade-opts:`,
            `      path: "${escapeYaml(node.path || '')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      return '';
    })
    .filter(Boolean);

  const proxyNames = nodes.map(
    (node) => `      - "${escapeYaml(node.name)}"`
  );

  const allGroupMembers = [
    `      - "自动选择"`,
    ...proxyNames,
    `      - DIRECT`,
  ];

  const autoGroupMembers = proxyNames.length ? proxyNames : [`      - DIRECT`];

  return [
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `ipv6: true`,
    ``,
    `proxies:`,
    ...(proxies.length ? proxies : []),
    ``,
    `proxy-groups:`,
    `  - name: "自动选择"`,
    `    type: url-test`,
    `    url: "http://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...autoGroupMembers,
    ``,
    `  - name: "节点选择"`,
    `    type: select`,
    `    proxies:`,
    ...allGroupMembers,
    ``,
    `rules:`,
    `  - MATCH,节点选择`,
  ].join('\n');
}

function renderSurge(nodes, baseUrl, accessToken) {
  const proxies = nodes
    .filter((node) => node.type === 'vmess' || node.type === 'trojan')
    .map((node) => {
      if (node.type === 'vmess') {
        return `${node.name} = vmess, ${node.server}, ${node.port}, username=${node.uuid}, ws=true, ws-path=${node.path || '/'}, ws-headers=Host:${node.host || ''}, tls=${node.tls ? 'true' : 'false'}, sni=${node.sni || ''}`;
      }
      return `${node.name} = trojan, ${node.server}, ${node.port}, password=${node.password || ''}, sni=${node.sni || ''}`;
    });

  return [
    '[General]',
    'skip-proxy = 127.0.0.1, localhost',
    '',
    '[Proxy]',
    ...proxies,
    '',
    '[Proxy Group]',
    'Proxy = select, ' +
      nodes
        .filter((n) => n.type === 'vmess' || n.type === 'trojan')
        .map((n) => n.name)
        .join(', '),
    '',
    '[Rule]',
    'FINAL,Proxy',
    '',
    '; token-protected subscription',
    `; ${baseUrl}?token=${accessToken}`,
  ].join('\n');
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) return id;
  }
  throw new Error('无法生成唯一短链接，请稍后再试');
}

function normalizeLines(value = '') {
  return String(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort()
    .join('\n');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}

async function handleGenerate(request, env, url) {
  if (!env.SUB_STORE) {
    return json(
      {
        ok: false,
        error: '系统配置错误：未检测到名为 SUB_STORE 的 KV 空间绑定。请前往 Cloudflare 网页后台，在此 Pages 项目的「设置 -> Functions -> KV 命名空间绑定」中添加一个名为 SUB_STORE 的绑定，并重新部署。',
      },
      500,
    );
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }

  const baseNodes = parseRawLinks(body.nodeLinks || '');
  const preferredEndpoints = parsePreferredEndpoints(body.preferredIps || '');

  if (!baseNodes.length) return json({ ok: false, error: '没有识别到可用节点' }, 400);
  if (!preferredEndpoints.length) return json({ ok: false, error: '没有识别到可用优选地址' }, 400);

  const options = {
    namePrefix: body.namePrefix || '',
    keepOriginalHost: body.keepOriginalHost !== false,
  };

  const nodes = buildNodes(baseNodes, preferredEndpoints, options);

  const payload = {
    version: 1,
    createdAt: new Date().toISOString(),
    options,
    nodes,
  };

  const dedupHash = await buildDedupHash(body);
  const dedupKey = `dedup:${dedupHash}`;

  let id = await env.SUB_STORE.get(dedupKey);

  if (!id) {
    id = await createUniqueShortId(env);
    const ttl = 60 * 60 * 24 * 7; // 7天

    await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), {
      expirationTtl: ttl,
    });

    await env.SUB_STORE.put(dedupKey, id, {
      expirationTtl: ttl,
    });
  }

  const origin = url.origin;
  const accessToken = env.SUB_ACCESS_TOKEN || '';
  const withToken = (target) =>
    `${origin}/sub/${id}${
      target
        ? `?target=${target}&token=${encodeURIComponent(accessToken)}`
        : `?token=${encodeURIComponent(accessToken)}`
    }`;

  return json({
    ok: true,
    storage: 'kv',
    deduplicated: true,
    shortId: id,
    urls: {
      auto: withToken(''),
      raw: withToken('raw'),
      clash: withToken('clash'),
      surge: withToken('surge'),
    },
    counts: {
      inputNodes: baseNodes.length,
      preferredEndpoints: preferredEndpoints.length,
      outputNodes: nodes.length,
    },
    preview: nodes.slice(0, 20).map((node) => ({
      name: node.name,
      type: node.type,
      server: node.server,
      port: node.port,
      host: node.host || '',
      sni: node.sni || '',
    })),
    warnings: accessToken ? [] : ['未检测到 SUB_ACCESS_TOKEN，订阅链接将没有第二层访问保护。'],
  });
}

function validateAccessToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) return { ok: true };
  const provided = url.searchParams.get('token') || '';
  if (!provided || provided !== expected) {
    return { ok: false, response: text('Forbidden: invalid token', 403) };
  }
  return { ok: true };
}

async function handleSub(url, env) {
  if (!env.SUB_STORE) {
    return text('System Configuration Error: KV namespace SUB_STORE is not bound.', 500);
  }
  const tokenCheck = validateAccessToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const id = url.pathname.split('/').pop();
  if (!id) return text('missing id', 400);

  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) return text('not found', 404);

  const record = JSON.parse(raw);
  const nodes = record.nodes || [];
  const target = (url.searchParams.get('target') || 'raw').toLowerCase();

  if (target === 'clash') {
    return text(renderClash(nodes), 200, 'text/yaml; charset=utf-8');
  }
  if (target === 'surge') {
    return text(
      renderSurge(nodes, url.origin + url.pathname, env.SUB_ACCESS_TOKEN || ''),
      200,
      'text/plain; charset=utf-8',
    );
  }
  return text(renderRaw(nodes), 200, 'text/plain; charset=utf-8');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type',
        },
      });
    }

    if (request.method === 'POST' && url.pathname === '/api/generate') {
      return handleGenerate(request, env, url);
    }

    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) {
      return handleSub(url, env);
    }

    return env.ASSETS.fetch(request);
  },
};