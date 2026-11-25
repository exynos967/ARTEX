#!/usr/bin/env node
/*
 * runtime_harvest.js <config.json>
 *
 * 参考模板 — 非通用成品。执行前须按目标站点调整 config.json 及脚本内逻辑：
 *   cookies/localStorage、neutralize 字段、stubs 结构、loginUrlPattern、apiPattern
 *
 * Drives a headless browser through an authorized SPA to capture the live API
 * surface (method + url + body) by defeating three client-side gates:
 *   1. render gate    -> inject fake auth state (cookies / localStorage)
 *   2. interceptor gate-> rewrite the "unauthorized" code field to success
 *   3. content gate   -> stub the menu/permission endpoint with a full-feature payload
 *
 * The default Runner bundles puppeteer-core and Playwright Chromium. Custom
 * environments must provide puppeteer-core and config.chromium or CHROMIUM.
 *
 * config.json schema (all fields optional except baseUrl):
 * {
 *   "baseUrl": "https://target/",
 *   "chromium": "/usr/bin/chromium",            // or env CHROMIUM
 *   "cookies":   [{"name":"auth","value":"b64json:{\"id\":1,\"username\":\"admin\"}"}],
 *   "localStorage": {"token":"x","isLogin":"1"},
 *   "neutralize": { "fields":["response_code","code","errno","ret"], "success":0,
 *                   "flags":{"success":true,"message":"ok"} },
 *   "forward": true,                            // forward real req then rewrite code; false = offline stub
 *   "loginUrlPattern": "/login",               // navigations matching this are suppressed as a fallback
 *   "stubs": [ {"match":"permission|menu|role", "body": { ...full-feature menu... }} ],
 *   "routes": ["/dashboard","/device", ...],   // from routes.txt or the forged menu
 *   "apiPattern": "/api/|/rest/|/graphql",      // what counts as an API call to record
 *   "proxy": "http://127.0.0.1:8080",           // optional; also HTTP_PROXY / HTTPS_PROXY
 *   "waitUntil": "domcontentloaded",            // prefer over networkidle2 for large SPAs
 *   "routeTimeout": 12000,
 *   "waitMs": 1200, "perRouteMs": 900, "headless": true
 * }
 */
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
process.env.NODE_USE_ENV_PROXY = '1';
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const tls = require('tls');

let puppeteer;
try { puppeteer = require('puppeteer-core'); }
catch (e) {
  try { puppeteer = require('/opt/artex-tools/node_modules/puppeteer-core'); }
  catch (_) { console.error("[!] puppeteer-core unavailable; select a Runner with api-recon browser dependencies"); process.exit(1); }
}

let ProxyAgent = null;
try { ({ ProxyAgent } = require('undici')); }
catch (_) {
  try { ({ ProxyAgent } = require('/opt/artex-tools/node_modules/undici')); }
  catch (_) {}
}

function fetchViaHttpProxy(targetUrl, { method, headers, body, proxyUrl, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const target = new URL(targetUrl);
    const proxy = new URL(proxyUrl);
    const proxyClient = proxy.protocol === 'https:' ? https : http;
    const proxyPort = proxy.port || (proxy.protocol === 'https:' ? 443 : 80);
    const targetPort = target.port || (target.protocol === 'https:' ? 443 : 80);

    const reqHeaders = {};
    for (const [k, v] of Object.entries(headers || {})) {
      const lk = k.toLowerCase();
      if (lk === 'host' || lk === 'proxy-connection' || lk === 'connection' || lk === 'content-length') continue;
      reqHeaders[k] = v;
    }
    reqHeaders.host = target.host;
    const payload = body != null ? (Buffer.isBuffer(body) ? body : Buffer.from(String(body))) : null;
    if (payload) reqHeaders['content-length'] = String(payload.length);

    let proxyAuth = null;
    if (proxy.username || proxy.password) {
      const creds = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
      proxyAuth = 'Basic ' + Buffer.from(creds).toString('base64');
    }

    let settled = false;
    let activeReq = null;
    let activeSocket = null;
    const done = (err, val) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (err) reject(err);
      else resolve(val);
    };
    const timer = setTimeout(() => {
      const err = new Error(`proxy request timed out after ${timeoutMs}ms`);
      if (activeReq) activeReq.destroy(err);
      if (activeSocket) activeSocket.destroy(err);
      done(err);
    }, timeoutMs);
    if (timer.unref) timer.unref();

    const readResponse = (res) => {
      const parts = [];
      res.on('data', (chunk) => parts.push(chunk));
      res.on('end', () => done(null, {
        text: Buffer.concat(parts).toString('utf8'),
        contentType: String(res.headers['content-type'] || ''),
      }));
      res.on('error', (err) => done(err));
    };

    if (target.protocol === 'http:') {
      const proxyHeaders = Object.assign({}, reqHeaders);
      if (proxyAuth) proxyHeaders['proxy-authorization'] = proxyAuth;
      activeReq = proxyClient.request({
        host: proxy.hostname,
        port: proxyPort,
        method,
        path: targetUrl,
        headers: proxyHeaders,
        rejectUnauthorized: false,
      }, readResponse);
      activeReq.on('error', (err) => done(err));
      if (payload) activeReq.write(payload);
      activeReq.end();
      return;
    }

    const connectHeaders = { host: `${target.hostname}:${targetPort}` };
    if (proxyAuth) connectHeaders['proxy-authorization'] = proxyAuth;
    const tunnelReq = proxyClient.request({
      host: proxy.hostname,
      port: proxyPort,
      method: 'CONNECT',
      path: `${target.hostname}:${targetPort}`,
      headers: connectHeaders,
      rejectUnauthorized: false,
    });
    activeReq = tunnelReq;
    tunnelReq.on('connect', (res, socket) => {
      activeSocket = socket;
      if (res.statusCode !== 200) {
        socket.destroy();
        done(new Error(`proxy CONNECT failed with status ${res.statusCode}`));
        return;
      }
      const tlsSocket = tls.connect({
        socket,
        servername: target.hostname,
        rejectUnauthorized: false,
      });
      activeSocket = tlsSocket;
      tlsSocket.on('error', (err) => done(err));
      const innerReq = https.request({
        host: target.hostname,
        port: targetPort,
        method,
        path: target.pathname + target.search,
        headers: reqHeaders,
        createConnection: () => tlsSocket,
        agent: false,
      }, readResponse);
      activeReq = innerReq;
      innerReq.on('error', (err) => done(err));
      if (payload) innerReq.write(payload);
      innerReq.end();
    });
    tunnelReq.on('error', (err) => done(err));
    tunnelReq.end();
  });
}

function loadCfg(p) {
  const c = JSON.parse(fs.readFileSync(p, 'utf8'));
  c.baseUrl || (() => { throw new Error("config.baseUrl required"); })();
  if (!c.chromium && !process.env.CHROMIUM) {
    try { c.chromium = require('/opt/artex-tools/node_modules/playwright').chromium.executablePath(); }
    catch (_) { /* External runners can supply their own Chromium. */ }
  }
  c.chromium = c.chromium || process.env.CHROMIUM || '/usr/bin/chromium';
  c.neutralize = c.neutralize || { fields: ['response_code', 'code', 'errno', 'ret', 'status'], success: 0, flags: { success: true } };
  c.forward = c.forward !== false;
  c.apiPattern = new RegExp(c.apiPattern || '/api/|/rest/|/service/|/graphql|/gateway/');
  c.loginUrlPattern = c.loginUrlPattern || '/login';
  c.routes = c.routes || ['/'];
  c.waitMs = c.waitMs || 1200; c.perRouteMs = c.perRouteMs || 900;
  c.headless = c.headless !== false;
  c.waitUntil = c.waitUntil || 'domcontentloaded';
  c.routeTimeout = c.routeTimeout || 12000;
  c.captureResponses = c.captureResponses !== false; // record response body samples (forward mode)
  c.recordWs = c.recordWs !== false;                 // record WebSocket frames + SSE endpoints
  c.respMax = c.respMax || 600;                       // truncation length for captured bodies
  c.proxy = c.proxy || process.env.HTTP_PROXY || process.env.HTTPS_PROXY || '';
  (c.stubs || []).forEach(s => s._re = new RegExp(s.match));
  return c;
}

function cookieValue(v) {
  if (typeof v === 'string' && v.startsWith('b64json:'))
    return Buffer.from(v.slice(8)).toString('base64');
  if (typeof v === 'string' && v.startsWith('json:'))
    return v.slice(5);
  return v;
}

function neutralize(txt, n) {
  try {
    const j = JSON.parse(txt);
    if (j && typeof j === 'object') {
      for (const f of n.fields) if (f in j) j[f] = n.success;
      Object.assign(j, n.flags || {});
      return JSON.stringify(j);
    }
  } catch (e) {}
  return txt;
}

(async () => {
  const cfg = loadCfg(process.argv[2] || 'config.json');
  const origin = new URL(cfg.baseUrl).origin;
  const host = new URL(cfg.baseUrl).hostname;
  const rec = [];           // {m,u,b,resp,ct}
  const chunks = new Set();
  const ws = [];            // {url,dir,data}  WebSocket frames
  const sse = new Set();    // SSE (text/event-stream) endpoints

  if (cfg.proxy) {
    process.env.HTTP_PROXY = cfg.proxy;
    process.env.HTTPS_PROXY = cfg.proxy;
  }
  const proxyDispatcher = (cfg.proxy && ProxyAgent)
    ? new ProxyAgent({ uri: cfg.proxy, requestTls: { rejectUnauthorized: false } })
    : null;
  async function forwardRequest(targetUrl, { method, headers, body }) {
    if (cfg.proxy && !proxyDispatcher) {
      return fetchViaHttpProxy(targetUrl, {
        method,
        headers,
        body,
        proxyUrl: cfg.proxy,
        timeoutMs: cfg.routeTimeout,
      });
    }
    const opts = {
      method,
      headers,
      body,
      signal: AbortSignal.timeout(cfg.routeTimeout),
    };
    if (proxyDispatcher) opts.dispatcher = proxyDispatcher;
    const r = await fetch(targetUrl, opts);
    return { text: await r.text(), contentType: r.headers.get('content-type') || '' };
  }

  const launchArgs = ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'];
  if (cfg.proxy) launchArgs.push(`--proxy-server=${cfg.proxy}`);

  let browser = null;
  let launchPromise = null;
  let closingPromise = null;
  let shuttingDown = false;
  function closeBrowser() {
    if (closingPromise) return closingPromise;
    if (!browser && !launchPromise) return Promise.resolve();
    closingPromise = (async () => {
      let b = browser;
      browser = null;
      if (!b && launchPromise) {
        const pendingLaunch = launchPromise;
        launchPromise = null;
        let launchTimer = null;
        try {
          b = await Promise.race([
            pendingLaunch,
            new Promise((resolve) => {
              launchTimer = setTimeout(() => resolve(null), 5000);
              if (launchTimer.unref) launchTimer.unref();
            }),
          ]);
        } catch (_) {
          b = null;
        } finally {
          if (launchTimer) clearTimeout(launchTimer);
        }
      }
      if (!b) return;
      let timer = null;
      try {
        await Promise.race([
          b.close(),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('browser.close timed out')), 3000);
            if (timer.unref) timer.unref();
          }),
        ]);
      } catch (_) {
        try {
          const proc = typeof b.process === 'function' ? b.process() : null;
          if (proc && !proc.killed) proc.kill('SIGKILL');
        } catch (_) {}
      } finally {
        if (timer) clearTimeout(timer);
      }
    })();
    return closingPromise;
  }

  const onSignal = (sig) => {
    if (shuttingDown) return;
    shuttingDown = true;
    const code = sig === 'SIGINT' ? 130 : 143;
    closeBrowser().finally(() => process.exit(code));
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  try {
    launchPromise = puppeteer.launch({
      executablePath: cfg.chromium, headless: cfg.headless ? 'new' : false,
      args: launchArgs
    });
    const launched = await launchPromise;
    launchPromise = null;
    if (shuttingDown) {
      if (!closingPromise) {
        browser = launched;
        await closeBrowser();
      } else {
        await closingPromise;
      }
      return;
    }
    browser = launched;
    const page = await browser.newPage();

    // ---- WebSocket frame capture via CDP (fetch/XHR interception can't see WS) ----
    if (cfg.recordWs) {
      try {
        const cdp = await page.target().createCDPSession();
        await cdp.send('Network.enable');
        const wsUrl = {}; // requestId -> url
        cdp.on('Network.webSocketCreated', e => { wsUrl[e.requestId] = e.url; });
        const onFrame = dir => e => {
          const p = e.response && e.response.payloadData;
          if (p != null) ws.push({ url: (wsUrl[e.requestId] || '').replace(origin, ''), dir, data: String(p).slice(0, cfg.respMax) });
        };
        cdp.on('Network.webSocketFrameSent', onFrame('send'));
        cdp.on('Network.webSocketFrameReceived', onFrame('recv'));
      } catch (e) { console.log('[ws] CDP capture unavailable:', e.message); }
    }

    // inject localStorage on every document
    if (cfg.localStorage) {
      await page.evaluateOnNewDocument((kv) => {
        try { for (const k in kv) localStorage.setItem(k, kv[k]); } catch (e) {}
      }, cfg.localStorage);
    }
    // fallback: block full-page navigations to the login url
    await page.evaluateOnNewDocument((pat) => {
      const bad = u => { try { return String(u).indexOf(pat) >= 0; } catch (e) { return false; } };
      try {
        const d = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
        Object.defineProperty(Location.prototype, 'href', { configurable: true,
          get() { return d.get.call(this); },
          set(v) { if (bad(v)) return; return d.set.call(this, v); } });
        const a = Location.prototype.assign, r = Location.prototype.replace;
        Location.prototype.assign = function (v) { if (bad(v)) return; return a.call(this, v); };
        Location.prototype.replace = function (v) { if (bad(v)) return; return r.call(this, v); };
      } catch (e) {}
    }, cfg.loginUrlPattern);

    await page.setRequestInterception(true);
    page.on('request', async (req) => {
      try {
        if (req.isInterceptResolutionHandled()) return;
        const u = req.url(), m = req.method();
        if (/\.js(\?|$)/.test(u) && /\/assets\/|\/static\/|\/js\//.test(u)) chunks.add(u.split('/').pop());

        // suppress fallback login navigations (after the app has bootstrapped)
        if (req.isNavigationRequest() && req.frame() === page.mainFrame()
            && u.includes(cfg.loginUrlPattern) && rec.length > 3) {
          if (!req.isInterceptResolutionHandled()) {
            await req.respond({ status: 204, body: '' });
          }
          return;
        }
        if (!cfg.apiPattern.test(u)) {
          if (!req.isInterceptResolutionHandled()) {
            await req.continue();
          }
          return;
        }

        const entry = { m, u: u.replace(origin, '').split('?')[0], full: u, b: req.postData() ? req.postData().slice(0, 400) : null };
        rec.push(entry);

        // explicit stubs (menu / permission forgery) win
        const stub = (cfg.stubs || []).find(s => s._re.test(u));
        if (stub) {
          if (!req.isInterceptResolutionHandled()) {
            await req.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(stub.body) });
          }
          return;
        }

        // SSE: forwarding a text/event-stream would hang the handler — record + short-circuit
        const accept = (req.headers().accept || '');
        if (/text\/event-stream/.test(accept)) {
          sse.add(entry.u);
          if (!req.isInterceptResolutionHandled()) {
            await req.respond({ status: 200, contentType: 'application/json', body: '{}' });
          }
          return;
        }

        if (!cfg.forward) {
          if (!req.isInterceptResolutionHandled()) {
            await req.respond({ status: 200, contentType: 'application/json',
              body: neutralize('{"data":{},"list":[],"total":0}', cfg.neutralize) });
          }
          return;
        }
        // forward real request, then rewrite the unauthorized code field
        try {
          const headers = Object.assign({}, req.headers());
          if (cfg.cookies) headers.cookie = cfg.cookies.map(c => `${c.name}=${cookieValue(c.value)}`).join('; ');
          const body = (m !== 'GET' && m !== 'HEAD') ? req.postData() : undefined;
          const { text: t, contentType: ct } = await forwardRequest(u, { method: m, headers, body });
          if (cfg.captureResponses) { entry.resp = t.slice(0, cfg.respMax); entry.ct = ct; }
          if (!req.isInterceptResolutionHandled()) {
            await req.respond({ status: 200, contentType: 'application/json', body: neutralize(t, cfg.neutralize) });
          }
        } catch (e) {
          if (!req.isInterceptResolutionHandled()) {
            await req.respond({ status: 200, contentType: 'application/json', body: '{"response_code":0,"code":0,"data":{}}' });
          }
        }
      } catch (_) {}
    });

    // set auth cookies
    if (cfg.cookies) {
      for (const c of cfg.cookies)
        await page.setCookie({ name: c.name, value: cookieValue(c.value), domain: host, path: c.path || '/' });
    }

    // boot
    await page.goto(cfg.baseUrl, { waitUntil: cfg.waitUntil, timeout: 45000 }).catch(e => console.log('[goto]', e.message));
    await new Promise(r => setTimeout(r, cfg.waitMs));
    const shell = await page.evaluate(() => ({
      url: location.href,
      loginForm: !!document.querySelector('input[type=password]'),
      links: [...document.querySelectorAll('a[href^="/"]')].map(a => a.getAttribute('href'))
    }));
    console.log(`[*] after boot: url=${shell.url}  loginForm=${shell.loginForm}`);
    if (shell.loginForm) console.log('[!] still on login — recheck render-gate facts (cookies/localStorage) in config');

    // discovered menu links extend the route list
    const routes = [...new Set([...cfg.routes, ...shell.links.filter(h => h && h.length > 1)])];
    const perRoute = {};
    for (const rt of routes) {
      const before = rec.length;
      try { await page.goto(origin + rt, { waitUntil: cfg.waitUntil, timeout: cfg.routeTimeout }); } catch (e) {}
      await new Promise(r => setTimeout(r, cfg.perRouteMs));
      const fresh = [...new Set(rec.slice(before).map(r => r.m + ' ' + r.u))];
      perRoute[rt] = fresh;
    }

    const uniq = [...new Set(rec.map(r => r.m + ' ' + r.u))].sort();
    const wsUniq = [...new Set(ws.map(f => f.url))].filter(Boolean).sort();
    const outdir = path.dirname(process.argv[2] || '.');
    fs.writeFileSync(path.join(outdir, 'runtime_api.json'),
      JSON.stringify({ provenance: 'mock-runtime', backendVerified: false, shell, uniq, perRoute, rec, ws, wsEndpoints: wsUniq, sse: [...sse] }, null, 2));

    // merge with static
    let merged = new Set(uniq.map(x => x.split(' ')[1]));
    const staticFile = path.join(outdir, 'api_static.txt');
    if (fs.existsSync(staticFile)) fs.readFileSync(staticFile, 'utf8').split('\n').filter(Boolean).forEach(p => merged.add(p));
    fs.writeFileSync(path.join(outdir, 'api_merged.txt'), [...merged].sort().join('\n'));

    console.log(`[+] runtime endpoints (with method): ${uniq.length}`);
    console.log(`[+] chunks seen at runtime: ${chunks.size}`);
    if (cfg.recordWs) console.log(`[+] websocket endpoints: ${wsUniq.length} (${ws.length} frames) | SSE endpoints: ${sse.size}`);
    if (cfg.captureResponses) console.log(`[+] response bodies captured for ${rec.filter(r => r.resp != null).length}/${rec.length} calls`);
    console.log(`[+] merged unique paths: ${merged.size}  -> api_merged.txt`);
    console.log(`[+] full detail -> runtime_api.json (per-route + bodies + ws frames + sse)`);
  } finally {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
    await closeBrowser();
    if (proxyDispatcher && typeof proxyDispatcher.close === 'function') {
      await proxyDispatcher.close().catch(() => {});
    }
  }
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
