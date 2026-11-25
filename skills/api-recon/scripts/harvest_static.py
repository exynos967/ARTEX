#!/usr/bin/env python3
"""
harvest_static.py <BASE_URL> <OUTDIR>

参考模板 — 非通用成品。执行前须按目标站点调整，常见改动：
  - extract_endpoints 正则（endpoint 方言）
  - webpack/Vite manifest 解析逻辑
  - 微前端 publicPath、重试策略

Static SPA bundle harvester. Framework-agnostic; tuned for webpack + Vite.
  1. Fetch entry HTML, collect script/module references.
  2. Parse the runtime chunk manifest(s) and download chunks (bounded concurrency,
     per-response size cap, rate pacing, and consecutive-404 circuit breaker so
     it never floods the MITM recording proxy).
  3. Extract API endpoints and route paths from all downloaded JS.

Prefers requests.Session / urllib3.PoolManager for pooled connections and falls
back cleanly to stdlib urllib.request. TLS verification is disabled (recon
against self-signed/internal hosts).
"""
import hashlib
import os
import re
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    urllib3 = None

try:
    import requests
    from requests.adapters import HTTPAdapter
except Exception:
    requests = None
    HTTPAdapter = None

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (spa-api-recon)"

# Hardened resource & proxy-protection limits (overridable within safe ceilings).
MAX_WORKERS_CEILING = 6
DEFAULT_WORKERS = 6
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB per response
READ_CHUNK_BYTES = 65536              # 64 KiB chunked reads
REQUEST_TIMEOUT = 15                  # seconds per request
MIN_REQUEST_INTERVAL = 0.05           # gentle pacing across worker threads
MAX_CONSECUTIVE_404 = 25              # stop probing dead/CSS-only chunk lists


def _env_int(name, default, minimum, maximum):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = int(raw.strip())
    except ValueError:
        return default
    return max(minimum, min(maximum, val))


def _env_float(name, default, minimum, maximum):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = float(raw.strip())
    except ValueError:
        return default
    return max(minimum, min(maximum, val))


def resolve_workers(requested=None):
    if requested is None:
        return _env_int("HARVEST_MAX_WORKERS", DEFAULT_WORKERS, 1, MAX_WORKERS_CEILING)
    return max(1, min(MAX_WORKERS_CEILING, int(requested)))


def resolve_timeout(requested=None):
    if requested is None:
        return _env_int("HARVEST_TIMEOUT", REQUEST_TIMEOUT, 1, 30)
    return max(1, min(30, int(requested)))


def resolve_max_bytes(requested=None):
    if requested is None:
        return _env_int("HARVEST_MAX_RESPONSE_BYTES", MAX_RESPONSE_BYTES, READ_CHUNK_BYTES, MAX_RESPONSE_BYTES)
    return max(READ_CHUNK_BYTES, min(MAX_RESPONSE_BYTES, int(requested)))


def resolve_min_interval(requested=None):
    if requested is None:
        return _env_float("HARVEST_MIN_INTERVAL", MIN_REQUEST_INTERVAL, 0.0, 5.0)
    return max(0.0, min(5.0, float(requested)))


def resolve_max_consecutive_404(requested=None):
    if requested is None:
        return _env_int("HARVEST_MAX_CONSECUTIVE_404", MAX_CONSECUTIVE_404, 1, 100)
    return max(1, min(100, int(requested)))


def read_bounded(read_fn, max_bytes=MAX_RESPONSE_BYTES, chunk_size=READ_CHUNK_BYTES):
    """Read at most max_bytes in fixed chunks so huge bodies never exhaust RAM."""
    buf = bytearray()
    remaining = max_bytes
    while remaining > 0:
        chunk = read_fn(min(chunk_size, remaining))
        if not chunk:
            break
        buf.extend(chunk)
        remaining -= len(chunk)
    return bytes(buf)


class RatePacer:
    """Thread-safe minimum-interval pacer that avoids sleeping while holding its lock."""

    def __init__(self, min_interval=MIN_REQUEST_INTERVAL):
        self.min_interval = max(0.0, float(min_interval))
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = now if now >= self._next_allowed else self._next_allowed
            self._next_allowed = slot + self.min_interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


class HttpFetcher:
    """Connection-pooled HTTP fetcher with chunked size cap, timeout, and pacing."""

    def __init__(self, workers=DEFAULT_WORKERS, timeout=REQUEST_TIMEOUT,
                 max_bytes=MAX_RESPONSE_BYTES, min_interval=MIN_REQUEST_INTERVAL):
        self.workers = resolve_workers(workers)
        self.timeout = resolve_timeout(timeout)
        self.max_bytes = resolve_max_bytes(max_bytes)
        self.pacer = RatePacer(resolve_min_interval(min_interval))
        self._tls = threading.local()
        self._sessions = []
        self._sessions_lock = threading.Lock()
        self._pool = None
        self._proxy_pools = {}
        self._backend = "urllib"
        self._init_transport()

    @staticmethod
    def _urllib3_retry():
        # Follow up to 5 HTTP redirects while performing zero retries on network/status errors.
        return urllib3.Retry(total=5, connect=0, read=0, status=0, other=0, redirect=5)

    def _get_requests_session(self):
        sess = getattr(self._tls, "session", None)
        if sess is not None:
            return sess
        sess = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=max(2, self.workers),
            pool_maxsize=2,
            max_retries=0,
        )
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        sess.headers.update({"User-Agent": UA})
        with self._sessions_lock:
            self._sessions.append(sess)
        self._tls.session = sess
        return sess

    def _init_transport(self):
        if requests is not None and HTTPAdapter is not None:
            self._backend = "requests"
            return

        if urllib3 is not None:
            proxies = urllib.request.getproxies()
            # urllib3 ProxyManager only supports http(s) proxies without PySocks;
            # fall back to urllib.request if a non-HTTP proxy is configured.
            proxy_vals = [v for k, v in proxies.items() if k.lower() in ("http", "https", "all")]
            if all(v.startswith(("http://", "https://")) for v in proxy_vals):
                self._pool = urllib3.PoolManager(
                    num_pools=self.workers,
                    maxsize=self.workers,
                    cert_reqs="CERT_NONE",
                    retries=self._urllib3_retry(),
                    timeout=self.timeout,
                )
                for scheme in ("http", "https"):
                    purl = proxies.get(scheme) or proxies.get("all")
                    if purl:
                        self._proxy_pools[scheme] = urllib3.ProxyManager(
                            purl,
                            num_pools=self.workers,
                            maxsize=self.workers,
                            cert_reqs="CERT_NONE",
                            retries=self._urllib3_retry(),
                            timeout=self.timeout,
                        )
                self._backend = "urllib3"

    def close(self):
        with self._sessions_lock:
            sessions = list(self._sessions)
            self._sessions.clear()
        for sess in sessions:
            try:
                sess.close()
            except Exception:
                pass
        if self._pool is not None:
            self._pool.clear()
        for pm in self._proxy_pools.values():
            pm.clear()

    def fetch(self, url, binary=False):
        self.pacer.wait()
        if self._backend == "requests":
            return self._fetch_requests(url, binary)
        if self._backend == "urllib3":
            return self._fetch_urllib3(url, binary)
        return self._fetch_urllib(url, binary)

    def _fetch_requests(self, url, binary):
        sess = self._get_requests_session()
        try:
            with sess.get(url, verify=False, timeout=self.timeout, stream=True) as resp:
                buf = bytearray()
                remaining = self.max_bytes
                for chunk in resp.iter_content(chunk_size=READ_CHUNK_BYTES):
                    if not chunk:
                        continue
                    if len(chunk) >= remaining:
                        buf.extend(chunk[:remaining])
                        break
                    buf.extend(chunk)
                    remaining -= len(chunk)
                data = bytes(buf)
                return (data if binary else data.decode("utf-8", "ignore")), resp.status_code
        except Exception as exc:
            resp = getattr(exc, "response", None)
            code = getattr(resp, "status_code", 0) if resp is not None else 0
            return (b"" if binary else ""), code

    def _fetch_urllib3(self, url, binary):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        hostport = f"{host}:{parsed.port}" if (host and parsed.port) else host
        if hostport and urllib.request.proxy_bypass(hostport):
            mgr = self._pool
        else:
            mgr = self._proxy_pools.get(scheme, self._pool)
        resp = None
        try:
            resp = mgr.request(
                "GET",
                url,
                headers={"User-Agent": UA},
                preload_content=False,
                retries=self._urllib3_retry(),
                timeout=self.timeout,
            )
            data = read_bounded(resp.read, self.max_bytes, READ_CHUNK_BYTES)
            return (data if binary else data.decode("utf-8", "ignore")), resp.status
        except Exception:
            return (b"" if binary else ""), 0
        finally:
            if resp is not None:
                resp.release_conn()

    def _fetch_urllib(self, url, binary):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, context=CTX, timeout=self.timeout) as resp:
                data = read_bounded(resp.read, self.max_bytes, READ_CHUNK_BYTES)
                return (data if binary else data.decode("utf-8", "ignore")), resp.status
        except Exception as exc:
            code = getattr(exc, "code", 0)
            return (b"" if binary else ""), code


_default_fetcher = None
_default_fetcher_lock = threading.Lock()


def fetch(url, binary=False):
    global _default_fetcher
    with _default_fetcher_lock:
        if _default_fetcher is None:
            _default_fetcher = HttpFetcher()
        fetcher = _default_fetcher
    return fetcher.fetch(url, binary=binary)


def local_js_filename(url):
    """Build a collision-free local filename using a short SHA-256 prefix of the URL."""
    fn = os.path.basename(urllib.parse.urlparse(url).path)
    if not fn.endswith(".js"):
        return None
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
    return f"{digest}_{fn}"


def origin_of(u):
    p = urllib.parse.urlparse(u)
    return f"{p.scheme}://{p.netloc}"


# ---- chunk manifest parsing -------------------------------------------------
def matched_block(s, end_brace_idx):
    """Walk back from a '}' index to its matching '{' and return the object body."""
    depth = 0
    j = end_brace_idx
    while j >= 0:
        if s[j] == "}":
            depth += 1
        elif s[j] == "{":
            depth -= 1
            if depth == 0:
                return s[j:end_brace_idx + 1]
        j -= 1
    return ""


def parse_chunk_maps(js_text):
    """Return list of (publicPath_hint, {id: hash}) for every `}[x]+".js"` map
    (webpack __webpack_require__.u) found in the text."""
    maps = []
    # publicPath hints in this file: .p="..."  or publicPath="..."
    pubs = re.findall(r'(?:\.p|publicPath)\s*=\s*"([^"]*)"', js_text)
    for m in re.finditer(r'\}\[[A-Za-z_$]\]\s*\+\s*"\.js"', js_text):
        body = matched_block(js_text, m.start())
        pairs = re.findall(r'(\d+):"([0-9a-fA-F]{6,16})"', body)
        if pairs:
            maps.append((pubs, dict(pairs)))
    # Vite style: __vite__mapDeps map of "assets/xx.js"
    for fn in re.findall(r'"(assets/[^"]+\.js)"', js_text):
        maps.append((["/"], {"__vite__": fn}))
    return maps


def chunk_urls(base, js_text):
    """Yield absolute chunk URLs reconstructable from this file's manifest(s)."""
    origin = origin_of(base)
    out = set()
    for pubs, idmap in parse_chunk_maps(js_text):
        paths = pubs or ["/assets/", "/"]
        for cid, h in idmap.items():
            if cid == "__vite__":
                fn = h  # already "assets/xx.js"
                for _pp in paths:
                    out.add(urllib.parse.urljoin(origin + "/", fn))
                continue
            for pp in paths:
                if pp.startswith("http"):
                    bareorigin = ""
                    prefix = pp
                else:
                    bareorigin = origin
                    prefix = pp if pp.startswith("/") else "/" + pp
                if not prefix.endswith("/"):
                    prefix += "/"
                out.add(f"{bareorigin}{prefix}{cid}.{h}.js")
    return out


# ---- endpoint / route extraction -------------------------------------------
API_HINT = re.compile(r'/(?:api|rest|service|services|gateway|graphql|v\d|web|admin|backend|open)\b', re.I)
ASSET_EXT = re.compile(r'\.(js|css|png|jpe?g|svg|gif|woff2?|ttf|ico|map|json|mp4|webp)(\?|$)', re.I)


def extract_endpoints(js_text):
    paths = set()
    # quoted ('/...'), double-quoted, and backtick template paths
    for m in re.findall(r'''["'`](/[A-Za-z0-9_\-./{}$:]+)["'`]''', js_text):
        paths.add(m)
    # concatenation heads:  "/api/x/" + var
    for m in re.findall(r'''["'](/[A-Za-z0-9_\-./]+/)["']\s*\+''', js_text):
        paths.add(m)
    api, other = set(), set()
    for p in paths:
        if ASSET_EXT.search(p):
            continue
        if p.count("/") < 2 and not API_HINT.search(p):
            continue
        (api if API_HINT.search(p) else other).add(p)
    return api, other


def extract_routes(js_text):
    r = set()
    for key in ("path", "to", "redirect", "href"):
        for m in re.findall(key + r'''\s*:\s*["'](/[A-Za-z0-9_\-/:]*)["']''', js_text):
            if not ASSET_EXT.search(m) and not API_HINT.search(m):
                r.add(m)
    return r


# ---- main -------------------------------------------------------------------
def main():
    if len(sys.argv) < 3:
        print("usage: harvest_static.py <BASE_URL> <OUTDIR>")
        sys.exit(1)
    base, outdir = sys.argv[1], sys.argv[2]
    if not base.startswith("http"):
        base = "https://" + base
    jsdir = os.path.join(outdir, "js")
    os.makedirs(jsdir, exist_ok=True)

    workers = resolve_workers()
    max_consecutive_404 = resolve_max_consecutive_404()
    fetcher = HttpFetcher(workers=workers)

    try:
        print(f"[*] entry: {base} (workers={workers}, max_bytes={fetcher.max_bytes}, timeout={fetcher.timeout}s)")
        html, _status = fetcher.fetch(base)
        with open(os.path.join(outdir, "index.html"), "w", encoding="utf-8") as fh:
            fh.write(html)

        # initial scripts from HTML
        srcs = set(re.findall(r'<script[^>]+src="([^"]+\.js[^"]*)"', html))
        srcs |= set(re.findall(r'(?:src|href)="([^"]*\.js)"', html))
        seed = set()
        for s in srcs:
            seed.add(s if s.startswith("http") else urllib.parse.urljoin(base, s))
        print(f"[*] {len(seed)} scripts referenced in HTML")

        state_lock = threading.Lock()
        have = {}            # url -> local path
        confirmed_404 = set()
        transient_failed = set()

        def run_batch(urls, label):
            if not urls:
                return False
            consecutive_404 = [0]
            aborted = threading.Event()

            def dl(url):
                if aborted.is_set():
                    return None
                local_fn = local_js_filename(url)
                if not local_fn:
                    return None
                with state_lock:
                    if url in have:
                        return have[url]
                lp = os.path.join(jsdir, local_fn)
                data, st = fetcher.fetch(url, binary=True)
                if st == 200 and data and not data[:15].lstrip().startswith(b"<"):
                    with open(lp, "wb") as out:
                        out.write(data)
                    with state_lock:
                        have[url] = lp
                        transient_failed.discard(url)
                        consecutive_404[0] = 0
                    return lp
                with state_lock:
                    if st == 404 or (st == 200 and data[:15].lstrip().startswith(b"<")):
                        confirmed_404.add(url)
                        transient_failed.discard(url)
                        consecutive_404[0] += 1
                        if consecutive_404[0] >= max_consecutive_404 and not aborted.is_set():
                            aborted.set()
                            print(
                                f"[!] {label}: stopped after {max_consecutive_404} consecutive "
                                "404/non-JS responses (proxy flood guard)"
                            )
                    else:
                        transient_failed.add(url)
                return None

            with ThreadPoolExecutor(max_workers=workers) as ex:
                list(ex.map(dl, sorted(urls)))
            return aborted.is_set()

        run_batch(seed, "seed")

        # iteratively expand via chunk manifests (chunks reference more chunks)
        seen_urls = set(have.keys())
        frontier = list(have.values())
        rounds = 0
        while frontier and rounds < 6:
            rounds += 1
            new_urls = set()
            for lp in frontier:
                try:
                    with open(lp, encoding="utf-8", errors="ignore") as fh:
                        txt = fh.read()
                except OSError:
                    continue
                for cu in chunk_urls(base, txt):
                    if cu not in seen_urls:
                        new_urls.add(cu)
            seen_urls |= new_urls
            if not new_urls:
                break
            print(f"[*] round {rounds}: {len(new_urls)} new chunk urls from manifest")
            before = set(have.values())
            aborted = run_batch(new_urls, f"round-{rounds}")
            frontier = [p for p in have.values() if p not in before]
            if aborted:
                break

        # retry-once only genuine transient failures (never re-probe 404s or aborted queues)
        all_manifest = set()
        for lp in list(have.values()):
            try:
                with open(lp, encoding="utf-8", errors="ignore") as fh:
                    all_manifest |= chunk_urls(base, fh.read())
            except OSError:
                pass
        retry_urls = sorted(u for u in transient_failed if u not in have and u not in confirmed_404)
        if retry_urls:
            run_batch(retry_urls, "retry")
        still = [u for u in all_manifest if u not in have]
        if all_manifest:
            print(
                f"[*] manifest chunks: {len(all_manifest)} | downloaded {len(have)} | "
                f"unreachable {len(still)} (CSS-only / undeployed)"
            )

        print(f"[+] total JS downloaded: {len(have)}")

        # extract from everything
        api, other, routes = set(), set(), set()
        for lp in have.values():
            try:
                with open(lp, encoding="utf-8", errors="ignore") as fh:
                    txt = fh.read()
            except OSError:
                continue
            a, o = extract_endpoints(txt)
            api |= a
            other |= o
            routes |= extract_routes(txt)

        def dump(name, items):
            path = os.path.join(outdir, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(sorted(items)))
            return path

        dump("api_static.txt", api)
        dump("paths_other.txt", other)
        dump("routes.txt", routes)
        dump("chunkmap.txt", sorted(os.path.basename(u) for u in all_manifest))

        print(f"[+] api endpoints: {len(api)}  (api_static.txt)")
        print(f"[+] other paths:   {len(other)} (paths_other.txt)")
        print(f"[+] route paths:   {len(routes)} (routes.txt)")
        print(f"[+] outdir: {outdir}")
        print(
            "\n[next] reverse the 3 gate facts (see reference.md), fill config.json, "
            "then: node runtime_harvest.js config.json"
        )
    finally:
        fetcher.close()


if __name__ == "__main__":
    main()
