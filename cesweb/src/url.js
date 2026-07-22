// Parse a gateway URL path into a CES target.
//
//   /<host>[-<ces-port>]/<ces-zone-path>
//
// The URL always anchors on the server's PRIMARY (CES) port — its identity.
// The gateway later resolves that to the rpc/CesPlex port for free via a MINX
// GetInfo (cesh ping). The first path segment is the selector; its trailing
// "-<digits>" (if any) is the CES port (omittable -> default). Everything after
// is the CES file path, verbatim — the CES zone namespace IS the URL namespace,
// no translation.
//
// Example: /ces.example.org-53830/p/site/index.html
//          selector="ces.example.org-53830" -> host=ces.example.org port=53830
//          cesPath="/p/site/index.html"

// Parse the OPTIONAL prefill in a dev-terminal path:
//   /dev/dial/<host>[-<ces-port>]/<pid>   or   /dev/dial/<pid>  (default host).
// The terminal's real inputs (server + pid) are entered in the page — the
// session runs on the user's own key, so it isn't namespaced to a server in the
// URL (that form is for the file scope). This just pre-fills the page's boxes.
// Returns { host, cesPort, pid } or null if there's nothing to prefill.
// `pid` is returned as a string of digits (the instance id).
export function parseDialPath(pathname, defaultCesPort, defaultHost) {
  if (!pathname.startsWith('/dev/dial/')) return null;
  const rest = pathname.slice('/dev/dial/'.length).replace(/\/+$/, '');
  const parts = rest.split('/').filter(Boolean);
  if (parts.length === 0) return null;

  // /dev/dial/<pid> against the default host.
  if (parts.length === 1) {
    if (!defaultHost || !/^\d+$/.test(parts[0])) return null;
    return { host: defaultHost, cesPort: defaultCesPort, pid: parts[0] };
  }
  // /dev/dial/<selector>/<pid>  (pid is the last segment, must be digits).
  const pid = parts[parts.length - 1];
  if (!/^\d+$/.test(pid)) return null;
  let selector = parts.slice(0, -1).join('/');
  let host = selector, cesPort = defaultCesPort;
  const m = selector.match(/^(.+)-(\d{1,5})$/);
  if (m) { host = m[1]; cesPort = parseInt(m[2], 10); }
  try { host = decodeURIComponent(host); } catch { /* keep raw */ }
  return { host, cesPort, pid };
}

export function parseRequestPath(pathname, defaultCesPort, defaultHost) {
  if (pathname === '/favicon.ico') return { kind: 'favicon' };

  // Default-host shortcut (single-box deploys): a path that begins with a CES
  // zone (/h//f//p//s/) carries no host selector — use the configured default
  // host. Lets a dedicated gateway serve clean URLs like /p/site/index.html.
  // The explicit /<host>/... form still works whenever the first segment is
  // not a bare zone letter.
  if (defaultHost && /^\/(h|f|p|s)\//.test(pathname)) {
    let cesPath = pathname;
    try { cesPath = decodeURIComponent(cesPath); } catch { /* keep raw */ }
    if (cesPath.endsWith('/')) cesPath += 'index.html';
    return { kind: 'file', host: defaultHost, cesPort: defaultCesPort, cesPath };
  }

  const p = pathname.replace(/^\/+/, '');
  if (p === '') return { kind: 'root' };

  const slash = p.indexOf('/');
  const selector = slash < 0 ? p : p.slice(0, slash);
  let cesPath = slash < 0 ? '' : p.slice(slash); // keeps leading '/'
  try { cesPath = decodeURIComponent(cesPath); } catch { /* keep raw */ }

  // selector -> host[-port]. Host may contain dashes (domain names do), so the
  // port is only the LAST "-<digits>" group; greedy host eats the rest.
  let host = selector;
  let cesPort = defaultCesPort;
  const m = selector.match(/^(.+)-(\d{1,5})$/);
  if (m) { host = m[1]; cesPort = parseInt(m[2], 10); }
  try { host = decodeURIComponent(host); } catch { /* keep raw */ }

  // Directory request -> index.html (a gateway nicety; CES has no directories).
  if (cesPath === '' || cesPath.endsWith('/')) cesPath += 'index.html';

  return { kind: 'file', host, cesPort, cesPath };
}

// Parse a program-browse path:
//   /i/<host>[-<ces-port>]/<pid>[/<subpath...>]   or   /i/<pid>[/<subpath...>]
// The second (host-less) form needs CESWEB_DEFAULT_HOST and a numeric first
// segment. The gateway proxies an HTTP request into the running compute instance
// <pid> on <host> over /ces/lua/1 (the Lua program speaks HTTP itself). The host
// lives in the path so the route knows which server hosts the pid - this is the
// gateway-paid scope (like files), not the user-key /dev scope. A numeric first
// segment reads as the pid because CES hosts are DNS names, never bare numbers.
// Returns { host, cesPort, pid, subPath } or null if it is not a prog path.
// `pid` is a digit string; `subPath` keeps its leading '/' (default '/'), query
// excluded (the caller appends it).
export function parseProgPath(pathname, defaultCesPort, defaultHost) {
  if (pathname !== '/i' && !pathname.startsWith('/i/')) return null;
  const parts = pathname.slice('/i/'.length).split('/');

  let host, cesPort = defaultCesPort, pid, subParts;
  if (defaultHost && parts.length >= 1 && /^\d+$/.test(parts[0])) {
    host = defaultHost; pid = parts[0]; subParts = parts.slice(1);
  } else if (parts.length >= 2 && /^\d+$/.test(parts[1])) {
    let selector = parts[0];
    const m = selector.match(/^(.+)-(\d{1,5})$/);
    if (m) { selector = m[1]; cesPort = parseInt(m[2], 10); }
    try { host = decodeURIComponent(selector); } catch { host = selector; }
    pid = parts[1]; subParts = parts.slice(2);
  } else {
    return null;
  }

  let subPath = '/' + subParts.join('/');
  try { subPath = decodeURIComponent(subPath); } catch { /* keep raw */ }
  return { host, cesPort, pid, subPath };
}
