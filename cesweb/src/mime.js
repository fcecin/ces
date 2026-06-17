// extension -> Content-Type.
//
// CES stores NO content-type — a file is a name with an extension, nothing
// more (MIME is web meaning, deliberately kept out of the substrate). So the
// gateway, at the edge, guesses the type purely from the URL extension. This
// guess is the gateway's only lever: a known renderable type displays inline;
// anything unknown gets application/octet-stream, whose sole job is to make the
// browser pop its download dialog instead of trying to render bytes it can't.
// The gateway never decides display-vs-download — the browser's rules do.

const TYPES = {
  html: 'text/html; charset=utf-8',
  htm:  'text/html; charset=utf-8',
  css:  'text/css; charset=utf-8',
  js:   'text/javascript; charset=utf-8',
  mjs:  'text/javascript; charset=utf-8',
  json: 'application/json; charset=utf-8',
  txt:  'text/plain; charset=utf-8',
  md:   'text/markdown; charset=utf-8',
  lua:  'text/plain; charset=utf-8',   // source — show inline, don't download
  xml:  'application/xml; charset=utf-8',
  csv:  'text/csv; charset=utf-8',
  svg:  'image/svg+xml',
  png:  'image/png',
  jpg:  'image/jpeg',
  jpeg: 'image/jpeg',
  gif:  'image/gif',
  webp: 'image/webp',
  avif: 'image/avif',
  ico:  'image/x-icon',
  bmp:  'image/bmp',
  pdf:  'application/pdf',
  wasm: 'application/wasm',
  woff: 'font/woff',
  woff2:'font/woff2',
  ttf:  'font/ttf',
  otf:  'font/otf',
  mp3:  'audio/mpeg',
  ogg:  'audio/ogg',
  wav:  'audio/wav',
  mp4:  'video/mp4',
  webm: 'video/webm',
  zip:  'application/zip',
  gz:   'application/gzip',
};

export function contentTypeFor(path) {
  const dot = path.lastIndexOf('.');
  const slash = path.lastIndexOf('/');
  if (dot < 0 || dot < slash) return 'application/octet-stream';
  return TYPES[path.slice(dot + 1).toLowerCase()] || 'application/octet-stream';
}
