#include <ces/l2/builtin_site.h>

namespace ces {

namespace {

// /s/welcome — a single, self-contained page. It assumes nothing about the
// gateway in front of it (it's just a CES file): links to its own assets are
// relative, the "rest of this server" link is relative to the /s/ zone, and the
// only absolute links are external. So it renders correctly however a gateway
// maps it.
const char* kIndexHtml = R"HTML(<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>CES — hello from /s/</title>
<link rel=stylesheet href="style.css">
<body>
<header>
  <img src="logo.svg" width=64 height=64 alt="CES">
  <div>
    <h1>Hello from CES.</h1>
    <p class=sub>This page is a file on a CES server, fetched to your browser.</p>
  </div>
</header>

<p>CES is a small public server: it keeps a ledger of credits and lets people
store files and run little programs against it. This page lives in its
<strong>/s/</strong> zone — the space an operator publishes and gives away for
free. Your browser can't speak CES (it's UDP only), so a gateway fetched these
bytes and handed them to you over the web.</p>

<p>There's nothing special about this file — it's plain HTML the server is
serving. Files, pages, and programs are all just entries in the same ledger.</p>

<h2>Look around</h2>
<ul>
  <li><a href="../index.html">This server's published files</a> — the catalog of the /s/ zone.</li>
  <li><a href="https://pubcom.org">What it's for</a> — the idea behind CES (public computing).</li>
  <li><a href="https://github.com/fcecin/ces">The code</a> — CES is open source.</li>
</ul>

<footer>Served from <code>/s/welcome/</code> — shipped with every CES server.</footer>
</body>
</html>
)HTML";

const char* kStyleCss = R"CSS(:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font:17px/1.65 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  max-width:42rem;margin:0 auto;padding:3rem 1.2rem;color:#1c1c1e}
header{display:flex;align-items:center;gap:1.1rem;margin-bottom:1.6rem}
header h1{font-size:1.8rem;margin:0;line-height:1.1}
.sub{margin:.35rem 0 0;color:#666}
h2{font-size:1.05rem;margin:2rem 0 .5rem;color:#444}
p{margin:.9rem 0}
ul{list-style:none;padding:0}
li{padding:.55rem .9rem;margin:.45rem 0;background:#0a7d3312;border-radius:8px}
code{background:#00000010;padding:.12em .4em;border-radius:4px;font-size:.9em}
a{color:#0a7d33;text-decoration:none;font-weight:600}
a:hover{text-decoration:underline}
footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid #00000014;
  color:#999;font-size:.88rem}
footer code{font-weight:400;color:inherit}
)CSS";

const char* kLogoSvg = R"SVG(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" role="img" aria-label="CES">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#0c8"/><stop offset="1" stop-color="#063"/></linearGradient></defs>
<rect width="100" height="100" rx="22" fill="url(#g)"/>
<text x="50" y="70" font-family="system-ui,sans-serif" font-size="58" font-weight="800" text-anchor="middle" fill="#fff">C</text>
</svg>
)SVG";

constexpr const char* kSitePrefix = "/s/welcome/";

}  // namespace

std::vector<BuiltinSiteFile> builtinSiteFiles() {
  return {
    {"welcome/index.html", kIndexHtml},
    {"welcome/style.css",  kStyleCss},
    {"welcome/logo.svg",   kLogoSvg},
  };
}

bool isBuiltinSitePath(const std::string& cesName) {
  const std::string p = kSitePrefix;
  return cesName.size() > p.size() &&
         cesName.compare(0, p.size(), p) == 0;
}

}  // namespace ces
