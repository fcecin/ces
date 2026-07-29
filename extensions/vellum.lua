-- /s/vellum.lua -- Vellum, "writing meant to be kept": the server half of the
-- first cwb application, served DYNAMICALLY.
--
-- Vellum is a web app, not a bag of static files. Every page is generated in
-- Lua at request time over ces.conn (the browser dials the instance via
-- lua://<pid>@host/<path> or luarpc://host:port/<path>, which sends an HTTP
-- GET; we answer once and close). The caller's CES identity is conn.pubkey, so
-- the app can GATE on who is asking.
--
-- THE NAME GATE IS AT ENTRY, NOT PUBLISH. Writing depends on a registered
-- name (it decides the /f/<name>/ zone stories live in). So /write refuses to
-- open the editor for a nameless caller: it serves a "register your name" page
-- instead. You never write a story and then lose it at publish time.
--
-- Persistence: the bounded story-feed state lives in /s/vellum/stories.state.
-- Published stories are real files in the author's own /f/<name>/ zone.

CES_MANIFEST = { name = "Vellum", version = "0.2",
                 description = "writing meant to be kept: typeset stories " ..
                               "with rent-paid permanence" }

local STORY_STATE = "/s/vellum/stories.state"
local LEGACY_STORY_LOG = "/s/vellum/stories.log"
local SOURCE     = "/s/vellum.lua"   -- resolved to a live pid by the directory
local ENTRY_DESC = "Own what you write: typeset stories under your own " ..
                   "name, kept alive by the people who love them."
local HEARTBEAT_MS = 5 * 60 * 1000
local FEED_MAX     = 30
local READ_MAX     = 1048576
local REQUEST_MAX  = 16 * 1024
local registration_conn = nil

-- === tiny HTTP-over-ces.conn (see monitor.lua's web module) ===============
local function parse_request(raw)
  local head = raw:match("^(.-)\r\n\r\n")
  if not head then return nil end
  local body = raw:sub(#head + 5)
  local first = head:match("^(.-)\r\n") or head
  local method, target = first:match("^(%S+)%s+(%S+)")
  if not method then return nil end
  local path, query = target:match("^([^?]*)%??(.*)$")
  local headers = {}
  for line in head:gmatch("\r\n([^\r\n]+)") do
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k then headers[k:lower()] = v end
  end
  return { method = method, target = target, path = path, query = query,
           headers = headers, body = body }
end

local function http(body, status)
  body = body or ""
  return ("HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\n" ..
          "Content-Length: %d\r\nConnection: close\r\n\r\n%s")
             :format(status or 200, (status == 404 and "Not Found") or "OK",
                     #body, body)
end

-- === helpers ==============================================================
local function esc(s)
  s = tostring(s or "")
  return (s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"))
end

-- The display form: the stored key_name is the underscore form; show spaces.
local function pretty(name) return (tostring(name or ""):gsub("_", " ")) end

local function write_exact(path, data)
  if #data == 0 then return false end
  local st = ces.file_stat(path)
  if not st then
    local ok = ces.file_create(path, #data, 0, 0)
    if not ok then return false end
  end
  local ok = ces.file_resize(path, #data)
  if not ok then return false end
  return ces.file_write(path, 0, data) and true or false
end

local function read_all(path)
  local st = ces.file_stat(path)
  if not st or not st.size or st.size == 0 then return nil end
  return ces.file_read(path, 0, math.min(st.size, READ_MAX))
end

local function load_stories_from(path, max)
  max = max or FEED_MAX
  local seen, list, lines = {}, {}, {}
  for line in (read_all(path) or ""):gmatch("[^\n]+") do
    lines[#lines + 1] = line
  end
  for i = #lines, 1, -1 do
    local ts, path, title, author =
        lines[i]:match("^S|(%d+)|([^|]+)|([^|]*)|([^|]*)$")
    if ts and not seen[path] then
      seen[path] = true
      list[#list + 1] = { ts = tonumber(ts), path = path, title = title,
                          author = author }
      if #list >= max then break end
    end
  end
  return list
end

local function load_stories()
  return load_stories_from(STORY_STATE)
end

-- Per-author story records: the hints that make the author's live shelf
-- possible (zones are non-enumerable by design; announces are the discovery).
-- The file store stays the truth: dead records are pruned at render time.
local AUTHOR_MAX = 500

local function author_state_path(author)
  if not author or not author:match("^[%w_%.%-]+$") then return nil end
  return "/s/vellum/authors/" .. author .. ".state"
end

local function save_author(author, list)
  local p = author_state_path(author)
  if not p then return end
  local b = {}
  for i = 1, math.min(#list, AUTHOR_MAX) do
    local s = list[i]
    b[#b + 1] = ("S|%d|%s|%s|%s\n"):format(
        s.ts, s.path, s.title:gsub("|", " "), s.author:gsub("|", " "))
  end
  if #b == 0 then
    pcall(function() ces.file_delete(p) end)
    return
  end
  write_exact(p, table.concat(b))
end

local function author_upsert(author, rec)
  local p = author_state_path(author)
  if not p then return end
  local list = load_stories_from(p, AUTHOR_MAX)
  for i = #list, 1, -1 do
    if list[i].path == rec.path then table.remove(list, i) end
  end
  table.insert(list, 1, rec)
  save_author(author, list)
end

local function save_stories(stories)
  local b = {}
  for i = 1, math.min(#stories, FEED_MAX) do
    local s = stories[i]
    b[#b + 1] = ("S|%d|%s|%s|%s\n"):format(
        s.ts, s.path, s.title:gsub("|", " "), s.author:gsub("|", " "))
  end
  if #b == 0 then
    -- write_exact cannot write zero bytes; an empty feed is the file's absence
    -- (unlisting the last story must not leave stale state to reload on boot).
    pcall(function() ces.file_delete(STORY_STATE) end)
    return true
  end
  return write_exact(STORY_STATE, table.concat(b))
end

-- === pages (all generated live) ===========================================
local HEAD = [[<!doctype html><html><head><meta charset=utf-8><style>
body{margin:0;background:#ffffff;color:#242424;
font-family:Charter,'Bitstream Charter',Georgia,'Noto Serif','Liberation Serif',serif}
#w{max-width:680px;margin:0 auto;padding:56px 24px 80px}
.vm{font-family:sans-serif;font-size:12px;letter-spacing:3px;color:#b3b3b1;margin-bottom:34px}
h1{font-size:42px;font-weight:700;margin:0 0 10px;letter-spacing:-0.4px}
.sub{font-size:21px;color:#6b6b6b;margin:0 0 34px;line-height:1.5}
.cta{font-family:sans-serif;font-size:15px;margin:0 0 46px}
.cta a{background:#1a8917;color:#ffffff;text-decoration:none;border-radius:18px;padding:9px 22px}
.cta a:hover{background:#156d12}
h2{font-family:sans-serif;font-size:13px;letter-spacing:1px;color:#6b6b6b;font-weight:600;margin:0 0 18px}
.e{font-size:22px;line-height:1.4;margin:0 0 4px}.e a{color:#242424;text-decoration:none}
.d{font-family:sans-serif;font-size:13px;color:#9c9c9a;margin:0 0 20px}
.bar{font-family:sans-serif;font-size:12px;color:#9c9c9a;margin:0 0 24px}
.bar .vm2{letter-spacing:3px;color:#b3b3b1}.bar a{color:#1a8917;text-decoration:none}
.ft{font-family:sans-serif;font-size:12px;color:#9c9c9a;margin-top:56px;border-top:1px solid #ececeb;padding-top:14px}
.ft a{color:#1a8917;text-decoration:none}
</style></head><body><div id=w>]]

-- A published story is a FILE in the author's /f/<name>/ zone (the file store),
-- not a Vellum route. This page is served over lua://<pid>, so a bare "/f/..."
-- link would resolve against lua:// and hit Vellum (404). Link the file store
-- explicitly: file://<host>/f/.../slug.html (portless -> cwb's rpc lane). host
-- is the Host header the browser sent, so the link points back at this server.
local function story_href(host, path)
  if host and host ~= "" then return "file://" .. host .. path end
  return path  -- no Host header: fall back to the raw path
end

-- The front page knows its reader (every request is authenticated), so the
-- pitch is shown exactly once in a person's life here: callers without a
-- name get the full hero; named citizens land straight on the stories. A
-- manual that never goes away is furniture; content is the page.
local function page_index(stories, host, name)
  local b = { HEAD }
  if name and name ~= "" then
    b[#b + 1] = "<div class=vm>VELLUM</div>"
    b[#b + 1] = "<div class=cta><a href=\"/write\">Write a story</a></div>"
  else
    b[#b + 1] = "<div class=vm>VELLUM</div>"
    b[#b + 1] = "<h1>Own what you write</h1>"
    b[#b + 1] = "<div class=sub>A story here lives under your name, at an " ..
        "address of its own, on a server that cannot unpublish you. It " ..
        "stays alive as long as anyone who loves it &mdash; you, or a " ..
        "reader &mdash; keeps it fed.</div>"
    b[#b + 1] = "<div class=cta><a href=\"/write\">Write a story</a></div>"
  end
  b[#b + 1] = "<h2>RECENTLY PUBLISHED</h2>"
  if #stories == 0 then
    b[#b + 1] = "<div class=d>Nothing yet. The first story could be yours.</div>"
  else
    for _, s in ipairs(stories) do
      local by = (s.author and s.author ~= "")
                 and ("by <a href=\"/by/" .. esc(s.author) .. "\">" ..
                      esc(pretty(s.author)) .. "</a>")
                 or "by an unnamed author"
      b[#b + 1] = ("<p class=e><a href=\"%s\">%s</a></p><div class=d>%s</div>")
          :format(esc(story_href(host, s.path)),
                  esc(s.title ~= "" and s.title or "Untitled"), by)
    end
  end
  b[#b + 1] = "</div></body></html>"
  return table.concat(b)
end

-- The file store is the truth for EVERY view: drop records whose story no
-- longer exists. Returns the live list plus whether anything was dropped.
local function prune_dead(list)
  local live, dropped = {}, false
  for _, s in ipairs(list) do
    local st = ces.file_stat(s.path)
    if st and st.size and st.size > 0 then
      live[#live + 1] = s
    else
      dropped = true
    end
  end
  return live, dropped
end

-- Unix seconds -> "YYYY-MM-DD" (no os.date in the sandbox; civil-from-days).
local function iso_date(secs)
  local z = math.floor(secs / 86400) + 719468
  local era = math.floor(z / 146097)
  local doe = z - era * 146097
  local yoe = math.floor((doe - math.floor(doe / 1460) +
      math.floor(doe / 36524) - math.floor(doe / 146096)) / 365)
  local y = yoe + era * 400
  local doy = doe - (365 * yoe + math.floor(yoe / 4) - math.floor(yoe / 100))
  local mp = math.floor((5 * doy + 2) / 153)
  local d = doy - math.floor((153 * mp + 2) / 5) + 1
  local m = mp < 10 and mp + 3 or mp - 9
  if m <= 2 then y = y + 1 end
  return ("%04d-%02d-%02d"):format(y, m, d)
end

-- The author's shelf, served LIVE. The records are hints; the file store is
-- the truth: each render stats the files and prunes the dead, so a deleted
-- story disappears from here with no index to maintain or lose.
local function page_author(author, host)
  local p = author_state_path(author)
  local list = p and load_stories_from(p, AUTHOR_MAX) or {}
  local live, pruned = prune_dead(list)
  if pruned then save_author(author, live) end
  local b = { HEAD,
    "<div class=bar><span class=vm2>VELLUM</span></div>",
    "<h1>Stories</h1>",
    ("<div class=sub>by %s</div>"):format(esc(pretty(author))) }
  if #live == 0 then
    b[#b + 1] = "<div class=d>Nothing here yet.</div>"
  else
    for _, s in ipairs(live) do
      b[#b + 1] = ("<p class=e><a href=\"%s\">%s</a></p><div class=d>%s</div>")
          :format(esc(story_href(host, s.path)),
                  esc(s.title ~= "" and s.title or "Untitled"),
                  esc(iso_date(s.ts)))
    end
  end
  b[#b + 1] = "<div class=ft><a href=\"/\">All stories</a> &#183; vellum</div>"
  b[#b + 1] = "</div></body></html>"
  return table.concat(b)
end

-- The GATE page: shown at /write when the caller has no name. Vellum refuses
-- the editor and LINKS to the browser's own account page, where names are set.
-- Setting a name is a signed ledger op (the main CES port) -- that is cwb's
-- ces:// account UI, not Vellum's business. Vellum only checks (ces.keyname)
-- and hands off; it never touches the main port. `host` is the Host header the
-- browser sent, so the link points back at this same server.
local function page_register(host)
  local acct = "ces://" .. (host ~= "" and host or "") .. "/"
  return HEAD ..
    "<div class=bar><span class=vm2>VELLUM</span></div>" ..
    "<h1>First, your name</h1>" ..
    "<div class=sub>Your writing lives under your name -- it becomes the " ..
    "/f/&lt;name&gt;/ home your stories are kept in. " ..
    "<a href=\"" .. acct .. "\">Set your name on your account</a>, then come " ..
    "back here to write.</div>" ..
    "<div class=ft><a href=\"/\">All stories</a> &#183; vellum</div>" ..
    "</div></body></html>"
end

-- The editor, shown at /write once the caller is named.
local function page_compose(name)
  -- A fullscreen native application proxy: cwb retains browser chrome,
  -- navigation and the outer scrollbar; cwb-write owns the whole page canvas.
  -- There is deliberately no surrounding HTML application UI.
  -- rpcport: the SERVER's rpc lane, declared explicitly because this page may
  -- be reached over luarpc:// (our own direct port), from which the browser
  -- cannot infer where file/compute binds belong.
  local info = ces.server_info and ces.server_info() or nil
  local rpc = (type(info) == "table" and tonumber(info.rpc_port)) or 0
  local rpcparam = rpc > 0
      and ("<param name=\"rpcport\" value=\"" .. rpc .. "\">") or ""
  return "<!doctype html><html><body style=\"margin:0\">" ..
    "<object type=\"application/x-cwb-write\">" ..
    "<param name=\"display\" value=\"fullscreen\">" ..
    "<param name=\"approot\" value=\"vellum\">" ..
    "<param name=\"appname\" value=\"Vellum\">" ..
    "<param name=\"appsource\" value=\"" .. SOURCE .. "\">" ..
    rpcparam ..
    "<param name=\"authorhandle\" value=\"" .. esc(name) .. "\">" ..
    "<param name=\"author\" value=\"" .. esc(pretty(name)) .. "\">" ..
    "</object></body></html>"
end

-- === publish announce (verify, record, reflected in the live feed) =========
local function hex(s)
  return (tostring(s or ""):gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end

-- The caller may act on a story path only if the authenticated connection
-- identity owns the zone it lives in: /f/<name>/ by key_name, /h/<hex>/ by
-- the key itself. Returns the canonical owner string, or nil + error.
local function verify_story_owner(path, conn)
  if path:sub(1, 3) ~= "/f/" and path:sub(1, 3) ~= "/h/" then
    return nil, "not an author page"
  end
  if not conn.pubkey or #conn.pubkey ~= 32 then return nil, "no identity" end
  if path:sub(1, 3) == "/f/" then
    local owner = path:match("^/f/([^/]+)/")
    if not owner or ces.keyname(conn.pubkey) ~= owner then
      return nil, "not owner"
    end
    return owner
  end
  local owner = path:match("^/h/([0-9a-fA-F]+)/")
  if not owner or owner:lower() ~= hex(conn.pubkey) then
    return nil, "not owner"
  end
  return owner:lower()
end

local function on_announce(line, conn)
  local path, title, author = line:match("^published|([^|]+)|([^|]*)|([^|]*)$")
  if not path then return "bad announcement" end
  if #path > 300 or #title > 200 or #author > 64 then return "too long" end
  local owner, err = verify_story_owner(path, conn)
  if not owner then return err end
  author = owner
  local st = ces.file_stat(path)
  if not st or not st.size or st.size == 0 then return "no such story" end
  local now = math.floor(ces.now() / 1000000)
  local stories = load_stories()
  for i = #stories, 1, -1 do
    if stories[i].path == path then table.remove(stories, i) end
  end
  local rec = {ts=now, path=path, title=title, author=author}
  table.insert(stories, 1, rec)
  if not save_stories(stories) then return "feed write failed" end
  author_upsert(author, rec)  -- the live shelf's discovery record
  ces.log("vellum: listed " .. path)
  return "ok"
end

-- "unlist|<path>": the owner takes a story out of the feed. The story file
-- itself is untouched (unlist is not unpublish); re-announcing re-lists it.
local function on_unlist(line, conn)
  local path = line:match("^unlist|(.+)$")
  if not path or #path > 300 then return "bad unlist" end
  local owner, err = verify_story_owner(path, conn)
  if not owner then return err end
  local stories = load_stories()
  local removed = false
  for i = #stories, 1, -1 do
    if stories[i].path == path then
      table.remove(stories, i)
      removed = true
    end
  end
  if removed then
    if not save_stories(stories) then return "feed write failed" end
    ces.log("vellum: unlisted " .. path)
  end
  return "ok"
end

-- "listed|<path>": is this story in the feed right now? Public read; the
-- feed page shows the same answer to everyone.
local function on_listed(line)
  local path = line:match("^listed|(.+)$")
  if not path then return "bad listed" end
  for _, s in ipairs(load_stories()) do
    if s.path == path then return "yes" end
  end
  return "no"
end

-- === router: path + caller identity -> a page =============================
local function route(req, conn)
  local path = req.path or "/"
  local host = (req.headers and req.headers["host"]) or ""
  if path == "/" or path == "" or path == "/index.html" then
    local name
    if conn.pubkey and #conn.pubkey == 32 then
      name = ces.keyname(conn.pubkey)
    end
    local stories, pruned = prune_dead(load_stories())
    if pruned then save_stories(stories) end
    return http(page_index(stories, host, name))
  elseif path:match("^/by/[%w_%.%-]+$") then
    return http(page_author(path:sub(5), host))
  elseif path == "/write" then
    -- ENTRY GATE: the caller must own a key_name on this server.
    local name
    if conn.pubkey and #conn.pubkey == 32 then name = ces.keyname(conn.pubkey) end
    if not name or name == "" then
      -- refuse the editor; hand off to the account page to set a name
      return http(page_register(req.headers and req.headers["host"] or ""))
    end
    return http(page_compose(name))
  end
  return http("<h1>Not found</h1>", 404)
end

-- === one ces.conn listener: HTTP pages AND raw publish announces ==========
ces.conn.set_listener({
  on_open = function(conn) conn.buf = "" end,
  on_data = function(conn, data)
    if conn.cwb_registration then
      conn.buf = (conn.buf or "") .. data
      if conn.buf:find("\n", 1, true) then
        ces.log("vellum: cwb registration: " .. conn.buf:gsub("[\r\n]+$", ""))
        conn:close()
        registration_conn = nil
      end
      return
    end
    conn.buf = (conn.buf or "") .. data
    if #conn.buf > REQUEST_MAX then
      conn:write("request too large\n"); conn:close(); return
    end
    -- Raw command line ("published|...", "unlist|...", "listed|...\n") vs an
    -- HTTP request (a method + space, so it never matches word-then-pipe).
    local cmd = conn.buf:match("^(%l+)|")
    if cmd == "published" or cmd == "unlist" or cmd == "listed" then
      local line = conn.buf:match("^([^\n]*)\n")
      if line then
        local reply
        if cmd == "published" then reply = on_announce(line, conn)
        elseif cmd == "unlist" then reply = on_unlist(line, conn)
        else reply = on_listed(line) end
        conn:write(reply .. "\n")
        conn:close()
      end
      return
    end
    if conn.buf:find("\r\n\r\n", 1, true) then
      local req = parse_request(conn.buf)
      local out = req and route(req, conn) or http("<h1>Bad request</h1>", 400)
      conn:write(out)
      conn:close()
    end
  end,
  on_close = function(conn)
    if conn == registration_conn then registration_conn = nil end
  end,
})

-- One-time migration from the old append-log name into compact bounded state.
-- Old generated Vellum HTML is equally obsolete: every page is served here.
if not read_all(STORY_STATE) then
  local legacy = load_stories_from(LEGACY_STORY_LOG)
  if #legacy > 0 then save_stories(legacy) end
end
pcall(function() ces.file_delete(LEGACY_STORY_LOG) end)
pcall(function() ces.file_delete("/s/vellum/index.html") end)

-- Vellum is a client of the live CWB directory service. Discover the current
-- /s/cwb.lua instance through the native compute catalog, dial its dedicated
-- RPC port, and renew our in-memory lease. No shared registration file exists.
local function register_once()
  if registration_conn then return end
  local info = ces.server_info and ces.server_info() or nil
  if type(info) ~= "table" then ces.log("vellum: registration: no server info"); return end
  local host = tostring(info.server_name or ""):match("^([^:]+)")
  local rpc = tonumber(info.rpc_port) or 0
  local my_port = tonumber(ces.rpc_port and ces.rpc_port() or 0) or 0
  if not host or host == "" or rpc == 0 or my_port == 0 then
    ces.log(("vellum: registration: endpoint unavailable host=%s rpc=%s my_port=%s")
        :format(tostring(host), tostring(rpc), tostring(my_port)))
    return
  end
  -- Discovery and registration stay on the CES host. The advertised public
  -- name is still used in rendered URLs, but is not a transport dependency.
  local cc = ces.compute_client("127.0.0.1:" .. rpc)
  if not cc then ces.log("vellum: registration: compute connect failed"); return end
  local rows = cc:instances("/s/cwb.lua") or {}
  cc:close()
  table.sort(rows, function(a, b) return (a.pid or 0) < (b.pid or 0) end)
  local cwb = rows[1]
  if not cwb or not cwb.rpc_port or tonumber(cwb.rpc_port) == 0 then
    ces.log("vellum: registration: cwb instance unavailable"); return
  end
  local conn = ces.conn.connect("127.0.0.1:" .. tostring(cwb.rpc_port),
                                cwb.program_pubkey, 5000)
  if not conn then ces.log("vellum: registration: direct connect failed"); return end
  registration_conn = conn
  conn.cwb_registration = true
  conn.buf = ""
  conn:write(("REGISTER|Vellum|%s|%s|%d\n"):format(
      SOURCE, ENTRY_DESC:gsub("|", " "), my_port))
end

ces.spawn(register_once)
ces.every(HEARTBEAT_MS, function() ces.spawn(register_once) end)
ces.run()
