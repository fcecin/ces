-- /s/cwb.lua — the cwb application server: the server side of the cwb browser.
--
-- Deployed when [extension] cwb = 1 is set. Maintains the server's cwb entry
-- point at /s/cwb/index.html: the directory of installed cwb applications. A
-- cwb browser given a bare host lands here first (falling back to the plain
-- /s/index.html catalog on servers without this extension).
--
-- Registration is stigmergic, through the file store, and the trust check is
-- the /s/ zone rule itself: only a server-authorized (/s/-sourced) program can
-- append to /s/cwb/registry.log, so every line in it was written by something
-- the operator installed. An application announces itself by appending
--   R|<unix-seconds>|<name>|<entry-path>|<description>\n
-- at boot and every few minutes (see extensions/vellum.lua). This extension
-- polls the log, keeps the freshest line per name, drops entries not
-- re-announced within TTL (a dead app leaves the directory by itself), and
-- regenerates the entry page when the set changes. Ordering-free: apps may
-- boot before or after this one; the log survives everyone's restarts.
-- User programs on /h/ or /f/ cannot write the log; they are reachable
-- directly but are not server-authorized applications, so they are not listed.

CES_MANIFEST = { name = "cwb application server", version = "0.1",
                 description = "directory of installed cwb applications; " ..
                               "maintains the /s/cwb/index.html entry point" }

local LOG_PATH   = "/s/cwb/registry.log"
local PAGE_PATH  = "/s/cwb/index.html"
local TTL_S      = 30 * 60        -- unannounced for 30 min = delisted
local POLL_MS    = 15 * 1000      -- log poll cadence
local COMPACT_AT = 64 * 1024      -- rewrite the log when it grows past this

local READ_MAX = 1048576

local function esc(s)
  s = tostring(s or "")
  s = s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
  return s
end

-- Size a /s/ file to exactly #data and overwrite from 0 (WRITE never grows a
-- file; RESIZE pays nothing on /s/).
local function write_exact(path, data)
  if #data == 0 then return end
  ces.file_create(path, #data, 0, 0)  -- no-op if it already exists
  ces.file_resize(path, #data)
  ces.file_write(path, 0, data)
end

local function read_all(path)
  local st = ces.file_stat(path)
  if not st or not st.size or st.size == 0 then return nil, st end
  local n = math.min(st.size, READ_MAX)
  return ces.file_read(path, 0, n), st
end

-- registry.log -> { name -> {ts,name,entry,desc} }, freshest line per name.
local function parse_log(data)
  local apps = {}
  local now = math.floor(ces.now() / 1000000)
  for line in (data or ""):gmatch("[^\n]+") do
    line = line:gsub("%z", "")  -- tolerate a sparse-seeded log's NUL padding
    local ts, name, entry, desc =
        line:match("^R|(%d+)|([^|]+)|([^|]+)|([^|]*)$")
    if ts then
      ts = tonumber(ts)
      -- Entry pages live in the file store; anything else is not linkable.
      if ts and entry:sub(1, 1) == "/" and (now - ts) < TTL_S then
        local cur = apps[name]
        if not cur or cur.ts < ts then
          apps[name] = { ts = ts, name = name, entry = entry, desc = desc }
        end
      end
    end
  end
  return apps
end

local function sorted(apps)
  local list = {}
  for _, a in pairs(apps) do list[#list + 1] = a end
  table.sort(list, function(x, y) return x.name < y.name end)
  return list
end

local function fingerprint(list)
  local parts = {}
  for _, a in ipairs(list) do
    parts[#parts + 1] = a.name .. "\1" .. a.entry .. "\1" .. (a.desc or "")
  end
  return table.concat(parts, "\2")
end

local function page_html(list)
  local b = {}
  b[#b + 1] = [[<!doctype html><html><head><meta charset=utf-8><style>
body{margin:0;background:#ffffff;color:#242424;
font-family:Charter,'Bitstream Charter',Georgia,'Noto Serif','Liberation Serif',serif}
#w{max-width:680px;margin:0 auto;padding:56px 24px 80px}
.vm{font-family:sans-serif;font-size:12px;letter-spacing:3px;color:#b3b3b1;margin-bottom:34px}
h1{font-size:34px;font-weight:700;margin:0 0 6px}
.sub{font-family:sans-serif;font-size:13px;color:#6b6b6b;margin:0 0 40px}
.e{font-size:22px;line-height:1.4;margin:0 0 6px}
.e a{color:#242424;text-decoration:none}
.d{font-family:sans-serif;font-size:14px;color:#6b6b6b;margin:0 0 22px}
.ft{font-family:sans-serif;font-size:12px;color:#9c9c9a;margin-top:56px;
border-top:1px solid #ececeb;padding-top:14px}
.ft a{color:#1a8917;text-decoration:none}
</style></head><body><div id=w>
<div class=vm>THIS SERVER</div>
<h1>Applications</h1>
<div class=sub>installed and running here</div>
]]
  if #list == 0 then
    b[#b + 1] = "<div class=d>No applications installed yet.</div>\n"
  else
    for _, a in ipairs(list) do
      b[#b + 1] = string.format(
          "<p class=e><a href=\"%s\">%s</a></p><div class=d>%s</div>\n",
          esc(a.entry), esc(a.name), esc(a.desc))
    end
  end
  b[#b + 1] = "<div class=ft><a href=\"/s/index.html\">All server files</a>" ..
              " &nbsp;&#183;&nbsp; cwb application server</div>\n"
  b[#b + 1] = "</div></body></html>\n"
  return table.concat(b)
end

-- Compact: rewrite the log as one fresh line per live app. An announcement
-- racing the rewrite can lose its line; its next heartbeat restores it.
local function compact(apps)
  local now = math.floor(ces.now() / 1000000)
  local b = {}
  for _, a in pairs(apps) do
    b[#b + 1] = string.format("R|%d|%s|%s|%s\n", now, a.name, a.entry,
                              a.desc or "")
  end
  if #b > 0 then write_exact(LOG_PATH, table.concat(b)) end
end

local last_fp = nil

local function refresh()
  local data, st = read_all(LOG_PATH)
  local apps = parse_log(data)
  local list = sorted(apps)
  local fp = fingerprint(list)
  if fp ~= last_fp then
    write_exact(PAGE_PATH, page_html(list))
    last_fp = fp
    ces.log("cwb: entry page regenerated (" .. #list .. " app(s))")
  end
  if st and st.size and st.size > COMPACT_AT then compact(apps) end
end

-- Seed the log (a real header LINE, so the first append starts at a line
-- boundary) and publish the (possibly empty) directory immediately: the entry
-- point exists from boot. Never overwrite an existing log.
if not ces.file_stat(LOG_PATH) then
  write_exact(LOG_PATH, "# cwb application registry\n")
end
refresh()
ces.every(POLL_MS, refresh)
ces.run()
