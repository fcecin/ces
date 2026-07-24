-- /s/vellum.lua — Vellum, writing meant to be kept: the server half of the
-- first cwb application.
--
-- Deployed when [extension] vellum = 1 is set (requires the cwb extension for
-- the application directory, but runs fine without it). Three jobs:
--
-- 1. Register with the cwb application server by appending a heartbeat line to
--    /s/cwb/registry.log (see extensions/cwb.lua for the format and the trust
--    argument). Re-announced every few minutes; silence delists us.
-- 2. Maintain the Vellum front page at /s/vellum/index.html: the wordmark, the
--    invitation to write, and the feed of recently published stories.
-- 3. Accept publish announcements on ces.conn (the browser's write surface
--    dials the relay after a successful publish and sends one line):
--        published|<file-path>|<title>|<author>\n
--    The path is VERIFIED to exist in this server's file store (and to be a
--    reader-reachable /h/ page) before it is listed; the announcement is a
--    hint, the file store is the truth. Stories persist in
--    /s/vellum/stories.log so the feed survives restarts.

CES_MANIFEST = { name = "Vellum", version = "0.1",
                 description = "writing meant to be kept: typeset stories " ..
                               "with rent-paid permanence" }

local REG_LOG    = "/s/cwb/registry.log"
local PAGE_PATH  = "/s/vellum/index.html"
local STORY_LOG  = "/s/vellum/stories.log"
local ENTRY_DESC = "Write, publish, and read typeset stories. " ..
                   "A story lives as long as its author feeds it."
local HEARTBEAT_MS = 5 * 60 * 1000
local FEED_MAX     = 30
local READ_MAX     = 1048576

local function esc(s)
  s = tostring(s or "")
  s = s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
  return s
end

local function write_exact(path, data)
  if #data == 0 then return end
  ces.file_create(path, #data, 0, 0)  -- no-op if it already exists
  ces.file_resize(path, #data)
  ces.file_write(path, 0, data)
end

local function read_all(path)
  local st = ces.file_stat(path)
  if not st or not st.size or st.size == 0 then return nil end
  return ces.file_read(path, 0, math.min(st.size, READ_MAX))
end

-- stories.log -> newest-first list of {ts,path,title,author}, deduped by path.
local function load_stories()
  local seen, list = {}, {}
  local lines = {}
  for line in (read_all(STORY_LOG) or ""):gmatch("[^\n]+") do
    lines[#lines + 1] = line
  end
  for i = #lines, 1, -1 do  -- newest lines are appended last
    local ts, path, title, author =
        lines[i]:match("^S|(%d+)|([^|]+)|([^|]*)|([^|]*)$")
    if ts and not seen[path] then
      seen[path] = true
      list[#list + 1] = { ts = tonumber(ts), path = path, title = title,
                          author = author }
      if #list >= FEED_MAX then break end
    end
  end
  return list
end

local function page_html(stories)
  local b = {}
  b[#b + 1] = [[<!doctype html><html><head><meta charset=utf-8><style>
body{margin:0;background:#ffffff;color:#242424;
font-family:Charter,'Bitstream Charter',Georgia,'Noto Serif','Liberation Serif',serif}
#w{max-width:680px;margin:0 auto;padding:56px 24px 80px}
.vm{font-family:sans-serif;font-size:12px;letter-spacing:3px;color:#b3b3b1;margin-bottom:34px}
h1{font-size:42px;font-weight:700;margin:0 0 10px;letter-spacing:-0.4px}
.sub{font-size:21px;color:#6b6b6b;margin:0 0 34px;line-height:1.5}
.cta{font-family:sans-serif;font-size:15px;margin:0 0 46px}
.cta a{background:#1a8917;color:#ffffff;text-decoration:none;border-radius:18px;
padding:9px 22px}
h2{font-family:sans-serif;font-size:13px;letter-spacing:1px;color:#6b6b6b;
font-weight:600;margin:0 0 18px}
.e{font-size:22px;line-height:1.4;margin:0 0 4px}
.e a{color:#242424;text-decoration:none}
.d{font-family:sans-serif;font-size:13px;color:#9c9c9a;margin:0 0 20px}
.ft{font-family:sans-serif;font-size:12px;color:#9c9c9a;margin-top:56px;
border-top:1px solid #ececeb;padding-top:14px}
.ft a{color:#1a8917;text-decoration:none}
</style></head><body><div id=w>
<div class=vm>VELLUM</div>
<h1>Writing meant to be kept</h1>
<div class=sub>Stories live here because their authors feed them.
No accounts, no platform: your machine pays your way.</div>
<div class=cta><a href="cwb://write">Write a story</a></div>
<h2>RECENTLY PUBLISHED</h2>
]]
  if #stories == 0 then
    b[#b + 1] = "<div class=d>Nothing yet. The first story could be yours.</div>\n"
  else
    for _, s in ipairs(stories) do
      local by = (s.author and s.author ~= "") and ("by " .. esc(s.author))
                 or "by an unnamed author"
      b[#b + 1] = string.format(
          "<p class=e><a href=\"%s\">%s</a></p><div class=d>%s</div>\n",
          esc(s.path), esc(s.title ~= "" and s.title or "Untitled"), by)
    end
  end
  b[#b + 1] = "<div class=ft><a href=\"/s/cwb/index.html\">All applications" ..
              "</a> &nbsp;&#183;&nbsp; vellum</div>\n</div></body></html>\n"
  return table.concat(b)
end

local function regenerate()
  write_exact(PAGE_PATH, page_html(load_stories()))
end

local function register()
  local now = math.floor(ces.now() / 1000000)
  local line = string.format("R|%d|Vellum|%s|%s\n", now, PAGE_PATH, ENTRY_DESC)
  local ok = ces.file_append and ces.file_append(REG_LOG, line)
  if not ok then
    -- Registry file not there yet (we may have booted before cwb.lua, or the
    -- cwb extension is absent). Seeding it ourselves makes registration
    -- ordering-free: any /s/ program may seed it, cwb.lua never overwrites an
    -- existing log, and if cwb.lua never comes, this is just an unread file.
    -- The seed is a header LINE so appends start at a line boundary.
    write_exact(REG_LOG, "# cwb application registry\n")
    ok = ces.file_append and ces.file_append(REG_LOG, line)
    if not ok then ces.log("vellum: cannot register; serving unlisted") end
  end
end

-- A publish announcement: verify, record, regenerate. The file store is the
-- authority: we list only paths that exist here, under /h/ (a reader-payable
-- author zone), so a lying announcement can at worst list a real page.
local function on_announce(line)
  local path, title, author =
      line:match("^published|([^|]+)|([^|]*)|([^|]*)$")
  if not path then return "bad announcement" end
  if path:sub(1, 3) ~= "/h/" then return "not an author page" end
  if #path > 300 or #title > 200 or #author > 64 then return "too long" end
  local st = ces.file_stat(path)
  if not st or not st.size or st.size == 0 then return "no such story" end
  local now = math.floor(ces.now() / 1000000)
  local rec = string.format("S|%d|%s|%s|%s\n", now, path,
                            title:gsub("|", " "), author:gsub("|", " "))
  if not (ces.file_append and ces.file_append(STORY_LOG, rec)) then
    write_exact(STORY_LOG, rec)
  end
  regenerate()
  ces.log("vellum: listed " .. path)
  return "ok"
end

-- The announcement listener: no hello (this is a wire endpoint, not a
-- terminal). One line in, one ack out, close.
ces.conn.set_listener({
  on_open = function(conn) conn.buf = "" end,
  on_data = function(conn, data)
    conn.buf = (conn.buf or "") .. data
    local line = conn.buf:match("^([^\n]*)\n")
    if line then
      local reply = on_announce(line)
      conn:write(reply .. "\n")
      conn:close()
    end
  end,
  on_close = function() end,
})

regenerate()
register()
ces.every(HEARTBEAT_MS, register)
ces.run()
