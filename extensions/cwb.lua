-- cwb.lua -- the live application directory service for the CWB browser.
--
-- This is an HTTP server, not an HTML generator. Installed applications are
-- clients of this service: they discover this instance, connect over ces.conn,
-- and renew a bounded in-memory lease. Browser users connect to GET / and
-- receive a page rendered from the live lease table at that instant.

CES_MANIFEST = { name = "cwb application server", version = "0.2",
                 description = "live directory of installed CWB applications" }

local LEASE_S     = 30 * 60
local REQUEST_MAX = 16 * 1024
local SOURCE      = "/s/cwb.lua"
local apps        = {}

local function esc(s)
  s = tostring(s or "")
  return (s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
           :gsub('"', "&quot;"):gsub("'", "&#39;"))
end

local function now_s() return math.floor(ces.now() / 1000000) end

local function server_endpoint()
  local info = ces.server_info and ces.server_info() or nil
  if type(info) ~= "table" then return nil, nil end
  local host = tostring(info.server_name or ""):match("^([^:]+)")
  if not host or host == "" then return nil, nil end
  return host, tonumber(info.rpc_port) or 0
end

local function http(body, status)
  body = body or ""
  status = status or 200
  local reason = status == 404 and "Not Found" or
                 status == 400 and "Bad Request" or "OK"
  return ("HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\n" ..
          "Content-Length: %d\r\nConnection: close\r\n\r\n%s")
             :format(status, reason, #body, body)
end

local function parse_request(raw)
  local head = raw:match("^(.-)\r\n\r\n")
  if not head then return nil end
  local first = head:match("^(.-)\r\n") or head
  local method, target = first:match("^(%S+)%s+(%S+)")
  if not method then return nil end
  return {method=method, path=(target:match("^([^?]*)") or "/")}
end

local function live_apps()
  local t, out = now_s(), {}
  for name, app in pairs(apps) do
    if app.expires > t then
      out[#out + 1] = app
    else
      apps[name] = nil
    end
  end
  table.sort(out, function(a, b) return a.name < b.name end)
  return out
end

local function page_html()
  local host = server_endpoint()
  local list = live_apps()
  local b = {[[<!doctype html><html><head><meta charset=utf-8><style>
body{margin:0;background:#fff;color:#242424;font-family:Charter,'Bitstream Charter',Georgia,'Noto Serif','Liberation Serif',serif}
#w{max-width:680px;margin:0 auto;padding:56px 24px 80px}.vm{font-family:sans-serif;font-size:12px;letter-spacing:3px;color:#b3b3b1;margin-bottom:34px}
h1{font-size:34px;font-weight:700;margin:0 0 6px}.sub{font-family:sans-serif;font-size:13px;color:#6b6b6b;margin:0 0 40px}
.e{font-size:22px;line-height:1.4;margin:0 0 6px}.e a{color:#242424;text-decoration:none}.d{font-family:sans-serif;font-size:14px;color:#6b6b6b;margin:0 0 22px}
.ft{font-family:sans-serif;font-size:12px;color:#9c9c9a;margin-top:56px;border-top:1px solid #ececeb;padding-top:14px}.ft a{color:#1a8917;text-decoration:none}
</style></head><body><div id=w><div class=vm>THIS SERVER</div><h1>Applications</h1><div class=sub>installed and running here</div>
]]}
  if #list == 0 then
    b[#b + 1] = "<div class=d>No applications are currently registered.</div>\n"
  else
    for _, app in ipairs(list) do
      local url = host and ("luarpc://%s:%d/"):format(host, app.rpc_port) or nil
      if url then
        b[#b + 1] = ("<p class=e><a href=\"%s\">%s</a></p><div class=d>%s</div>\n")
            :format(esc(url), esc(app.name), esc(app.description))
      else
        b[#b + 1] = ("<p class=e>%s</p><div class=d>%s</div>\n")
            :format(esc(app.name), esc(app.description))
      end
    end
  end
  b[#b + 1] = "<div class=ft>cwb application server</div></div></body></html>"
  return table.concat(b)
end

local function same_instance(source, rpc_port, pubkey)
  local info = ces.server_info and ces.server_info() or nil
  if type(info) ~= "table" then return false end
  local rpc = tonumber(info.rpc_port) or 0
  if rpc == 0 then return false end
  -- Validation is service-to-service traffic on this CES host. Using the
  -- advertised public name here incorrectly depends on NAT hairpinning.
  local cc = ces.compute_client("127.0.0.1:" .. rpc)
  if not cc then return false end
  local rows = cc:instances(source) or {}
  cc:close()
  for _, row in ipairs(rows) do
    if tonumber(row.rpc_port) == rpc_port and row.program_pubkey == pubkey then
      return true
    end
  end
  local function hx(s)
    return (tostring(s or ""):gsub(".", function(c)
      return string.format("%02x", string.byte(c))
    end))
  end
  ces.log(("cwb: registration mismatch source=%s port=%s caller=%s rows=%d")
      :format(source, tostring(rpc_port), hx(pubkey):sub(1, 16), #rows))
  for _, row in ipairs(rows) do
    ces.log(("cwb: candidate port=%s program=%s")
        :format(tostring(row.rpc_port), hx(row.program_pubkey):sub(1, 16)))
  end
  return false
end

local function register(line, pubkey)
  local name, source, description, port =
      line:match("^REGISTER|([^|]+)|([^|]+)|([^|]*)|(%d+)$")
  port = tonumber(port)
  if not name or #name > 64 or #description > 240 or not port or port < 1 or port > 65535 then
    return "ERR bad registration"
  end
  if source:sub(1, 3) ~= "/s/" then return "ERR source" end
  if not pubkey or #pubkey ~= 32 then return "ERR identity" end
  if not same_instance(source, port, pubkey) then return "ERR not live instance" end
  apps[name] = {name=name, source=source, description=description,
                rpc_port=port, program_pubkey=pubkey,
                expires=now_s() + LEASE_S}
  ces.log("cwb: registered " .. name .. " from " .. source)
  return "OK " .. tostring(LEASE_S)
end

ces.conn.set_listener({
  on_open = function(conn) conn.buf = "" end,
  on_data = function(conn, data)
    conn.buf = (conn.buf or "") .. data
    if #conn.buf > REQUEST_MAX then
      conn:write("ERR request too large\n"); conn:close(); return
    end
    if conn.buf:sub(1, 9) == "REGISTER|" then
      local line = conn.buf:match("^([^\n]*)\n")
      if line then
        local pubkey = conn.pubkey
        -- Native client calls yield. Connection callbacks are not coroutines,
        -- so validation must run in a behavior rather than inside on_data.
        ces.spawn(function()
          local reply = register(line, pubkey)
          pcall(function() conn:write(reply .. "\n"); conn:close() end)
        end)
      end
      return
    end
    if conn.buf:find("\r\n\r\n", 1, true) then
      local req = parse_request(conn.buf)
      if not req or req.method ~= "GET" then
        conn:write(http("<h1>Bad request</h1>", 400))
      elseif req.path == "/" or req.path == "/index.html" then
        conn:write(http(page_html()))
      else
        conn:write(http("<h1>Not found</h1>", 404))
      end
      conn:close()
    end
  end,
  on_close = function() end,
})

-- Remove artifacts produced by the superseded file-as-IPC implementation.
-- The directory is this running program; it never materializes an HTML cache.
pcall(function() ces.file_delete("/s/cwb/registry.log") end)
pcall(function() ces.file_delete("/s/cwb/index.html") end)
ces.log("cwb: live directory service ready (" .. SOURCE .. ")")
ces.run()
