-- /s/dice.lua — fair-coin double-or-nothing.
--
-- Deployed automatically when [builtin_app] dice = 1 is set on the
-- server. The house bankroll is the file's dedicated program account
-- (see HOUSE_PUBKEY below): bets are transferred into it and winnings
-- are paid out of it. On /s/ the server auto-tops that account at boot;
-- a non-/s/ deployer funds it with `cesh file deposit`.
--
-- Game (MVP):
--   1. User dials /s/dice.lua via cesh dial.
--   2. Program greets, prints the house pubkey + bet protocol.
--   3. User does an out-of-band CES_TRANSFER of N credits to the
--      house pubkey (e.g. `cesh transfer N <house-pubkey>`).
--   4. User types `play` in the dial.
--   5. Program reads the user's account, verifies
--      lastXferDest == house prefix and
--      lastXferTime is fresh (not already consumed for this user).
--      The bet amount is lastXferAmount — no need to re-type it.
--   6. Program flips a fair coin via ces.random_bytes(1).
--      Heads → ces.transfer(user, 2 * bet) and the user nets +bet.
--      Tails → nothing; the house keeps the deposit.
--   7. Program records lastXferTime as consumed for this user so
--      the same deposit can't be replayed in another round.
--
-- Net: 50/50, 0 house edge.

-- The "house" is the file's dedicated program account — the pool that
-- ces.transfer pays winnings from — so deposits (bets) and payouts
-- share one balance. (ces.owner_pubkey() is the owner's wallet, which
-- ces.transfer does not draw from, so bets sent there would never fund
-- payouts.) On /s/ the server auto-tops this account at boot; other
-- deployers fund it via `cesh file deposit`.
local HOUSE_PUBKEY = ces.program_pubkey()
local HOUSE_PREFIX = HOUSE_PUBKEY:sub(1, 8)

-- This program-instance was born at start_time (microseconds since
-- epoch). Any payment whose lastXferTime is ≤ START_S (seconds)
-- predates THIS instance and so cannot have been a fresh deposit
-- aimed at it. Replay-protection floor.
local START_S = math.floor(ces.start_time() / 1000000)

-- Replay-protection bucket. Maps user_pubkey (32 bytes raw) to the
-- last_xfer_time (decimal string, ≤ 10 chars) of the deposit we
-- already played for that user. Bucket TTL = BUCKET_TTL_S; entries
-- older than that may have been aged out, so any deposit older than
-- (now - BUCKET_TTL_S + GRACE_S) is rejected as too-old-to-track.
--
-- Capacity is declared up-front: max_entries × max_entry_bytes is
-- the standing footprint the host bills against (feeBucketByteSec).
-- 32 (key) + ~10 (value) + slack ⇒ 64 bytes per entry; 100k entries
-- ⇒ ~6.4 MB committed. /s/ files are unmetered so the bill is a
-- no-op for the bottomless server account.
local BUCKET_TTL_S    = 7200      -- 2 hours of guaranteed retention
local BUCKET_MAX_E    = 100000    -- up to 100k unique players
local BUCKET_MAX_B    = 64        -- bytes per entry (key + value)
local GRACE_S         = 60        -- safety margin on the bucket horizon
local consumed = ces.bucket_new(BUCKET_TTL_S, BUCKET_MAX_E, BUCKET_MAX_B)
if not consumed then
  error("/s/dice.lua: failed to allocate bucket cache")
end

-- MIN_BET keeps "0-credit transfers" from being interpreted as a
-- bet. There is deliberately NO upper cap: the user already paid
-- the transfer fee and moved real credits to the house when they
-- did the deposit, so rejecting "too large" bets just burns their
-- money for no reason — the transfer happened either way. The
-- transfer layer's "you can't transfer more than you have"
-- already bounds the realistic upper end.
local MIN_BET = 1

local function hex(s)
  local out = {}
  for i = 1, #s do
    out[i] = string.format("%02x", string.byte(s, i))
  end
  return table.concat(out)
end

local function trim(s)
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function flip()
  local b = ces.random_bytes(1)
  return (string.byte(b, 1) % 2) == 0
end

local function send_line(conn, msg)
  conn:write(msg .. "\n")
end

local function send_help(conn)
  send_line(conn, "commands:")
  send_line(conn, "  play       play your deposited bet")
  send_line(conn, "  balance    credits deposited & available to play")
  send_line(conn, "  self       your pubkey + CES account balance")
  send_line(conn, "  help       this message")
  send_line(conn, "  quit       close the connection")
end

local function send_greeting(conn)
  send_line(conn, "")
  send_line(conn, "  /s/dice — fair-coin double-or-nothing")
  send_line(conn, "")
  send_line(conn, "  house pubkey: " .. hex(HOUSE_PUBKEY))
  send_line(conn, "")
  send_line(conn,
    "  to bet: transfer N credits to the house pubkey (e.g.")
  send_line(conn,
    "  `cesh transfer N <house-pubkey>`), then type `play` here.")
  send_line(conn,
    "  heads pays 2N, tails pays 0. each transfer is one bet.")
  send_line(conn, "")
  send_help(conn)
  send_line(conn, "")
end

-- The credits this user has DEPOSITED on the contract and that are PLAYABLE
-- right now — a fresh, unconsumed transfer to the house. Returns
-- (amount, reason, xferTime): amount > 0 + xferTime when there's a bet ready;
-- (0, why, nil) otherwise. This is the contract's notion of "your balance"
-- (chips on the table), NOT your CES account balance. `balance` reports it;
-- `play` spends it. Shared so the two can never disagree.
local function pending_bet(conn)
  local acc, err = ces.account_read(conn.pubkey)
  if not acc then return 0, "account read failed: " .. tostring(err), nil end

  if acc.last_xfer_dest ~= HOUSE_PREFIX then
    return 0, "nothing deposited. transfer credits to the house, then `play`.", nil
  end
  local n = acc.last_xfer_amount
  if n < MIN_BET then
    return 0, "your deposit of " .. tostring(n) ..
              " is below the minimum bet of " .. MIN_BET .. ".", nil
  end
  if acc.last_xfer_time <= START_S then
    return 0, "your deposit predates this dice instance; send a fresh transfer.", nil
  end
  -- Anything older than the bucket's guaranteed-retention window may have aged
  -- out of `consumed`, so we can't tell if it was already played. Reject.
  local now_s = math.floor(ces.now() / 1000000)
  if acc.last_xfer_time < (now_s - BUCKET_TTL_S + GRACE_S) then
    return 0, "your deposit is too old to verify (over " ..
              tostring(BUCKET_TTL_S) .. "s); send a fresh transfer.", nil
  end
  local prior_str = consumed:get(conn.pubkey)
  if prior_str then
    local prior_t = tonumber(prior_str)
    if prior_t and acc.last_xfer_time <= prior_t then
      return 0, "that deposit was already played. transfer again to bet again.", nil
    end
  end
  return n, nil, acc.last_xfer_time
end

local function handle_play(conn)
  local n, why, xfer_time = pending_bet(conn)
  if n == 0 then send_line(conn, why); return end

  -- Consume FIRST so a quick double-tap can't double-spend the same transfer.
  consumed:put(conn.pubkey, tostring(xfer_time))

  if flip() then
    local payout = n * 2
    local ok, terr = ces.transfer(conn.pubkey, payout)
    if not ok then
      send_line(conn,
        "won " .. payout .. " but payout failed: " .. tostring(terr))
      return
    end
    send_line(conn, "heads. you won " .. payout .. " (+" .. n .. ", paid to your account)")
  else
    send_line(conn, "tails. house keeps " .. n)
  end
end

local function handle_line(conn, line)
  if line == "" then return end

  if line == "quit" or line == "exit" then
    send_line(conn, "bye")
    conn:close()
    return
  end

  if line == "help" or line == "?" then
    send_help(conn)
    return
  end

  if line == "balance" then
    -- The CONTRACT balance: credits deposited and available to play (0 once
    -- played — winnings go to your CES account, not back onto the table).
    local n = pending_bet(conn)
    send_line(conn, "available to play: " .. n)
    return
  end

  if line == "self" or line == "whoami" then
    -- Your identity + your CES ACCOUNT balance (where winnings land) — distinct
    -- from "available to play" (the bet you've deposited onto the table).
    send_line(conn, "you: " .. hex(conn.pubkey))
    local acc, err = ces.account_read(conn.pubkey)
    if acc then
      send_line(conn, "account balance: " .. acc.balance)
    else
      send_line(conn, "account balance: read failed (" .. tostring(err) .. ")")
    end
    return
  end

  if line == "play" then
    handle_play(conn)
    return
  end

  send_line(conn, "unknown command. type `help`.")
end

local function on_open(conn)
  conn.buf = ""
  send_greeting(conn)
end

local function on_data(conn, data)
  conn.buf = (conn.buf or "") .. data
  while true do
    local nl = conn.buf:find("\n", 1, true)
    if not nl then break end
    local line = trim(conn.buf:sub(1, nl - 1))
    conn.buf = conn.buf:sub(nl + 1)
    handle_line(conn, line)
  end
end

local function on_close(conn)
  -- consumed bucket survives close on purpose: a user can disconnect
  -- and reconnect, their last-played transfer time still counts
  -- until the bucket ages it out (BUCKET_TTL_S).
end

ces.conn.set_listener({
  on_open  = on_open,
  on_data  = on_data,
  on_close = on_close,
})

ces.conn.run()
