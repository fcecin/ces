-- /s/dice2.lua - fair-coin double-or-nothing, paid via SYS_L2_CALL.
--
-- The SYS_L2_CALL flavor of /s/dice.lua. dice.lua takes the bet as an
-- out-of-band CES_TRANSFER and reads the last-transfer receipt; dice2 takes the
-- bet as the value of a SYS_L2_CALL. A caller runs a VM program that fires
-- SYS_L2_CALL at this instance's pid with value = bet. on_l2call enqueues the
-- bet; a serialized worker flips a fair coin and, on heads, pays 2x back to
-- the caller. Overkill for a coin flip on purpose: it exercises SYS_L2_CALL
-- as the payment path end to end.
--
--   value : the bet. Settlement is reply-time: the host mints it into the
--           house (this file's program account) only AFTER on_l2call returns,
--           so during the handler the house balance does NOT include it.
--   payer : the better's account (full key), delivered by the call.
--   heads pays 2*bet to ctx.payer; tails, the house keeps the bet.
--
-- Net: 50/50, 0 house edge. Because the bet is not yet in the account during
-- the handler, the house needs standing funds >= 2x the largest bet (not just
-- the 1x delta); on /s/ the server auto-tops the program account at boot.

CES_MANIFEST = { name = "Double-or-Nothing Dice (L2)", version = "1.0",
                 description = "Fair-coin double-or-nothing paid via SYS_L2_CALL." }

local HOUSE   = ces.program_pubkey()
local MIN_BET = 1

local stats = { plays = 0, heads = 0, tails = 0, wagered = 0, paid = 0, recent = {} }
local RECENT_MAX = 30

local function hex(s)
  local out = {}
  for i = 1, #s do out[i] = string.format("%02x", string.byte(s, i)) end
  return table.concat(out)
end

local function flip()
  return (string.byte(ces.random_bytes(1), 1) % 2) == 0
end

local function note(line)
  local r = stats.recent
  r[#r + 1] = line
  while #r > RECENT_MAX do table.remove(r, 1) end
end

-- Paid call: value = bet, payer = caller key. The handler only enqueues; a
-- single worker coroutine plays bets one at a time, so the bankroll check and
-- the payout are atomic per bet (account_read/transfer yield, and concurrent
-- on_l2call coroutines would otherwise interleave across those yields and
-- double-spend the bankroll).
local bets = ces.chan()

function on_l2call(payload, ctx)
  bets:send({ payer = ctx.payer, bet = ctx.value })
end

local function play(payer, bet)
  if bet < MIN_BET then return end

  local payout = bet * 2
  -- The bet mints into the house only after its on_l2call returned, and may or
  -- may not have settled by now; the check spends standing bankroll only, so
  -- the house needs standing funds >= 2x the largest bet either way.
  local house = ces.account_read(HOUSE)
  if not house or house.balance < payout then return end  -- house must cover 2x

  stats.plays = stats.plays + 1
  stats.wagered = stats.wagered + bet
  local who = hex(payer):sub(1, 12)
  if flip() then
    if ces.transfer(payer, payout) then
      stats.heads = stats.heads + 1
      stats.paid = stats.paid + payout
      note(who .. " bet " .. bet .. " -> heads, paid " .. payout)
    else
      note(who .. " bet " .. bet .. " -> heads, PAYOUT FAILED")
    end
  else
    stats.tails = stats.tails + 1
    note(who .. " bet " .. bet .. " -> tails, house keeps " .. bet)
  end
end

ces.spawn(function()
  while true do
    local b, err = bets:recv(60000)
    if err == "closed" then return end
    if b then play(b.payer, b.bet) end
  end
end)

if ces.extension_admin and mene then
  local panel = mene.app{
    model = stats,
    view = function(m)
      local house = ces.account_read(HOUSE)
      return mene.card({ title = "Dice house (L2)", subtitle = "paid via SYS_L2_CALL" },
        mene.grid({ cols = 4, gap = 12 },
          mene.stat({ label = "house balance",
                      value = house and house.balance or "?",
                      tone = (house and house.balance or 0) > 0 and "ok" or "err" }),
          mene.stat({ label = "plays", value = m.plays }),
          mene.stat({ label = "wagered", value = m.wagered }),
          mene.stat({ label = "paid out", value = m.paid })),
        mene.breakdown({ label = "outcomes (fairness monitor)", parts = {
          { "heads (player wins)", m.heads, "ok" },
          { "tails (house keeps)", m.tails, "info" },
        } }),
        mene.row({ align = "between" },
          mene.stack({ gap = 4 },
            mene.text({ tone = "muted" }, "house pubkey"),
            mene.text({ copy = true, tone = "code" }, hex(HOUSE))),
          mene.button({ on = "reset", kind = "danger",
                        confirm = "Reset the play counters?" }, "Reset counters")),
        #m.recent > 0 and mene.section({ title = "recent plays" },
          mene.log({ lines = m.recent, height = 160, follow = true })) or nil)
    end,
    update = function(ev, m)
      if ev.on == "reset" then
        m.plays, m.heads, m.tails, m.wagered, m.paid = 0, 0, 0, 0, 0
        m.recent = {}
      end
      return m
    end,
  }
  ces.extension_admin{
    status = function()
      return { plays = tostring(stats.plays), heads = tostring(stats.heads),
               tails = tostring(stats.tails), wagered = tostring(stats.wagered),
               paid = tostring(stats.paid) }
    end,
    panel = panel,
  }
end

ces.run()
