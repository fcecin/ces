# CES Extensions

An extension is a `/s/` Lua program managed through a lifecycle surface: install
from a read-only catalog into `/s/`, enable (launch), configure, command, read
status, disable, uninstall. The mechanism is the privileged L2 compute already in
CES; "extension" adds a management contract on top. Not a new runtime type: the
Compute page still shows every instance raw; the Extensions page is the `/s/`
lifecycle lens. A plain compute program (dice) appears as an extension that
implements none of the contract, so its management cells read N/A.

## Progress

Legend: [ ] todo  [~] in progress  [x] done

- [x] P1  ces.extension_admin Lua contract + host<->program IPC seam
        (cesluajitd register/dispatch + disable_self; compute_handler IPC tags +
        REGISTER store, EXT_REQ/REP correlation, EXT_CONFIG push, DISABLE_SELF;
        public computeHandlerExtInfo/ExtRequest/ExtConfig). Builds clean.
- [x] P2  ExtensionManager (C++): catalog scan, install/uninstall, enable/disable,
        config read/write/reset, status/command/config relay. extensions_dir
        config knob; computeHandlerKillBySource. Builds clean.
- [x] P3  webadmin Extensions page + endpoints. Tab + per-extension cards
        (badge, lifecycle buttons, status k/v poll, command buttons, config
        editor + reset). GET/POST endpoints to the manager.
- [x] P4  Manifest = a static `CES_MANIFEST = { name, version, description }`
        global table (NOT a function call — it's data). Single human source is
        `project.lua`; the cesdk bundler GENERATES the table into the built `.lua`
        (a hand-written /s/ program like dice declares it directly). Read two
        ways, NO source-text parsing either way:
          - running: cesluajitd reads CES_MANIFEST at run-loop entry and reports
            it (EXT_MANIFEST frame -> instance -> computeHandlerExtInfo).
          - not running: `cesluajitd --manifest <file>` loadfile-evaluates the
            table in a no-op sandbox (stub `ces`, instruction budget) and prints
            it; the server runs that probe, mtime-cached, for AVAILABLE/INSTALLED
            rows (extension_manager::probeManifest).
        So pre-launch metadata works without scraping and without running the
        service. Separate from the contract: CES_MANIFEST = identity,
        ces.extension_admin = caps/commands/config; dice has a manifest, no
        contract. Verified end-to-end (running + not-running + dice + hello).
- [ ] P5  wire discovery as the reference extension (deferred). The contract
        demos `sample` (full contract) + `probe` (status only) now live in cesdk
        under `examples/`; in-tree, `dice.lua` is the oblivious -> N/A case.
- [x] P6  END-TO-END VERIFIED via the live node + dashboard: install/enable/
        disable/uninstall, live status poll, command (ping->pong), config reset
        pushes on_config live (greeting unset->hello). dice renders N/A.

- [x] startup config push: on REGISTER, if the extension declares on_config, the
      host reads /s/<name>.conf and pushes it, so live state matches the file from
      the first tick (verified: re-enable shows persisted config at ticks=1).
- [x] webadmin: an open config editor no longer freezes the status poll for the
      tab; only the row rebuild is suppressed while editing.

Open follow-ups:
- P5: wire discovery as the reference extension (the actual goal the extension
  surface was built to unblock).

Notes / decisions log:
- Catalog lives at repo-root `extensions/` (was `src/ceslib/extensions/`).
- No uninstall hook (decision B). No per-extension metadata files (decision A).
- Config edits are always hot and pushed live (decision C, below).
- `[extension]` TOML stays the boot enabled-set; the dashboard is dynamic until
  Config -> Export Config snapshots it (decision E).
- New IPC tags 0x0d..0x11 (REGISTER/REQ/REP/CONFIG/DISABLE_SELF). Found a latent
  pre-existing bug while picking tags: TAG_HOST_LOG and TAG_NET_USAGE are BOTH
  0x0c, so net-usage frames are mis-dispatched as host logs. Not touched here;
  flagged for a separate fix.

## The contract

`ces.extension_admin{...}` registers the admin contract — and ONLY the contract.
It carries NO metadata: name/version/description live in the `CES_MANIFEST`
global table (see A). Registered once at the top of the program:

```lua
ces.extension_admin{
  status   = function() return { registry="100", alive="80", state="converged" } end,
  commands = { {id="dump", label="Dump registry"},
               {id="wipe", label="Wipe + turn off"} },
  on_command = function(id, arg)
    if id == "dump" then return reg:dump()
    elseif id == "wipe" then ces.file_delete("/s/discovery.reg"); ces.extension_admin.disable_self() end
  end,

  config_defaults = "crawl_ms = 3000\nseeds = ces.pubcom.org:53830\n",  -- string or fn
  on_config       = function(cfg) apply(cfg) end,   -- cfg = string->string table
}
```

The host invokes these callbacks over IPC only for a running `/s/` extension. A
program that never calls `ces.extension_admin{}` (dice) is a `/s/` program with no
contract: every management cell renders N/A. Unimplemented fields render N/A
individually. (Metadata is orthogonal: a program with no contract can still set
`CES_MANIFEST` to report name/version/description — that's exactly dice.)

Fields:
- `status` fn -> map of string->string. Polled for display.
- `commands` list of `{id, label}`: buttons the page renders.
- `on_command(id, arg)` -> string|nil: handle a button or freeform command.
- `config_defaults` string|fn -> string: source for the Reset button.
- `on_config(cfg)`: live config delivery (see C).

New native: `ces.extension_admin.disable_self()` — the program turns itself off
(the program-initiated Disable; the `/s/` file stays).

## A — metadata, one human source, static table

Metadata (name/version/description) is written by a human in exactly one place,
as a static `CES_MANIFEST` global TABLE — data, not behavior:
- cesdk extension: the human writes it once in `project.lua`; the **bundler
  generates** `CES_MANIFEST = {...}` into the built `.lua`. Code never re-types it.
- hand-written, un-bundled `/s/` file (dice): the program assigns
  `CES_MANIFEST = {...}` directly.

Because it's a static table (not a function call), it's read two ways, NEITHER of
which scrapes source text:
- **running**: cesluajitd reads the `CES_MANIFEST` global at run-loop entry and
  reports it to the host (EXT_MANIFEST frame -> instance -> computeHandlerExtInfo).
- **not running**: `cesluajitd --manifest <file>` `loadfile`-evaluates the file in
  a no-op sandbox (a stub `ces` whose every index/call yields itself, plus an
  instruction budget) and reads the table — the program's real logic never runs.
  The server runs that probe (mtime-cached) for AVAILABLE/INSTALLED rows.

So pre-launch metadata works WITHOUT scraping and WITHOUT running the service —
the same single table feeds both paths. (Why a table and not a `ces.manifest()`
call: static data is `loadfile`-harvestable; a call would force a runtime.)

Two distinct names, don't conflate them: the **file slug** (the `.lua` filename
= the `/s/<slug>.lua` path = the server's identity for every op; in cesdk it's
`project.lua`'s `name`) and the manifest **display name** (`CES_MANIFEST.name`; in
cesdk it's `project.lua`'s `title`, a free string, defaulting to `name`). They
may differ — the dashboard shows the display name, then version, then the slug
grayed in parens (`Full-Contract Sample v1.0 (sample.lua)`).

Metadata and the runtime contract are independent axes: dice sets `CES_MANIFEST`
but calls no `ces.extension_admin`, so it shows version/description but N/A
status/commands/config.

## C — config

Config is a `string->string` map, persisted as `/s/<name>.conf` and always hot.
On a dashboard save: write the file AND push the parsed table to the running
extension via `on_config(cfg)`. The extension applies it however it likes
(bind to live variables now, or stash and apply on its own trigger). No
generation counter; the event is the signal. No forced restart. If `on_config`
is absent, the edit still persists and applies on next launch. `on_config` also
fires once right after launch with the current file contents, so startup and
live-edit are one path. Reset to defaults = write `config_defaults` -> file ->
push `on_config`.

## B — uninstall, no hook

Lifecycle Uninstall = delete `/s/<name>.lua`, nothing else. Ancillary files
(`/s/<name>.conf`, `/s/discovery.reg`, ...) stay. Cleanup is the extension's job,
done while live via its own command: a `wipe` command deletes the files it knows,
then calls `ces.extension_admin.disable_self()`. Not a lifecycle button.

## D — catalog

A read-only, committed directory of single-file extensions, at repo-root
`extensions/`. Runtime path configurable (`extensions_dir`; default the shipped
`extensions/`). Install = copy `<name>.lua` -> `/s/<name>.lua` (the existing `/s/`
reconcile then stamps the sidecar and mints the program account). Uninstall =
delete the `/s/` copy; the catalog copy persists for one-click re-install.

## E — enabled-set

`[extension]` in the TOML is the boot enabled-set, read on startup, untouched by
the dashboard. The page's Enable/Disable is dynamic only. To persist, the operator
uses Config -> Export Config to snapshot the running config (including currently-
enabled extensions). Live state vs exported boot config stay separate.

## C++ architecture

`ExtensionManager` (server) orchestrates three subsystems it does not own:
- file handler: copy catalog->`/s/`, delete, read/write `/s/<name>.conf`.
- compute handler: launch / kill.
- host->program IPC: `status`, `command(id,arg)`, `config(cfg)` requests to the
  child, each dispatched to the matching `ces.extension_admin` callback and answered;
  `disable_self()` flows program->host.

The cesluajitd IPC loop already pumps frames (conn data, api replies); the seam
adds these request/reply tags and a dispatch into the registered callbacks.

## Webadmin Extensions page

Layout decided: **table-like rows, each expanding inline into a control center.**
Collapsed, a row is one thin line (chevron, name, version, badge, pid, lifecycle
buttons) with a separator -- the whole list reads as a table. Click a row to
expand it (as tall as it needs) into status / commands / config; click again to
collapse. Expansion is per-row and remembered across refreshes. Status refreshes
every 3s but ONLY for expanded rows while the tab is open (a collapsed or unseen
row is never polled). The row list rebuilds only on a real state change, so the
steady-state status tick never flickers a row or loses an open editor. The
number of installed extensions is bounded, so this stays cheap.

Per row: name/version/description (catalog header or live manifest), a state badge
(Available / Installed / Enabled), the status k/v table (or N/A), command buttons
(or none), a config editor with Save + Reset-to-defaults, and lifecycle buttons
(Install / Enable / Disable / Uninstall). Status polls every few seconds; every
action hits an ExtensionManager endpoint and re-renders. Distinct from the
Compute page, which stays the raw all-instances view.
