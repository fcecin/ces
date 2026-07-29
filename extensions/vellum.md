# vellum — writing meant to be kept

The server half of Vellum, the first cwb application: typeset stories with
rent-paid permanence. The browser half is cwb's writing surface
(`x-cwb-write`, `cwb://write`); authors publish to their own `/h/` or `/f/`
zone and pay their own rent.

Source: cesdk `apps/vellum` (`bin/cesdk build` -> `dist/vellum.lua`). This file
is the built bundle; edit the cesdk source, not it.

## Enable

```toml
[extension]
cwb = 1      # the application directory (recommended, not required)
vellum = 1
```

## What it does

Vellum is a plain web server on a CesPlex RUDP channel (cesdk `lib/web`). Every
page and every action is an HTTP request over `ces.conn`; the caller's
bind-authenticated identity (`req.pubkey`) gates who may write.

- `GET /` — the feed of recently published stories. The pitch is shown once, to
  a nameless caller; a named citizen lands on the stories.
- `GET /by/<name>` — an author's shelf.
- `GET /write` — the editor, or, for a nameless caller, a page that hands off to
  the account UI to register a name (the name gate is at entry, not publish).
- `POST /publish` body `<path>|<title>` — list a story. The path is verified to
  exist and to be owned by the caller (`/f/<name>/` by key_name, `/h/<hex>/` by
  the key). The listed author is the verified owner, not a free-text claim.
- `POST /unlist` body `<path>` — the owner drops a story from the feed; the file
  is untouched (unlist is not unpublish; re-announcing re-lists it).
- `POST /listed` body `<path>` — is the story in the feed now.

State (the feed and per-author shelves) is Vellum's own, held in memory and
backed by one rent-exempt kv-file, `/s/vellum.kv` — no loose state files. The
file store is the truth for every view: a record whose story file no longer
exists is pruned at render, so a dead story leaves no index to maintain or lose.

Registration with the cwb directory is a fire-and-forget dial: on boot and every
5 minutes Vellum finds the live `/s/cwb.lua` instance in the compute catalog,
dials its rpc port, and renews an in-memory lease. Silence delists it.

## Economics

Everything this extension writes lives in `/s/` (operator-donated, unmetered).
Story pages themselves are the authors' files in `/h/` or `/f/`, paying the
authors' rent; the feed only points at them, and a starved story that dies
simply disappears from the feed.
