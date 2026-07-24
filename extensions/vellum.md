# vellum — writing meant to be kept

The server half of Vellum, the first cwb application: typeset stories with
rent-paid permanence. The browser half is cwb's writing surface
(`x-cwb-write`, `cwb://write`); authors publish to their own `/h/` zone and
pay their own rent. This extension gives the server a Vellum front page and a
feed of recently published stories.

## Enable

```toml
[extension]
cwb = 1      # the application directory (recommended, not required)
vellum = 1
```

## What it does

- Maintains `/s/vellum/index.html`: the wordmark, the invitation to write
  (a `cwb://write` link), and the feed.
- Registers with the cwb application server by appending its heartbeat to
  `/s/cwb/registry.log` (see `extensions/cwb.md`); silence delists it.
- Accepts publish announcements on `ces.conn` (the browser's write surface
  dials the relay after a successful publish):

  ```
  published|<file-path>|<title>|<author>\n
  ```

  One line in, one ack out, close. The path is VERIFIED to exist in this
  server's file store, under `/h/`, before it is listed: the announcement is
  a hint, the file store is the truth. A lying announcement can at worst list
  a real page. Stories persist in `/s/vellum/stories.log`, so the feed
  survives restarts; the newest 30 are shown, deduped by path.

## Economics

Everything this extension writes lives in `/s/` (operator-donated,
unmetered). Story pages themselves are the authors' files in `/h/`, paying
the authors' rent; the feed only points at them, and a starved story that
dies simply 404s from the feed until its line ages out.
