# cwb — the cwb application server

The server side of the cwb browser: maintains this server's cwb entry point at
`/s/cwb/index.html`, the directory of installed cwb applications. A cwb
browser given a bare host lands there first, falling back to the plain
`/s/index.html` catalog on servers without this extension.

## Enable

```toml
[extension]
cwb = 1
```

Requires the compute feature (and `builtin:file`), like every extension.

## How applications register

Through the file store, not a wire protocol. The trust check is the `/s/` zone
rule itself: only a server-authorized (`/s/`-sourced) program can append to
`/s/cwb/registry.log`, so every line in it was written by something the
operator installed. An application announces itself by appending

```
R|<unix-seconds>|<name>|<entry-path>|<description>
```

at boot and every few minutes. This extension polls the log (15 s), keeps the
freshest line per name, drops entries not re-announced within 30 min (a dead
application delists itself), regenerates the entry page when the set changes,
and compacts the log when it grows. Ordering-free: applications may boot
before or after this one, and any of them may seed the log.

User programs on `/h/` or `/f/` cannot write the log; they are reachable
directly but are not server-authorized applications, so they are not listed.

See `extensions/vellum.lua` for the reference registrant.
