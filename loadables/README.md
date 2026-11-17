# Loadables

A loadable is a Lua file under `/s/loadables/` on a server. A program runs it with `ces.load`, which returns what the file returns, and a second call with the same path returns the same value.

```lua
local vs1 = ces.load("vs1/vs1.lua")
```

| Path | |
| --- | --- |
| `vs1/vs1.lua` | VS1, screens of character cells for programs that people dial. The docs are at the top of the file. |

## Deploy

Copy them into the file store by hand.

```bash
mkdir -p <file_store_dir>/s/loadables
cp -r loadables/vs1 <file_store_dir>/s/loadables/
```

`file_store_dir` defaults to `<data_dir>/cesfilestore`. A loadable is a normal `/s/` file, so it is kept for free, anyone can read it, and `cesh file put` with the server key also works. A running program keeps the version it loaded until it is launched again.

## Paths

A path is relative to `/s/loadables/`. It is parts joined by `/`, each made of letters, digits, `.`, `-` and `_` and starting with a letter, a digit, `-` or `_`, up to 200 characters in all.

## ces.load

- It waits for the server, also in a task, so load at the top of the program.
- The file is Lua text of at most 1 MiB.
- Errors in the file start with its path, for example `vs1/vs1.lua:12:`.
- A missing file, a compile error or a runtime error raises an error in the program, and the next call tries again.
- A file that loads itself, also through another file, raises an error.
