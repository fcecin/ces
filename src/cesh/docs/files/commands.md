---
title: File commands
summary: Exact syntax of cesh file put, get, stat, deposit, withdraw, set-price and rm
order: 3
---

The file commands use the server's rpc port (see [Servers](../basics/servers.md)).

| Command | What it does | Who |
| --- | --- | --- |
| `cesh file put <local> <remote> [--deposit RAW]` | Upload a local file; `-` reads stdin. On an existing file, `--deposit` is added as a top-up | Owner |
| `cesh file get <remote> [<local>]` | Download; no `<local>` or `-` writes to stdout | Anyone |
| `cesh file stat <remote>` | Owner, size, balance, price, times | Anyone |
| `cesh file deposit <remote> <raw>` | Add credits to the file balance | Anyone |
| `cesh file withdraw <remote> <raw>` | Take credits from the file balance | Owner |
| `cesh file set-price <remote> <raw-per-kb>` | Set the read price | Owner |
| `cesh file rm <remote>` | Delete the file | Owner |

`<remote>` is a path on the server: a full path (`/h/...`, `/f/...`,
`/p/...`) or a bare name, which means `/h/<signer>/<name>`.

`<local>` is a path on your own disk, relative to the directory where you
run cesh. `file put` reads it and `file get` writes it. `file stat` and the
other commands look only at the server: they cannot check a local file, and
you do not need to check it first.

`file put -` reads the content from stdin, which must be a pipe or a file,
not a terminal. A shell can give the content in place:

```
cesh file put - hello.lua <<END
function on_l2call(memo, info)
  return "hello " .. memo
end
ces.run()
END
```

## Example

Keep a note for a month, with 10 credits in its balance:

```
cesh file put note.txt note.txt --deposit 1000000000
cesh file stat note.txt
```
