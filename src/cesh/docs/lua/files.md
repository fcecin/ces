---
title: Files
summary: ces.file_* on this server: make, read, write and pay files as the program's owner, with a guest book example
order: 5
---

The `ces.file_*` calls work on files of the server that runs the program.
The program acts as the owner of its source file: it makes, reads and
writes files as that key, in the zones where that key can make files (see
[Zones](../files/zones.md)). The program's balance pays every fee and
every deposit.

- A path is a full path, such as `/h/<owner hex>/notes.txt`. A bare name
  fails with `CES_ERROR_BAD_NAME`.
- A file has a size of 1 byte or more, and it has its own balance, which
  pays its rent (see [Rent](../files/rent.md)).
- One call reads or writes at most 1 MB (1048576 bytes).

| Call | Returns |
| --- | --- |
| `ces.file_create(path, size, price_per_kb, deposit)` | `true, file_balance`. A new file of `size` zero bytes, with `deposit` raw in its balance |
| `ces.file_write(path, offset, data)` | `true, file_balance` |
| `ces.file_append(path, data)` | `true, file_balance, new_size`. The data goes after the last byte |
| `ces.file_read(path, offset, length)` | The bytes |
| `ces.file_stat(path)` | A table: `size`, `file_balance`, `price_per_kb`, `owner_pubkey`, `created_us`, `modified_us` |
| `ces.file_resize(path, size)` | `true, file_balance, new_size` |
| `ces.file_deposit(path, raw)` | `true, file_balance`. Anyone can pay into any file |
| `ces.file_withdraw(path, raw)` | `true, file_balance`. The credits go back to the program |
| `ces.file_set_price(path, price_per_kb)` | `true, new_price`. What a reader pays per KB |
| `ces.file_delete(path)` | `true, refunded`. The rest of the balance goes back to the program |

Each call returns `nil, code` when it fails, for example
`ces.err.FILE_NOT_FOUND` or `ces.err.NOT_OWNER`.

## A guest book

```lua
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
local book = "/h/" .. hex(ces.owner_pubkey()) .. "/guestbook.txt"

local function sign(name)
  local line = name .. "\n"
  if not ces.file_stat(book) then
    -- A file has at least 1 byte, so make it the size of the first line.
    local ok, err = ces.file_create(book, #line, 0, 100000000)  -- 1 credit
    if not ok then return nil, err end
    return ces.file_write(book, 0, line)
  end
  return ces.file_append(book, line)
end

function on_l2call(memo)
  if memo == "read" then
    local st = ces.file_stat(book)
    if not st then return "nobody signed yet" end
    return ces.file_read(book, 0, st.size)
  end
  local ok, err = sign(memo)
  if not ok then return "could not sign: error " .. err end
  return "signed"
end

ces.run()
```

The owner reads the same file with `cesh file get guestbook.txt -`.

- A file made with a size of 1 and then appended starts with a zero byte.
  Make the file the size of its first data, and write that data.
- Keep the file balance above the rent, with `ces.file_deposit`, or the
  server deletes the file.
- For many small records, the [key-value store](store.md) is simpler.
- For files on another server, use `ces.file_client` (see
  [Other servers](servers.md)). It acts as the program's own key, not as
  the owner.
