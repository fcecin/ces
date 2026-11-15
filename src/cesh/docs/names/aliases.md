---
title: Aliases
summary: An alias is a 1 KB memory cell bound to an account, with an owner and one editor
order: 2
---

An alias is a cell of 1024 bytes that belongs to an account. The server gives
it a number. The owner pays its rent. The owner can grant one editor, who can
change the content.

| Command | What it does |
| --- | --- |
| `cesh alias write ...` | Write bytes into the alias (signed) |
| `cesh alias read ...` | Read a range of bytes (free) |
| `cesh alias rm` | Delete the alias of this account |
| `cesh alias run ...` | Run the program in an alias |

Use `cesh man alias write` (and the others) for the arguments.
