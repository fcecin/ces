---
title: Key names
summary: Register a name for your key, resolve a name to a key, and the /f/<name>/ file zone
order: 1
---

A key name is a name of up to 32 bytes that a key gives to itself. Each name
belongs to one key, and each key has at most one name.

| Command | What it does | Cost |
| --- | --- | --- |
| `cesh keyname register <name>` | Give the actor key that name | Signed, paid |
| `cesh keyname clear` | Remove the actor key's name | Signed |
| `cesh keyname query <key>` | The name of a key | Free |
| `cesh keyname resolve <name>` | The key of a name | Free |

- Spaces and underscores are the same: "Ada Lovelace" and "Ada_Lovelace"
  are one name.
- The key's account pays a daily rent for the name. If the account cannot
  pay, the name is free again.
- The owner of a name owns the file zone `/f/<name>/`.
- A name taken by another key gives `CES_ERROR_KEYNAME_TAKEN`.
