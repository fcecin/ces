---
title: Zones
summary: The four path zones /h/ /f/ /p/ /s/, who can create files in each, and why paths are capabilities
order: 1
---

Each file path starts with a zone. A path in no zone fails with
`CES_ERROR_BAD_NAME`.

| Zone | Who can create a file there |
| --- | --- |
| `/h/<64-hex-pubkey>/...` | Only that key: it is the home of the key |
| `/f/<name>/...` | Only the key that owns the key name `<name>` (see [Key names](../names/keynames.md)) |
| `/p/...` | Anyone, first come first served on the exact path |
| `/s/...` | Only the server itself (files of the operator) |

- With `cesh file put`, a bare name such as `notes.txt` becomes
  `/h/<signer>/notes.txt`.
- Anyone can read a file, if they know its path. Only `/s/` has a list.
  For all other zones the path is the capability: a path that nobody knows
  is a file that nobody finds.
- The owner is set when the file is made, and does not change.
