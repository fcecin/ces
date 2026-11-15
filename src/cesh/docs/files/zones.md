---
title: Zones
summary: The path zones /h/ /f/ /p/ /s/ /m/, who can create files in each, and why paths are capabilities
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
| `/m/<64-hex-pubkey>/...` | Only that key. Private: nobody reads it over the network, the owner included. The server reads it for that key's mail attachments and `think` conversations |

- With `cesh file put`, a bare name such as `notes.txt` becomes
  `/h/<signer>/notes.txt`.
- Anyone can read a file in `/h/`, `/f/`, `/p/` or `/s/`, if they know its
  path. Only `/s/` has a list. For the other zones the path is the
  capability: a path that nobody knows is a file that nobody finds.
- The owner is set when the file is made, and does not change.
