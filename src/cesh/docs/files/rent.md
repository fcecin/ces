---
title: Rent and the file balance
summary: How a file pays rent from its own balance, the 15-minute upfront rent, and deletion when the balance is gone
order: 2
---

Each file has its own balance (`Balance` in `cesh file stat`). That balance
pays:

- the rent, per byte per day, for as long as the file exists.
- the write fee, per KB, for each write or append.
- for a program file, the compute of the program (see [Compute](../compute.md)).

## Rules

- A new file, or a file that grows, must pay 15 minutes of rent in advance.
  `cesh file put` deposits that amount by default; use `--deposit` to give
  more.
- The rent price follows how full the server's store is. An empty store
  costs much less than a full one.
- When the balance cannot pay the rent that is owed, the server deletes the
  file. After that, the path gives `CES_ERROR_FILE_NOT_FOUND`.
- Anyone can deposit into any file (`cesh file deposit`). Only the owner can
  withdraw. Thus keeping a file alive is something anyone can do.
- A reader pays a read fee per KB, and the owner's price per KB if the
  owner set one (`cesh file set-price`). The owner does not pay its own
  price.
