---
title: Errors
summary: What the common CES_ERROR_* codes mean, and what to do for each one
order: 4
---

A failed command prints a code such as `CES_ERROR_INSUFFICIENT_BALANCE`.
These are the common codes.

## Accounts and credits

| Code | Meaning | What to do |
| --- | --- | --- |
| `CES_ERROR_ORIGIN_NOT_FOUND` | The signing key has no account on this server | Get credits sent to that key, with `--open` |
| `CES_ERROR_INSUFFICIENT_BALANCE` | The payer has too few credits for the amount plus the fee | Send less, or add credits |
| `CES_ERROR_INSUFFICIENT_BALANCE_WITH_CREATE` | The payer cannot pay the amount plus the cost to open the destination | Send more, or add credits |
| `CES_ERROR_TARGET_NOT_FOUND` | The destination account does not exist | Add `--open` to the transfer |
| `CES_ERROR_WRONG_NONCE` | The replay counter did not match | Run the command again |
| `CES_ERROR_WRONG_PAYMENT_AMOUNT` | A transfer to a payment account must be its exact amount | Send the exact amount |
| `CES_ERROR_BALANCE_OVERFLOW` | The result is too large | Send less |

## Files and programs

| Code | Meaning | What to do |
| --- | --- | --- |
| `CES_ERROR_FILE_NOT_FOUND` | No file at that path, or its rent ran out and the server deleted it | Check the path |
| `CES_ERROR_FILE_EXISTS` | A file is already at that path | Use another path |
| `CES_ERROR_BAD_NAME` | The path is not in a valid zone | See [Zones](../files/zones.md) |
| `CES_ERROR_NOT_OWNER` | Only the owner can do this | Sign with the owner key (`-a`) |
| `CES_ERROR_STORE_FULL` | The server's file store has no space | Try later, or another server |
| `CES_ERROR_PATH_CONFLICT` | The path collides with a directory or a file | Use another path |
| `CES_ERROR_COMPUTE_FUND_TOO_LOW` | The source file cannot pay 15 minutes of compute in advance | Deposit into the source file |
| `CES_ERROR_COMPUTE_MAX_INSTANCES` | The server runs all the programs it allows | Try later |
| `CES_ERROR_COMPUTE_INSTANCE_NOT_FOUND` | No running program with that pid | Check with `cesh compute ps` |
| `CES_ERROR_COMPUTE_DISABLED` | This server has no compute | Use another server |

## Service and network

| Code | Meaning | What to do |
| --- | --- | --- |
| `CES_ERROR_DISABLED` | The server has this service off | Use another server |
| `CES_ERROR_QUEUE_FULL` | The server is busy, or a call on the same file is in progress | Try again later |
| `CES_ERROR_PROTO_REJECTED` | The server does not run that service, for example a file store or compute | Use a server that runs it |
| `CES_ERROR_UNREACHABLE` | No server answered at that address | Check the address and the port, then try again |
| `CES_ERROR_CONNECTION_LOST` | The connection to the server closed during the command | Try again |
| `CES_ERROR_TIMEOUT` | No reply in time | Try again |
| `CES_ERROR_UNKNOWN_PEER` | The destination server is not a peer of this server | Use a server that peers with it |
| `CES_ERROR_KEYNAME_TAKEN` | Another key has that name | Choose another name |
| `CES_ERROR_KEYNAME_NOT_FOUND` | No key has that name | Check the name |
| `CES_ERROR_INTERNAL` | A fault in the server, or a reply that cesh cannot read | Try again; tell the operator if it stays |
