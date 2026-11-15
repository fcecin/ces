---
title: Think
summary: cesh think syntax, what a call costs, the hold before a call, and conversation files
order: 5
---

A server with think sends text to a language model and streams the reply.
The operator chooses the model and the prices. The signer pays.

```
cesh think <words...> [--file <path>] [-v]
```

- The prompt is the words, or `--in <file>`, or stdin.
- Only the reply goes to stdout, so the command can pipe. `-v` also prints
  on stderr the charge, the tokens that the call used (the prompt, the part
  of it from the model's cache, and the reply), and the server's limits (the
  model's window in tokens, the largest prompt in bytes, the longest reply
  in tokens). An older server sends no tokens and no limits.
- `--file <path>`: a conversation file in the store. The server sends the
  model the content of the file and then the new text. After the reply, it
  appends the new text and the reply to the file. The signer must own the
  file, and the file balance pays for the growth.

## What it costs

- Before the call, the server holds the most that the call can cost: one
  token for each byte of the prompt, plus the largest reply. The balance must
  cover the hold, else the call fails with `CES_ERROR_INSUFFICIENT_BALANCE`.
- After the call, the server keeps the real cost of the tokens and gives the
  rest back.
- A call that fails before the model does work costs nothing.
- A server without think answers `CES_ERROR_DISABLED`.
- A second call on the same conversation file, while one runs, gets
  `CES_ERROR_QUEUE_FULL`.

## Privacy

The prompt goes to the server and to the model provider that the operator
uses. A conversation file under `/h/` can be read by anyone who knows its
path.
