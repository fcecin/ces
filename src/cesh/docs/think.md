---
title: Think
summary: cesh think syntax, chat requests with tools, what a call costs and the credits it needs, and conversation files
order: 5
---

A server with think sends text to a language model and streams the reply.
The operator chooses the model and the prices. The signer pays.

```
cesh think <words...> [--file <path>] [-v]
cesh think --chat [--in <request>] [-v]
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

## Chat requests

With `--chat`, the input is a chat request in JSON. It has the messages,
each with its role, and the tools that the model can call. A program that
runs the tools sends the whole conversation each time.

```
cesh think --chat --in 'text:{"messages":[
  {"role":"system","content":"You work in a shell."},
  {"role":"user","content":"What is in my home?"}],
 "tools":[{"type":"function","function":{"name":"shell",
  "description":"Run one command.","parameters":{"type":"object",
  "properties":{"command":{"type":"string"}},"required":["command"]}}}]}'
```

- The roles are `system`, `user`, `assistant` and `tool`. An `assistant`
  message has `content`, `tool_calls` or both, and it can have
  `reasoning_content`. A `tool` message has the `tool_call_id` of the call
  that it answers, and the result in `content`.
- A tool has `type` "function" and a `function` with a `name`, a
  `description` and `parameters` (a JSON schema). `tool_choice` is
  optional, with the value "auto", "none", "required" or one function.
- cesh and the server refuse other fields, and cesh gives the reason.
- When the model is done, stdout gets the answer as one JSON object,
  `{"content":"...","tool_calls":[...],"finish_reason":"..."}`. Each tool
  call has an `id`, and its `function` has a `name` and the `arguments`
  text, which is usually JSON. `finish_reason` is "tool_calls" when the
  model waits for the results, and "length" when the answer reached the
  longest reply.
- To go on, add the answer as an `assistant` message (without
  `finish_reason`) and one `tool` message for each call, and send it all
  again. With reasoning on, each `assistant` message needs its
  `reasoning_content` back.
- `--chat` takes no `--file`. A server older than chat requests drops the
  connection, and the call costs nothing.

## What it costs

- Before the call, the server takes the most that the call can cost: one
  token for each byte of the prompt, plus the largest reply. So the balance
  must have that much, else the call fails with
  `CES_ERROR_INSUFFICIENT_BALANCE`.
- After the call, the server keeps the real cost of the tokens and gives the
  rest back.
- A call that fails before the model does work costs nothing.
- A server without think answers `CES_ERROR_DISABLED`.
- A second call on the same conversation file, while one runs, gets
  `CES_ERROR_QUEUE_FULL`.

## Privacy

The prompt goes to the server and to the model provider that the operator
uses. A conversation file under `/h/` can be read by anyone who knows its
path. A conversation file under your own `/m/<your key>/` is private: the
server reads it and appends to it for your `think`, and nobody can read it
over the network, you included. Make it with `cesh file put` as any file.
Another signer who names it gets `CES_ERROR_NOT_OWNER`, the same answer as
for a path with no file.
