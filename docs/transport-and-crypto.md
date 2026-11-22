# Transport and cryptography

This document describes how CES moves bytes, how it proves addresses and identities, and where it uses encryption. It covers each level of the stack, from the UDP datagram to the web gateways. It gives the rules that the design follows, and the attacks that the design accepts. Section 13 lists the items that are open.

The parts:

| Part | Repository | Role |
| --- | --- | --- |
| MINX | `fcecin/minx` | UDP datagrams, address tickets, spam filter, IP bans, proof of work |
| RUDP | `fcecin/minx` (`rudp/`) | Reliable channels on MINX |
| CES server | `fcecin/ces` | The ledger, the requests on the main port, the CesPlex bus and the L2 builtins |
| `cesh`, `ceshd` | `fcecin/ces` | The command line client, and a daemon that runs it for other services |
| `cesluajitd` | `fcecin/ces` | The process of one Lua program |
| `cesproxy` | `fcecin/ces` | A TCP front for the main port |
| cesweb | `fcecin/ces` (`cesweb/`) | A web gateway. It reads files and dials programs with its own key. Its web terminal relays the signatures of a key that the browser holds. |
| fc bridge | `fcecin/fc` (`bridge/`) | The CES client of a web site. It holds the keys of the site's users, and the key of its ledger server. |

## 1. The rules

1. **Two kinds of proof.** The transport proves an address: a party can receive packets at that address. A signature proves an identity: the owner of a key acts and pays. The transport proves no identity. No signature covers a transport value, and no key gets a right from one. The meter counts transport bytes, so a party that can send on a channel can make its bill larger.
2. **An unproven address gets small replies only.** An `HS_OPEN` of 35 bytes gets an `HS_ACCEPT` and one empty `CHANNEL` packet, of 35 bytes each. A `GET_INFO` gets an `INFO`. An `INIT` gets an empty `MESSAGE`. These replies go to the claimed address, so only a party at that address can continue. After that, the opener speaks first. The RUDP accept and the CesPlex bind follow this rule. MINX tickets follow it in part, because the reference implementation does not tie a ticket to an address (section 3).
3. **Each signed request names its receiver and is fresh.** A request on the main port and a CesPlex bind name the server that they are for. They also carry an account nonce, a time that the server deduplicates, or a challenge that the server picked for one channel. So a copy of them fails at each other server and on each other channel. A per-op verb on a bound channel signs the digest of its bind, so it names its server and its channel too (section 6). Section 13 lists the exceptions.
4. **No encryption on the CES wire.** A party on the path can read each channel. A party that can read a channel and send packets with the address of one end can also change what the channel carries. That damage has two limits: what the program at the other end lets the bound key do while the channel is open, and the credit of that key at that server. Section 11 lists the effects that reach past one channel. The design treats an attack on a channel as a sign that the channel has value: an attacker spends effort only on traffic that is worth it.
5. **No key means trust in the key of the connection.** A client that gives no expected server key signs for the key that the server announces. That is the choice of the caller, and the risk falls on the caller's own key. It is trust on first use (TOFU) only where the client keeps the key, as `CesPlexChannel` does for the life of the object.
6. **You trust the gateway that you use.** A gateway sees and can change all the traffic that it relays. cesweb also serves the page into which a person puts a private key. With an empty allowlist, cesweb dials each server that has a public address.
7. **A server is its own accounting universe.** Each server keeps its own ledger, its own prices and its own payout factor. A server with a wrong setting is the same as a server with a wrong ledger. The server bills the resources that a channel uses, from its own measurements. On a direct channel to a program, the measurement comes from the process of that program, which rule 8 counts as part of the server. Clients choose the servers that they trust.
8. **A program process is part of its server.** A program that controls its process can bill each account of that server, because the server bills the payer that a usage report names. Each process holds the private key of its program. A `/s/` process on an ed25519 server also holds the private key of the server. So the server adds no defense against the reports of its program processes. The asset VM (`CES_RUN_ASSET`, `CES_RUN_ALIAS`) runs inside the server process itself.
9. **No ban for an unproven source.** CES does not ban an address for a bad signature or a malformed request, because the source address can be forged. MINX bans for a bad proof of work and for strong RUDP abuse signals, and section 11 shows what that allows.
10. **Clients and servers ship together.** The design adds no paths for old versions. One remains: the client accepts the 7-byte `INFO` body of an older server.

## 2. The levels

| Level | Carried by | It proves | It stops | It does not stop |
| --- | --- | --- | --- | --- |
| UDP datagram | the network | nothing | nothing | forged source addresses, reading, changing |
| MINX ticket | `MESSAGE`, `INFO`, `PROVE_WORK` | that the sender got a packet from this node, in the last 60 to 120 s | packets from a party that got no ticket | a ticket spent from a forged address; a party on the path |
| RUDP channel | MINX `EXTENSION` messages | an address, by the session token | off-path injection into a channel | a party on the path; reading |
| Signed requests | MINX `MESSAGE` on the main port | an identity, by a signature | copies at another server; copies at the same server | reading; a forged `INFO` key |
| Unsigned queries and application datagrams | MINX `MESSAGE` and `APPLICATION` on the main port | nothing | nothing | a changed reply; a forged sender |
| CesPlex bind | the first bytes of a RUDP channel | an identity, by a signature over a server key and a challenge | copies on another channel or at another server | a relay through a server that a no-key client dials, or through a party on the path |
| Per-op signatures | each verb on a bound channel | an identity, per operation, on one channel of one server | copies on another channel or at another server | a copy on the same channel; a relay through a server that a no-key client dials, or through a party on the path, as for the bind; reading |
| Raw pipes | the bytes after a bind | nothing more | nothing more | a party on the path, inside that channel |
| TLS to a web gateway | browser to cesweb, browser to fc | the identity of the web server | reading and changing on that link | the gateway itself |
| TLS to a model API | server to the API of `builtin:think` | the identity of the API server (certificate and host name) | reading and changing on that link | the API provider |
| TLS to a mail relay | server to relay, when the relay offers it | nothing (the certificate is not checked) | a party that only reads | a party on the path that removes the offer, or gives its own certificate |

## 3. UDP and MINX

A MINX message is one UDP datagram. MINX does not divide a message. The `DATA` field of a message is at most 1,280 bytes (`MAX_DATA_SIZE`), the minimum IPv6 MTU. So a reply on the main port must fit in one datagram (for example, `serverinfo` and `builtin-info`).

**Tickets.** MINX checks senders with tickets. A node sends a random 64-bit value (`GPASSWORD`) and keeps it for 60 to 120 seconds. The other node spends it (`SPASSWORD`) in a later packet. A `MESSAGE`, an `INFO` or a `PROVE_WORK` with an unknown ticket is dropped, unless the sender is connected (see below) or a trusted loopback address. Each ticket is good one time. `INIT`, `GET_INFO`, `EXTENSION` and `APPLICATION` messages carry no ticket to spend.

The MINX specification lets an implementation tie a ticket to the address that it went to, or not. The reference implementation does not: it keeps its tickets in one set (`Minx::allocatePassword`, `Minx::spendPassword`). So a party can get a ticket at its own address, and spend it in a packet with another source address. A ticket proves that the sender got a packet from this node, not that the sender is at the source address of its packet.

**First contact.** An `INIT` or a `GET_INFO` carries no ticket. A node must not ban its source, because the source can be forged. The reply is small: an `INFO` for a `GET_INFO`, and in CES an empty `MESSAGE` for an `INIT`. Each reply carries a ticket.

**Connected.** The application tells MINX which addresses are connected. A packet from a connected address needs no ticket, and the receive path applies no ban and no spam filter to it. In CES, the main port treats the IP address of each verified peer as connected (section 7). CES also trusts loopback on both ports, so a process on the server host needs no ticket and gets no ban.

**Spam filter.** A count-min sketch counts packets for each address block, in two tables of one hour each. MINX counts each `INIT` and `GET_INFO` from an address that is not connected, and drops them above the threshold. CES sets the threshold to the highest value (65,535) and counts 1 of 512 other packets. CES also counts each `MESSAGE` and each `PROVE_WORK`, and drops them for a block above the threshold.

**IP bans.** A strong abuse signal bans the address block of the source: a /24 for IPv4, a /56 for IPv6. A failed proof of work and the strong RUDP abuse signals (section 4) are such signals. Each port has its own `Minx` object and its own ban tables: a bad proof of work bans a block on the main port, and a forged token bans it on the rpc port. A trusted loopback address is never banned. A ban does not stop the packets of a connected address, but MINX drops the proofs of work of a banned block. The rpc port has no connected addresses, so a ban there also stops a verified peer.

A ban stays for one hour or more. IPv4 and IPv6 each have a ban table. A table rotates only when a new ban arrives in it, and a ban ends at the second rotation after it. On a port that gets no other ban, a ban does not end. A table also rotates when it holds 1,000,000 blocks, so a flood of bans can end a ban early. The ticket table works the same way.

**Proof of work.** A `PROVE_WORK` message carries a RandomX solution, and spends a ticket. The RandomX hasher is keyed by the server key (`SKEY`), so a solution is good at one server only. The puzzle holds the client key (`CKEY`), a hash of application data (`HDATA`), a time and a nonce, so a solution credits one key. The CES server credits the account whose key starts with the same 8 bytes as `CKEY`. It mints `2^(D-1) * POW_REWARD_BASE` raw credits (one credit is 10^8 raw), with the difficulty D at most 54. A new account pays the account fee from that amount. CES does not compare `HDATA` with the data of the message, so a party on the path can change that data (it carries the listen port of a peer, section 7).

The server keeps the solutions that it accepted, in memory. After a restart, `pow_delay` must refuse the solutions that the server accepted before. The default `pow_delay` is 0, which refuses none.

## 4. RUDP channels

RUDP gives reliable, ordered channels. A channel is `(peer address and port, 32-bit channel id)`. The application drives it: RUDP has no threads and no timers of its own.

**Handshake.** The opener sends `HS_OPEN` with a random 64-bit nonce. The accepting side answers `HS_ACCEPT` with its own random nonce. The session token is the XOR of the two nonces. `HS_ACCEPT` goes to the address that `HS_OPEN` claims, so only a party at that address learns the token. Each `CHANNEL` packet and each `HS_CLOSE` carries the token in clear. A packet with a wrong token is dropped. This is the MINX ticket rule, applied to one channel, and here the token is tied to the address of the channel.

An `HS_OPEN` needs no token. An `HS_OPEN` with another nonce, on a live channel, ends that session and starts a new one.

**What the token is.** The token names one incarnation of a channel, and it keeps off-path parties out. It is not a credential:
- each `CHANNEL` packet carries it in clear;
- the side that accepts sends its nonce last, so it can choose the token;
- a party in the middle can forward the nonces, and give two channels the same token.

So no signature in CES covers the RUDP token.

**The accepting side.** RUDP makes a channel ESTABLISHED on the `HS_OPEN` alone, in the same call that sends `HS_ACCEPT`. Its next pulse sends one empty `CHANNEL` packet. Data that the accepting side writes goes out at once, to an address that has not sent one valid `CHANNEL` packet, and RUDP sends unacked data again in each pulse until the channel idles out. So a protocol on RUDP must let the opener speak first. CesPlex does (section 6).

An `HS_OPEN` proves no address, but the accepting side keeps a channel, and CesPlex keeps a session, for it until the idle time ends. The limit of 8 channels is for each address and port, and no limit applies for each address block. So a party off the path can fill the memory of a server with forged opens.

**Integrity.** Each RUDP packet has a CRC32C trailer. It catches corruption, not tampering.

**Metering.** The channel metrics count each packet before the CRC check and the token check, so a party that can send packets to a channel adds to its bytes.

**Limits.**
- Each side states its byte rate and burst at the handshake. A per-channel token bucket applies the lower of the two values. The CES default is no limit.
- The CES rpc port allows 8 channels for each address and port (`max_channels_per_peer` in the `[rpc_rudp]` table).
- A channel with no traffic for 60 s closes (`DEFAULT_RPC_RUDP_CHANNEL_IDLE_SECS`). A persistent channel is exempt.

**Abuse signals.** A forged token on a `CHANNEL` or `HS_CLOSE` packet, and a reorder buffer overflow, are strong signals: MINX bans the address block of the source. A CRC failure, a stray packet and a truncated packet are soft signals: they feed the spam filter. `CesPlexClient`, `cesh dial` and the fc bridge build their `Rudp` with no `Minx`, so they do not ban. A server and a program endpoint build it with a `Minx`. A program endpoint also dials out on that `Rudp`, so it can ban the block of a server that it dials.

**Closing.** `HS_CLOSE` carries the token. A graceful close waits until the send buffer drains. A `RudpStream::shutdown` before the channel is ESTABLISHED waits for ESTABLISHED when bytes went to RUDP before it, so that they go out first. With no bytes, it closes at once.

## 5. The main port

Accounts, transfers, assets and queries use MINX `MESSAGE` datagrams on the main port.

**The server key.** The client takes the server key from each `INFO` that it accepts, and keeps no key between runs. `INFO` is not signed, so a party that answers a `GET_INFO` can give its own key. Then the client's signed requests name that party, and no other server accepts them. The `INFO` also gives the rpc port, so that party also picks the port that the client dials for CesPlex. A caller that knows the key must compare it (`getServerKey`). The peer miner does this. The client checks each signed reply with the key from the `INFO`.

**Signed requests.** The client signs each request with its account key. The signed bytes include:
- `serverId`, the first 8 bytes of the server key. The server drops a request for another `serverId`, so a copy fails at each other server.
- `reqNonce`, the next nonce of the account. A copy fails at the same server, because the nonce moved on.
- Or `CES_NONCELESS` with a time. The server accepts a time up to 1 hour old and 5 minutes ahead. It keeps the first 8 bytes of each accepted signature in memory, for at least 65 minutes, the longest time that a copy is good. A second copy gets `CES_OK`, and the server does not do it again. A restart clears this record. So a server whose ledger has an earlier run refuses each time before its boot plus `nonceless_delay`, 10 minutes by default: the earlier run took times up to 5 minutes after it stopped. This holds if the clock at boot is not more than 5 minutes behind the clock of the earlier run. A request stamped before the cutoff fails for good, and the sender does not sign a settlement again. The amount of that settlement stays in the vostro, the account of the receiving server at the sending server. Test networks set `nonceless_delay = 0`. Only some operations accept this form.

The server looks up the account by the first 8 bytes of the key, then checks the full key, so two keys with the same prefix are not mixed. The server's own bills (network use, a program's compute fees, burns) do not move the account nonce, so a signed request that runs at the same time keeps its nonce. The server signs its replies to signed requests with its key.

**Unsigned queries.** Seven queries have no signature, and their replies have none: `CES_UNSIGNED_QUERY_ACCOUNT`, `CES_UNSIGNED_QUERY_SOLUTION`, `CES_UNSIGNED_QUERY_ASSET`, `CES_QUERY_PEER_INFO`, `CES_QUERY_ALIAS`, `CES_QUERY_KEYNAME` and `CES_QUERY_KEYNAME_BY_NAME`. A party on the path can change these replies. So a name that such a reply gives is not proof of a key.

**Presence.** The server keeps a table from each key to the address of its last signed request. It writes that table before it checks the nonce, and before it checks that the account exists. So a copy of an old signed request from another address moves the presence of that key there. The table from address to key has no size limit.

**Application datagrams.** A client can send an unsigned datagram to a program on the main port (`CES_APP_COMPUTE_MSG`). It needs no ticket. The server tells the program a sender: the key whose presence is at that address and port. A program can send an unsigned datagram to the presence address of a key (`ces.client_send`), and the client accepts it by its source address only. So this sender is a claim about an address only, and a program must not give a right to it.

**Gossip.** Servers pass `CES_GOSSIP` messages along. Each hop signs again, so a message proves its last sender only, and its author field has no signature. A message id in a bounded cache stops repeats. Gossip uses `CES_NONCELESS`, but it checks no time, so the cutoff after a restart does not cover it (section 13).

**Autoexec.** A server can keep a signed `CES_RUN_ASSET` request and run it at each boot, with no nonce and no time check. This is a deliberate exception to rule 3.

## 6. The CesPlex bind

CesPlex is the L2 bus on the rpc port. It carries file storage, compute, Lua channels, the server mesh and the other builtins. Each RUDP channel starts with a bind, which ties the channel to a key as its payer.

**The four messages** (`include/ces/cesplex/wire.h`):

1. Client to server: the protocol name, `[u16 name_len][name]`. The client speaks first. Its `CHANNEL` packet carries the session token, so it proves the address of the open. The server sends no data on the channel before this. A name length of 0 or more than 256 ends the channel with no reply.
2. Server to client: the server hello, `[32 server_pubkey][u64 challenge]`. The challenge is a fresh random number for this channel, from the server's secure random source (`AutoSeededRandomPool`), and never zero.
3. Client to server: the rest of the bind request, `[u64 client_time_us][32 client_pubkey][32 client_sha256][65 sig]`.
4. Server to client: the bind reply, signed by the server.

The client signs:

```
client_sha256 = SHA-256( u16 name_len || name || u64 client_time_us
                       || client_pubkey || server_pubkey || u64 challenge )
```

The server computes the digest with its own key and the challenge that it keeps for this channel, checks that it is the digest in the request, and checks the signature. A bind for another server, another channel or another time fails. The time check (5 minutes each way) checks the client's clock only: the challenge is what makes a bind good on one channel. The server meters the channel only after these checks.

The bind reply covers the status, `client_sha256`, the server time, the server key, the challenge and the protocol version. The client checks the reply signature, and checks that the reply has the key and the challenge of the hello. A refusal (NACK) is signed too, and the client takes it as a refusal only after that check. A reply that does not verify, or that has an unknown status, is a bad reply.

**Expected keys.** A client that has an expected server key refuses a hello with another key, and signs nothing: it sent only the protocol name. A client with no expected key signs the key in the hello.

| Client | Expected key |
| --- | --- |
| `CesPlexChannel` (file, compute, think and mail clients) | If the caller sets one. Otherwise the first bind that succeeds sets it for the later binds of that object. |
| `cesh` file, compute, mail and think commands | Always: `--server-key`, or the key of the `INFO` of the main port |
| `cesh dial` | `--server-key`, if given |
| Lua `ces.conn.connect` | Always: the key is an argument |
| Lua `ces.file_client`, `ces.compute_client`, `ces.think_client` | If the caller gives one |
| Server mesh (`/ces/peer/1`) | Always: the peer's key |
| fc bridge | Always. It takes the key from the first `INFO` of its session with that server. |
| `SYS_RPC` | Never (section 7) |

**What a copy of a bind can do.** Nothing at another channel. The challenge of that channel differs, and the server picked it.

**What the dialed server can do.** With a client that expects a key: nothing at another server. A party on the path can still relay to that same server, as it can relay any traffic that it sees. With a client that has no expected key: the dialed party can send the hello of another server, pass the bind on while the client is connected, and make the other server bill the client. That is the cost of rule 5. A party on the path that can send with the address of the server can do the same to a client with no expected key, because the hello has no signature.

**Per-op signatures.** After the bind, each file, compute, think and mail verb is `[u8 verb][u32 len][preamble][65 sig]`. The signature covers `SHA-256(verb || preamble || client_sha256)`, with the `client_sha256` of the bind of the channel. That digest covers the protocol name, the client time, the client key, the server key and the challenge. The preamble starts with an 8-byte per-op salt, so two equal operations sign differently, and then an account nonce, or `CES_NONCELESS`. The C++ clients send `CES_NONCELESS` in each verb, and a verb carries no time.

A copy of a verb fails on each other channel and at each other server, because the bind digest differs. This is also true when a dishonest server gives its channel the challenge of a channel at another server: the server keys differ, so the bind digests differ. On the same channel, a copy with an account nonce fails if the operation has a fee. A copy with `CES_NONCELESS` gets `CES_OK` for 65 to 130 minutes: the server does not do a change again, but it does a read again, with no fee. After that time, the copy is a new operation. `LAUNCH` and `CALL` of `/ces/compute/1` use no nonce, so a copy of them on the same channel is a new, paid operation.

A client with no expected key signs for the server key in the hello. A server that such a client dials can send the hello of another server and relay the bind there. Then it can relay the per-op verbs too. That is the cost of rule 5, as for the bind.

The `ATTACH` verb of `/ces/lua/1` has the same signature. Its preamble is the 8-byte instance id only, with no salt and no nonce.

**Responses.** The server signs each response over the status, the verb, the response preamble, a time and the 8 bytes after the tag byte of the request signature. The C++ client (`CesPlexChannel`) writes a failed check to its log and goes on, and it does not compare those 8 bytes with its request. `cesh dial` and the fc bridge read the `ATTACH` response and do not check its signature.

## 7. Above the bind

**Raw pipes.** On `/ces/lua/1` after the `ATTACH`, on `/ces/luarpc/1` (a direct channel to a program's own endpoint), on `/ces/peer/1` and on `/ces/rpc/1`, the bytes after the bind have no signature. A party that can read such a channel and send packets with the address of one end can put bytes on it. A program takes each byte as a byte of the bound key, and the bound key pays for it (rule 4).

**Metering.** The server measures each bound channel, except a `/ces/peer/1` channel, and bills its bound key at each tick (60 s) and once more when the channel closes. The payout factor (`compute_payout_factor`, default 2) makes a channel into a program cost its caller the network price (the server's price for the bytes of a channel) times the factor, and the program's account gets the part above the network price. A program in the server zone (`/s/`) gets no payout.

On `/ces/lua/1`, the server meters the channel itself. On a direct `/ces/luarpc/1` channel, the program's process meters it and reports the payer and the usage to its server, and the server bills that report (rule 8).

**Program endpoints.** Each compute instance can have its own CesPlex endpoint, with its own program key. Its hello carries the program key, so a bind for another program fails there.

**The peer table and the mesh.** A key enters the peer table from the configuration, or from a proof of work whose data carries a peer address. That address is a host and a port, or a port only. For a port only, the host is the source address of that packet. The server does not check an advertised host, and the source address can be forged. So the address of an unverified peer is a claim only. The peer miner sends its probes to that address. The server marks a peer as verified after a paid, signed `serverinfo` query that the key of the peer answers. `/ces/peer/1` accepts the bind of a configured or verified peer only. On the main port, the IP address of a verified peer is connected (section 3).

**`SYS_RPC`.** A VM program can ask its server to call a `/ces/rpc/1` service at an address that the program picks. The server binds the channel with its own server key, expects no key, and sends the program's request bytes raw. So the remote sees the server as the sender, and it cannot tell the server's operator from any program on that server. A later copy of such a bind fails at each other endpoint. But the endpoint that the program picks can pass the bind on while the call runs, because the server expects no key. CES core serves no `/ces/rpc/1`.

**Program signatures.** `ces.sign` signs any bytes with the program's own key. `ces.serverSign`, for a `/s/` program, signs with the server key, over `SHA-256("CES_EXT_ATTEST_V1" || bytes)`. The tag keeps such a signature from standing for a request or a bind of the server.

## 8. Keys, signatures and processes

**Algorithms.** A key is ed25519 (Crypto++) or secp256k1 (libsecp256k1). A public key is 32 bytes. For secp256k1 it is the X coordinate, and the parity of Y goes in the signature tag. So the tag selects the algorithm, and one 32-byte public key can stand for an ed25519 key and for two secp256k1 keys.

**Signatures.** A signature is 65 bytes: a tag byte and 64 bytes. The tag is `0x00` for ed25519, and `0x01` (even Y) or `0x02` (odd Y) for secp256k1. ed25519 signs the bytes that it gets. secp256k1 signs a 32-byte input as it is, and the SHA-256 of a longer input. It uses RFC 6979 nonces and a low S, so its signatures are deterministic. So a request on the main port is signed as its raw bytes with ed25519, and as their SHA-256 with secp256k1. The bind and per-op signatures are over SHA-256 digests. Integers in a digest are big-endian. No digest has a type tag, except the attestation of `ces.serverSign`. cesweb's `cessign.js` produces the same bytes as the C++ code (`SignaturesMatchCessign` in `tests/test_cesplex.cpp`, and its twin in `cesweb/tests/cessign.test.mjs`).

**The server key.** It is also the key of the server's own account, which the server refills. So a party that has the private key of a server can mint on that server.

**Keys at rest.**
- A `cesh` wallet is a file with one key per line, as hex, written with restricted file permissions. `CESH_WALLET` can give the keys instead. cesweb keeps its own wallet the same way.
- A server key is hex, in the configuration (`server_key`) or in its own file (`server_key_file`).
- The server makes an ed25519 key for each program file, and keeps the private key with the file, in clear. Each process of that program gets it.
- The mail password is plain text in the server configuration (`mail_pass`).
- The API key of the model provider is plain text in its own file (`think_api_key_file`).
- fc keeps the CES keys of its users sealed with AES-256-GCM, under a master key of its bridge (section 10).

**Program processes.** `cesluajitd` runs one Lua program. It talks to its server over a Unix socket, which also carries the private key of the program (and, for a `/s/` process on an ed25519 server, the private key of the server, which a hyle validator program uses to sign consensus messages). It has a limit on its address space (`RLIMIT_AS`, from `compute_process_mem_max`). It drops to the compute user (`--computeuser`, default `cesluad`) only when the server runs as root. Otherwise it runs as the server's own Unix user, and a program that escapes the Lua sandbox can read the private key of the server and change the ledger.

**`ceshd`.** It runs `cesh` commands for other services, one confined child process for each command. Landlock limits the files and the TCP ports of the child, and resource limits bound its CPU time, memory and file size. The keys of a command come in its request (`CESH_WALLET`).

## 9. Encryption

The CES wire has no encryption: MINX, RUDP, the requests on the main port and CesPlex are all clear text. Encryption is at the edges only.

| Link | Encryption | Check of the other side |
| --- | --- | --- |
| Browser to cesweb | TLS 1.2 or 1.3 (nginx, Let's Encrypt) | the browser checks the certificate |
| Browser to fc | HTTPS (Caddy) | the browser checks the certificate |
| nginx to cesweb; Caddy to the fc application | none (HTTP on loopback) | loopback |
| CES server to a model API (`builtin:think`) | HTTPS (OpenSSL) | certificate and host name. Plain `http://` is accepted for a local model server. |
| CES server to a mail relay (`builtin:mail`) | STARTTLS when the relay offers it | none: the certificate is not checked. With no STARTTLS, `AUTH LOGIN` goes in clear. |
| CES server to a program process | none (a Unix socket) | the file permissions of the socket |
| fc web application to its bridge | none (a Unix socket) | the file permissions of the socket |
| `cesproxy` clients to the proxy | none (TCP) | none |
| WebAdmin (the server dashboard) | none (HTTP, no authentication) | loopback by default. An operator option permits another address. It can mint. |
| Cesco (the server console) | none (a Unix socket) | the file permissions of the socket |
| fc keys at rest | AES-256-GCM | the GCM tag |

## 10. Gateways and custodians

**cesweb.** It reads files and dials programs with its own wallet, and pays for them. Its allowlist, `CESWEB_ALLOW_HOSTS`, lists the servers that it dials. An empty list lets it dial each server that has a public address, and `CESWEB_ALLOW_PRIVATE_HOSTS=1` adds private addresses.

Its web terminal (`/dev/dial`, a dev tool) is different. The person gives a private key to the page, and the page puts it in WebCrypto as an ed25519 key that cannot be exported. The page signs the bind and the `ATTACH` itself, and cesweb relays the signatures to `cesh dial --extsign`. cesweb serves that page, so the key stays away from cesweb only while cesweb serves an honest page. The order of the control messages:

1. The browser sends its `hello` message (its key and the target).
2. `cesh` sends the protocol name, reads the server hello, and prints `HELLO <server key> <challenge>`.
3. cesweb sends `serverHello` to the browser. The challenge stays a decimal string end to end, because it can be above 2^53.
4. The browser sends `sigs`: the bind signature and the `ATTACH` signature.
5. `cesh` binds, attaches and prints `READY`. Then the channel is a raw pipe.

The page signs for the server key that cesweb reports, and it has no field for an expected key. So the browser trusts cesweb for the identity of the server (rule 6).

**`cesproxy` and MinxProxy.** MinxProxy carries MINX over TCP to one UDP server. It forwards `MESSAGE` and `PROVE_WORK` only, so no RUDP or CesPlex goes through it. It rewrites the tickets and answers `GET_INFO` from its cache, so a client behind it takes the server key from the proxy (rule 6). `cesproxy` is the CES form of it: it checks the signatures and the proofs of work before it forwards. The `APPLICATION` lane does not go through it.

**fc.** fc holds the keys of its users, so fc can sign for them. The sealing protects a copy of the database. It does not protect against the web application: the bridge signs with a sealed key, or gives the private key (`export`), for each caller on its socket, and a sealed key is not tied to a user. The bridge also holds the private key of its ledger server, and signs grants from the server's own account with it, and it holds a reader key and the master key. The ledger server and the bridge run as one Unix user. The deploy files give the ledger no compute builtin, so no Lua program runs beside these key files. The programs run on the network servers, which run as root, and their program processes run as `cesluad`. The bridge always expects the server key (section 6). A visitor's key pays the visitor's channel into a program.

## 11. Who can do what

| Party | Can | Cannot |
| --- | --- | --- |
| Off the path | Make a server send small replies to a forged address. The spam filter limits `INFO` and the empty `MESSAGE`. No limit for each address block applies to `HS_ACCEPT` and the empty `CHANNEL` packet. | Send on a RUDP channel; get a server hello or channel data sent to another address; guess a live channel id |
| Off the path | Fill the memory of a server with forged opens, each kept until the idle time ends | — |
| Off the path, with a ticket from its own address | Make the server answer one request to a forged address, for each ticket | — |
| Off the path, with a ticket from its own address | Ban the address block of another address on the main port, with a bad proof of work | — |
| Off the path | Fill the spam budget of an address block with about 200,000 forged `GET_INFO` packets. The server then drops the first contacts, the requests and the proofs of work of that block for one to two hours. | — |
| On the path, reading only | Read each channel and each request | Use a signature at another server or on another channel |
| On the path, reading and sending | Change the bytes of a raw pipe that it sees, which the program takes as commands of the bound key. End that channel. Change an unsigned reply. For each client, answer in place of the server with the challenge of a channel that it opened at that same server. The server then binds that channel to the client's key (section 6). For a client with no expected key, do the same with the hello of another server, and relay the bind and the per-op verbs there (rule 5) | Use a signature at another server, or open a channel as another key at another server, if the client expects a key |
| On the path, reading and sending | Ban the address block of one end on the rpc port, with one packet that has a wrong token | — |
| On the path, reading and sending | Move the presence of a key, with a copy of its old signed request | Spend for that key |
| A server that a client dials | Read and answer the channel. If the client expects no key: relay the bind and the per-op verbs to another server (rule 5) | Use the client's bind or per-op verbs elsewhere, if the client expects a key |
| A gateway (cesweb, MinxProxy) | All that it relays: read, change, choose the server key. cesweb: get the private key of a person, if it serves a changed page. | — |
| A custodian (fc) | Sign for its users; mint on its ledger server | — |
| A program on a server | Speak as its server through `SYS_RPC`; bill each account of its server, if it controls its process; on a server that runs it as the server's own user, own the server, if it escapes the sandbox | Get a bind of a visitor for another program or server |
| A server | Bill and pay as it likes, in its own ledger | Change another server's ledger |

These effects reach past one channel:
- a packet with a wrong token bans an address block on the rpc port;
- a bad proof of work with a forged address bans an address block on the main port;
- forged first contacts fill the spam budget of an address block;
- bytes on a raw pipe to a program are commands of the bound key, and their effect can outlast the channel;
- a copy of an old signed request moves the presence of its key;
- a party on the path that answers the hello gets a bound channel of its own at the same server, and the client's close does not end it.

## 12. The cryptographic principles

| Principle | What it asks | Where CES applies it |
| --- | --- | --- |
| Freshness | A signature is good one time: the verifier gives a challenge, or keeps the messages that it saw | The CesPlex challenge; the account nonce; the deduplication of `CES_NONCELESS` (in memory, with a cutoff after a restart); gossip has only a cache of message ids |
| Name the receiver | A signed message names its receiver, so another receiver refuses it | `serverId` in each signed request; the server key in each bind, and so in each per-op verb, which signs the bind digest (section 6) |
| Channel binding | An authentication belongs to one channel | The CesPlex challenge: a value that the server makes for one channel, and that the client signs. With no key agreement, a party in the middle can still pass a bind on. It can pass it to the same server for each client, and to another server when the client expects no key. |
| Intended identity | The signer signs the identity that it meant, from a key that it already holds, not one that the other side announced | Each client with an expected key. A client with no expected key accepts this risk (rule 5). |
| No signing oracle | An untrusted party cannot make a trusted key sign what it chooses | Each VM program can make its server bind with the server key through `SYS_RPC`, and this is an open design question. `ces.serverSign` puts a domain tag before the data. |
| Authenticate the whole session | Each message is signed, or the session has a key that only the two ends hold | The per-op verbs. The raw pipes are not, and the design accepts this (rule 4). The C++ client does not enforce the response signatures (section 6). |
| Address before answer | Answer an unproven address with small replies only | The RUDP accept and token; the CesPlex protocol name first. MINX tickets, without the tie to an address. |

## 13. Open items

- `SYS_RPC` speaks as the server, for each program on it. Which identity it should show is a design question.
- RUDP does not stop an accepting side that writes first. Each protocol on it must let the opener speak first.
- A MINX ticket is not tied to an address in the reference implementation. So a bad proof of work with a forged source address bans the block of that address (section 3).
- A packet with a wrong token bans the address block that it claims, on the rpc port (section 11).
- A ban ends only when later bans rotate the table, so on a quiet port it does not end (section 3).
- Forged first contacts can fill the spam budget of an address block (section 11).
- The spent proofs of work are in memory, and the default `pow_delay` is 0, so a spent solution is good again after a restart.
- The server writes the presence of a key before it checks the nonce of the request (section 5).
- `CesPlexChannel` logs a response that fails its signature check, and goes on (section 6).
- MinxProxy takes an `INFO` from any source as the reply of its server, and caches its key before it checks the ticket.
- Gossip has no `serverId` check on its path, and its author field has no signature (section 5).
- Gossip checks no time. After a restart, or after the cache drops the message id, a copy of a signed hop debits its sender again (section 5).
- Autoexec runs a stored signed request at each boot, with no nonce and no time check (section 5).
- `HDATA` is not compared with the data of a `PROVE_WORK`, so a party on the path can change a peer advertisement (section 3).
- Forged opens can fill the memory of a server: each one keeps a channel and a CesPlex session until the idle time ends (section 4).
- A copy of a `CES_NONCELESS` read runs again with no fee, for 65 to 130 minutes (section 6).
- The table from address to key of the presence has no size limit (section 5).
- `cesh dial` and the fc bridge do not check the signature of the `ATTACH` response (section 6).
- A direct channel between two instances of one program bills the file balance of the program in place of its account, because the report tells the direction by `payer == self`.
- The raw pipes after a bind have no authentication, and the design accepts this.
- A client with no expected key trusts the key in the hello, and the design accepts this.
