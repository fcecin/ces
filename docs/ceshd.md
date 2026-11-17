# ceshd

ceshd runs cesh commands for many people. A web site or another service sends a request for each command. A confined child process runs the command with the cesh code, as if a person typed it.

## Start

```
ceshd --socket /run/ceshd/ceshd.sock --scratch /run/ceshd/scratch
```

| Option | Default | What it does |
| --- | --- | --- |
| `--socket PATH` | (necessary) | The Unix socket for the requests |
| `--socket-mode MODE` | `600` | The mode of the socket file, in octal |
| `--scratch DIR` | `/tmp` | The directory for the scratch directory of each command |
| `--homes DIR` | (none) | The directory for the homes (see "Homes"). Without it, each command gets a new scratch directory. |
| `--home-mb MB` | `64` | The most that a home can hold |
| `--max-running N` | `32` | The maximum number of commands that run at the same time |
| `--timeout SECS` | `300` | The time that a command can run. Then ceshd stops it. |
| `--cpu SECS` | `60` | The CPU time of each command |
| `--mem-mb MB` | `1024` | The address space of each command |
| `--file-mb MB` | `64` | The largest file that a command can write |

ceshd needs Linux 6.7 or later (Landlock ABI 4). It does not start on an earlier kernel. The build skips ceshd when the kernel headers are older than 6.7, and the ceshd E2E tests skip on an earlier kernel.

## Requests

The client connects to the socket (`SOCK_SEQPACKET`) and sends one message. The message holds these fields, and a NUL byte follows each field:

1. `ceshd/1`
2. The environment of the command: zero or more fields `NAME=value`. The names are the client variables of cesh: `CESH_WALLET` (the keys), `CESH_SERVER` and `CESH_PROXY`. Each name can occur one time.
3. An empty field, at the end of the environment
4. The cesh arguments, without the program name

A server in `CESH_SERVER` is the server of each command that does not name a server. A `--server` in the arguments has priority.

The message also holds three file descriptors (`SCM_RIGHTS`): the stdin, stdout and stderr of the command. The output goes directly to these descriptors. ceshd does not copy it.

When the command ends, ceshd sends one reply and closes the connection.

- `exit N`: the command ended with the exit code N.
- `signal N`: a signal stopped the command.
- `timeout`: the command ran longer than `--timeout`.
- `error TEXT`: ceshd refused the request, or ceshd stopped.

If the client closes the connection before the reply, ceshd stops the command.

The client side is in `src/ceshd/ceshd.h` (`send` and `wait`). After `send`, the client must close its copies of the descriptors. If it does not, it does not see the end of the output.

To give a command a terminal, send the terminal side of a pty as the three descriptors. The child makes it its controlling terminal.

## The child

For each request, ceshd forks a child. The child is a copy of ceshd, so it starts immediately, and it shares the memory pages of ceshd until it writes them. The child does these steps.

- It uses the three descriptors as fds 0, 1 and 2, and closes all other descriptors.
- It uses one directory as its home and its current directory. This is the home of its key (see "Homes"), or a new scratch directory.
- It gets an environment with only `HOME`, `PATH` and the variables of the request.
- It confines itself (see below).
- It runs the command with `ceshRun`, and ends.

ceshd removes a scratch directory before it sends the reply. Nothing from a command stays in memory.

## Homes

With `--homes DIR`, a request with a wallet gets the home of the first key of the wallet: `DIR/<the public key in hex>`. The home stays between commands. So the files of cesh in `~/.cesh` (the notes and the scratch of `cesh chat`) and the files that commands write are there for the next command of the same key. Another key cannot see them. A request without a wallet gets a new scratch directory.

A home can hold `--home-mb` at most. Each file and each directory counts at least 4096 bytes. Before a command starts, the child measures its home. A file of the command can grow only into the space that is left. A command that writes more than that ends on `SIGXFSZ` (the reply is `signal 25`). Other commands of a full home continue to run.

## The confinement

- Files. The child can read `/usr`, `/lib`, `/lib64`, the files of the name resolver (`/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/host.conf`, `/etc/gai.conf`), `/etc/localtime`, `/dev/null`, `/dev/urandom` and `/dev/random`. It can read and write its directory (its home or its scratch directory). It cannot see the other files of the host.
- Programs. The child cannot start a program, not from the system directories and not from its directory. It does not need to, because it runs cesh in its own process. A command that starts a program fails: at its end, `cesh bootstrap` cannot start a shell.
- Network. The child cannot open or accept a TCP connection, so `--proxy` cannot get to a local service. UDP stays open, because CES uses UDP.
- Limits. The CPU time, the address space and the file size have limits (`--cpu`, `--mem-mb`, `--file-mb`). The child makes no core file.
- Other processes. The child is not dumpable, so other processes of the same user cannot read its memory or its environment (the wallet). If ceshd ends, the child ends.

Landlock applies the rules for the files and for TCP.

## Operation

- Run ceshd as a separate user that cannot read the secrets of the host. The confinement hides the files, and the separate user gives a second protection.
- Give the scratch directory to ceshd only. A tmpfs is a good location, because nothing goes to the disk.
- Put the homes on a disk, because they must stay. Give the directory to ceshd only.
- SIGINT or SIGTERM stops ceshd. It stops each command that runs, sends `error ceshd stopped` to its client, and removes the socket file.
- ceshd writes one line on stderr for each command: the process ID, the result and the time. It does not write the wallet or the arguments.

## Why ceshd uses fork

ceshd starts no threads. `fork` copies only the thread that calls it. In a process with more threads, the child can get a lock that no thread releases. ceshd checks at start that it has one thread. If it has more, it does not start.
