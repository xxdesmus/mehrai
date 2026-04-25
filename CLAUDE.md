# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Mehrai v2 is a Mirai-focused honeypot. A Docker container exposes a deliberately weak telnetd on TCP/23 to attract Mirai bots. The capture logic runs on the **host** (not inside the container) and uses the Linux kernel's Netlink Connector (`PROC_CN_MCAST_LISTEN`) to receive FORK/EXEC/EXIT/etc. process events from the kernel. When it sees a typical Mirai pattern — a forked child whose `/proc/<pid>/exe` symlink ends in `(deleted)` (Mirai unlinks itself after exec) — it copies the binary out of `/proc/<pid>/exe`, kills the process, and uploads the sample to a Viper API.

Targets Python 2 (uses `print` statements, `urllib2`, `mimetools`, `string.letters`). Don't migrate to Python 3 piecemeal.

## Run / build

```bash
# Build and start the lure container (host)
docker build -t honeypots/mehrai .
docker run -dit --rm -p 23:23 honeypots/mehrai

# Start the host-side monitor (Python 2)
python mehrai.py run $(docker ps -l --no-trunc | grep mehrai | awk '{print $1}') [--recurse] [--monitor] [--overlayfs]
```

Flags:
- `--monitor`: observe only, do not kill caught processes (use when collecting pcaps).
- `--recurse`: recursive watchdog filesystem scan (noisy).
- `--overlayfs`: use overlay2 driver layout instead of devicemapper for the container's diff path.

There are no tests, no linter config, and no CI. Don't invent them; ask the user before adding.

## Architecture

Three files do all the work:

- **`netlinks.py`** — pure `ctypes` binding to `AF_NETLINK` / `NETLINK_CONNECTOR`. Defines the kernel structs (`proc_event`, `cn_msg`, etc.), opens a netlink socket, sends `PROC_CN_MCAST_LISTEN`, and decodes incoming events into dicts. `recv()` returns a list because a single netlink message can carry multiple bitflagged events. Also exposes `pid_to_exe()` / `pid_to_cmdline()` helpers that read `/proc/<pid>/{exe,cmdline}`.
- **`mehrai.py`** — the event loop. Constructs a `NetlinkConnector`, plus a `watchdog.Observer` watching the container's diff path on the host filesystem (`/var/lib/docker/devicemapper/<id>/diff` or the overlay2 equivalent via `map_overlayfs()`). Both paths funnel into `utils.upload()`. The Mirai-specific heuristic lives here: on a FORK event, if `pid_to_exe(child)` contains the string `deleted`, copy `/proc/<child>/exe` to `/tmp/exe.<rand>`, upload, then `kill -9` the child. Also tries to detect Mirai killing telnetd and respawns it via `docker exec`.
- **`utils.py`** — Viper client. `VIPER_URL_ADD` is hardcoded to `http://viper:8080/file/add`; change it for your deployment. `MultiPartForm` builds the multipart body by hand (this is Python 2 — don't replace with `requests` without confirming the Python version target). `get_sha256()` and printable-character sanitizers also live here.

### Why host-side monitoring

Mirai self-deletes its binary very quickly after exec. Watching from inside the container loses the race. The host can read `/proc/<pid>/exe` (which still resolves to the deleted inode) for any PID in any namespace, so the host wins. This is the v1→v2 redesign and shouldn't be undone.

### The Docker storage-driver gotcha

`fspath` is computed for the **devicemapper** layout by default. If the host uses overlay2, `--overlayfs` triggers `map_overlayfs()` which reads `/var/lib/docker/image/overlay2/layerdb/mounts/<id>/mount-id` and points at `/var/lib/docker/overlay2/<fsid>/diff`. Other storage drivers (aufs, btrfs, zfs) are not handled — the path will need manual editing in `mehrai.py`. This was the reason for commit `e2e06a6`.

## Known rough edges (don't "fix" without asking)

- `utils.getTelnetPid` is referenced without being called (`telnet = utils.getTelnetPid` assigns the function object). The EXIT-handler comparison `event['process_pid'] == telnet` therefore never matches.
- `utils.args_to_strings` (plural) is referenced once but only `args_to_string` exists.
- `'kill' and 'telnetd' in netlinks.pid_to_cmdline(...)` is always equivalent to `'telnetd' in ...` — the `'kill' and` is dead.
- These are pre-existing bugs in committed code, not regressions. Leave them alone unless the user asks, and call them out if work touches that path.

## Companion documents

- `CLOUDFLARE_FLEET_SPEC.md` — forward-looking spec for running 10+ honeypot nodes behind Cloudflare Spectrum with a Workers + Durable Objects + R2 backend replacing Viper. Read it before proposing backend / infrastructure changes; it captures already-decided constraints (no Tunnel ingress, no Dynamic Worker Loader, per-node Spectrum apps with PROXY v2, three DO facets justified by fleet scale).
- `SESSION_LOG.md` — running task log per global instructions; keep current.
