# Mehrai Fleet on Cloudflare — Specification

## 1. Goal

Operate a fleet of 10+ Mehrai (Mirai-style) honeypot nodes behind Cloudflare,
with central binary storage, deduplication, telemetry, and fleet coordination.
Each node continues to serve raw TCP/23 telnet to attract Mirai bots, capture
dropped binaries via Netlink process monitoring, and forward them to a
Cloudflare-hosted backend for durable storage and analysis.

## 2. Non-Goals

- Replacing the raw TCP/23 lure with a Cloudflare-only architecture (not
  possible — Workers/Sandboxes/DOs do not accept raw TCP).
- Running the honeypot itself inside Cloudflare compute.
- Live malware analysis or detonation. The backend stores and indexes; analysis
  is out of scope.
- Using Cloudflare Tunnel for ingress. `cloudflared` TCP tunnels require the
  client to also run `cloudflared access`, so real Mirai bots cannot reach a
  Tunnel-fronted port. Spectrum is the only viable Cloudflare ingress.
- Using Dynamic Worker Loader. It runs JavaScript in V8 isolates; Mirai samples
  are ELF binaries and cannot execute there.

## 3. Constraints

- Cloudflare Workers / Sandboxes / Durable Objects accept inbound HTTP/WS only.
  Raw TCP/23 must terminate on a VPS.
- The user has Spectrum available at no cost on their Cloudflare account.
- Source IP of attackers must be preserved end-to-end (PROXY protocol).
- Honeypot must not become a DoS weapon: outbound traffic and resource use must
  be bounded at multiple independent layers.
- Per-node compromise must not escalate to fleet compromise: per-node API keys,
  revocable independently.

## 4. Architecture Overview

```
[Mirai Bot] --TCP/23--> [Cloudflare Spectrum (per-node app, PROXY v2)]
                              |
                              v
                  [VPS: Docker honeypot container]
                  - telnetd (PROXY-aware ingress)
                  - mehrai.py + netlinks.py (Netlink monitor)
                  - Captures dropped binary, computes SHA-256
                              |
                              v
                  HTTPS POST (signed, per-node API key)
                              |
                              v
                       [Workers API]
                              |
       +----------------------+----------------------+
       |                      |                      |
  SampleFacet DO       FleetFacet DO        CoordinationFacet DO
  (dedup, R2 write,    (node registry,      (per-IP and global
   first-seen meta)    health, capture       rate limits across fleet)
                       rate per node)
                              |
                              v
                  Analytics Engine (telemetry)
                              v
                  Dashboard Worker (read-only fleet view)
                              v
                       R2 (binary store)
```

## 5. Components

### 5.1 Honeypot Node (per VPS)

**Container image: `mehrai-node:<version>`**

Contents:
- Alpine base
- `telnetd` (busybox) bound to internal port, fronted by a small PROXY-protocol
  shim that parses the v2 header from Spectrum and forwards the real client IP
  to the application
- Python 3 + `mehrai.py`, `netlinks.py`, `utils.py`
- A small Go or Python sidecar that POSTs captured binaries to the Workers API
  (replaces the current Viper upload path)

Container runtime flags (mandatory):

```
docker run \
  --cpus=1 --memory=256m \
  --pids-limit=50 \
  --ulimit nofile=50:100 --ulimit nproc=20:40 \
  --security-opt=no-new-privileges \
  --security-opt seccomp=mehrai-seccomp.json \
  --read-only --tmpfs /tmp:rw,size=64m \
  --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  -p 2323:23 \
  mehrai-node:<version>
```

Host-side `iptables` (mandatory):

```bash
# Inbound rate limit (Spectrum is the primary defense; this is L2 backstop)
iptables -A INPUT -p tcp --dport 2323 -m state --state NEW \
         -m hashlimit --hashlimit-name telnet \
         --hashlimit 10/sec --hashlimit-burst 20 \
         --hashlimit-mode srcip -j ACCEPT
iptables -A INPUT -p tcp --dport 2323 -j DROP

# Outbound rate limit for container egress (DoS safety net)
iptables -A FORWARD -s <container_cidr> -p tcp --dport 25 -j DROP   # block SMTP
iptables -A FORWARD -s <container_cidr> -m limit --limit 100/sec -j ACCEPT
iptables -A FORWARD -s <container_cidr> -j DROP
```

Application changes vs. current `master`:

| File | Change |
|------|--------|
| `mehrai.py` | Replace Viper upload (`upload()` in `utils.py`) with signed HTTPS POST to Workers API. Add per-IP rate tracking before capture. |
| `utils.py` | Remove `MultiPartForm`, `upload()`, `VIPER_URL_ADD`. Add Workers API client + HMAC signing. |
| `netlinks.py` | No change. |
| `requirements.txt` | Audit `urllib3` / `watchdog` actual usage; remove only what is genuinely unused. |
| *(new)* `proxyproto.py` or sidecar | Parse PROXY protocol v2 header so `mehrai.py` sees real attacker IP instead of Spectrum edge IP. |
| *(new)* `bootstrap.sh` | First-boot: register node with Workers API, receive node ID and API key, write to `/etc/mehrai/node.env`. |

### 5.2 Workers API

Single Worker, multiple routes:

| Route | Method | Purpose |
|-------|--------|---------|
| `/v1/nodes/register` | POST | First-boot node registration. Returns `node_id` and API key. Requires bootstrap secret. |
| `/v1/samples` | POST | Submit captured binary. Multipart: metadata JSON + binary blob. Auth: HMAC of body with per-node key. |
| `/v1/samples/:sha256` | GET | Fetch sample metadata (for dashboard / manual inspection). Auth: operator key. |
| `/v1/coordination/check` | POST | Pre-capture check: `{node_id, attacker_ip, sha256}` → `{should_capture: bool}`. Used by `mehrai.py` before processing. |
| `/v1/health` | POST | Per-node heartbeat (every 60s). Updates `FleetFacet`. |
| `/v1/dashboard/*` | GET | Read-only fleet view. |

Auth model:
- **Bootstrap secret**: shared across all nodes, used only for `/register`. Stored in Workers secret, rotatable.
- **Per-node API key**: issued at registration, stored on the VPS in
  `/etc/mehrai/node.env` (root-owned, mode 0600), never logged. Revocable
  individually via `FleetFacet`.
- **HMAC signing**: every request includes `X-Node-Id`, `X-Timestamp`,
  `X-Signature: hmac-sha256(api_key, timestamp + method + path + body_sha256)`.
  Reject if timestamp drift > 5 min.

### 5.3 Durable Object Facets

**SampleFacet** (one DO instance per SHA-256 prefix shard, e.g. first byte):
- `recordSample({sha256, node_id, attacker_ip, captured_at, size, ...})`:
  atomic check-and-write. If first time, writes binary to R2 at
  `samples/<sha256>` with conditional PUT (`If-None-Match: *`), records
  first-seen metadata, returns `{stored: true, first_seen: true}`. If already
  present, appends sighting metadata to a sightings list, returns
  `{stored: false, first_seen: false, sighting_count: N}`.
- `getSample(sha256)`: returns metadata + sightings.

**FleetFacet** (single DO instance):
- `registerNode({hostname, region, public_ip}) -> {node_id, api_key}`.
- `heartbeat(node_id, stats)`.
- `listNodes()`, `revokeNode(node_id)`.
- Tracks per-node capture rate, last-seen, health.

**CoordinationFacet** (single DO instance, or sharded by attacker IP):
- `shouldCapture({attacker_ip, sha256, node_id})`:
  - If `attacker_ip` exceeded global rate (e.g. 60 captures/hour across fleet):
    return `false`, increment dropped counter.
  - If `(attacker_ip, sha256)` already captured by any node in last 24h:
    return `false`, count as duplicate sighting only.
  - Otherwise: return `true`, record decision.
- Prevents the same Mirai scan campaign from creating 10× duplicate work
  across the fleet.

### 5.4 Storage

**R2 bucket: `mehrai-samples`**
- Object key: `samples/<sha256>` (binary).
- Object key: `metadata/<sha256>.json` (first-seen + sightings, mirrored from
  SampleFacet for offline analysis).
- Lifecycle: no expiration; samples are the product.

**Analytics Engine dataset: `mehrai_events`**
Indexed by:
- `node_id` (index1)
- `attacker_ip` (index2)
- `event_type` (blob1): `connect | capture | dedup_hit | rate_limited | error`
- `sha256` (blob2)
- `country` (blob3, from Cloudflare geo)
- `bytes_captured` (double1)

Queryable via SQL API. 90-day retention.

### 5.5 Spectrum Configuration

**Per-node Spectrum apps** (one per VPS), not a single load-balanced app.
Reasons:
- Preserves source attribution naturally (each node knows which Spectrum app
  fronted the connection).
- Allows per-region targeting (e.g. `us-east-1.honey.example.com` →
  US-region VPS).
- Independent rate limit tuning per node.

Each app:
- Protocol: TCP
- Edge port: 23
- Origin: VPS IP, port 2323 (not 23, so the host's own SSH/whatever is
  unaffected)
- **PROXY protocol: v2 enabled** (mandatory — without this, attacker IP is lost)
- IP access rules: drop known bogon ranges, optional geo allow/deny per node
- Connection rate limit: 20 new conns / sec / source IP

### 5.6 Dashboard Worker

Read-only HTML/JSON view backed by Analytics Engine + FleetFacet:
- Fleet status: nodes alive, captures/hour each
- Recent unique samples (last 24h, 7d, 30d)
- Top attacker IPs, top source countries
- Per-sample detail: SHA-256, first-seen node, sightings, R2 download link

Auth: Cloudflare Access in front of the dashboard route.

## 6. Defense in Depth (DoS / Abuse Prevention)

| Layer | Mechanism | Failure mode it catches |
|-------|-----------|------------------------|
| L1 Spectrum edge | Connection rate limit, IP rules, geo filter | Mass scan floods |
| L2 VPS kernel | iptables hashlimit (in), limit (out), SMTP block | Container bypasses app limits, or escapes |
| L3 Container | cgroup CPU/mem, pids, ulimits, no-new-privileges, seccomp, read-only rootfs, dropped caps | Attacker gains shell in container |
| L4 Application | Per-IP capture rate, kill_process on suspicious EXEC | Sustained low-rate abuse |
| L5 CoordinationFacet | Fleet-wide per-IP and per-sample caps | Distributed scan hitting many nodes |

Each layer is independent; failure-open in one is caught by the next.

## 7. Provisioning / Deployment

Hand-rolling 10+ VPSs is unacceptable. Required automation:

- **Image**: `mehrai-node` Docker image published to a registry (GHCR or
  similar), tagged by version.
- **Bootstrap**: `bootstrap.sh` (idempotent) installs Docker, applies iptables,
  writes systemd unit, calls `/v1/nodes/register`, starts container.
- **Infra-as-code**: Terraform module per VPS provider that:
  - Provisions VPS
  - Runs bootstrap on first boot via cloud-init
  - Creates the corresponding Spectrum app via Cloudflare provider
  - Outputs `node_id` and edge hostname
- **Secrets**: Bootstrap secret in Terraform variable / 1Password; per-node API
  keys never leave the VPS after registration.

## 8. Migration from Current Code

Current state (commit `4ab3362`):
- `mehrai.py` uploads captured binaries to Viper via `utils.upload()`.
- No telemetry beyond stdout.
- No fleet awareness.

Migration steps:

1. **Add Workers API client to `utils.py`** alongside existing Viper upload.
   Behind a feature flag (`MEHRAI_BACKEND={viper,workers,both}`).
2. **Stand up Workers API + R2 + DO Facets** in a Cloudflare account. Test
   end-to-end with one node in `both` mode.
3. **Add PROXY protocol parser** to ingress path. Test with a Spectrum app in
   front of a single test node.
4. **Build bootstrap + Terraform module**. Provision node #2 from scratch.
5. **Cut over node #1** to `MEHRAI_BACKEND=workers`. Decommission Viper path
   once stable for 7 days.
6. **Scale to 10 nodes** via Terraform. Verify fleet dashboard, dedup, and
   coordination work as designed.

## 9. Verification

Plan is not done until all of these pass:

1. **Ingress + PROXY**: telnet via Spectrum edge → container sees real client
   IP in PROXY v2 header, `mehrai.py` logs that IP (not a Cloudflare IP).
2. **Capture path**: simulated Mirai binary execution in container → binary
   captured, SHA-256 computed, POSTed to Workers API, stored in R2.
3. **Dedup**: submit same binary from two different nodes → exactly one R2
   object, two sightings recorded in SampleFacet.
4. **Coordination**: fire 100 capture attempts from one IP across fleet →
   global rate cap kicks in, excess attempts return `should_capture: false`,
   counted as dropped in Analytics Engine.
5. **L2 rate limit**: open 1000 conn/sec from one IP to a node → iptables
   hashlimit drops most, container CPU stays under cap.
6. **L3 hardening**: shell into the running container, attempt to:
   - mount `/proc`: blocked
   - run `iptables`: blocked (no NET_ADMIN)
   - fork beyond pids-limit: blocked
   - flood outbound: rate-shaped by L2
7. **Auth**: replay a captured request 6 minutes later → 401 (timestamp drift
   reject). Submit with revoked node key → 401.
8. **Telemetry**: trigger 10 captures → Analytics Engine SQL query returns 10
   `event_type=capture` rows with correct `node_id`, `attacker_ip`, `sha256`.
9. **Dashboard**: fleet view shows all nodes alive, capture counts match
   Analytics Engine totals.
10. **Failure isolation**: kill one node's container → FleetFacet marks it
    unhealthy within 2 minutes; other nodes unaffected; revoking its API key
    does not affect other nodes.

## 10. Open Questions

- Which VPS provider(s)? Affects Terraform module scope. Likely candidates:
  Hetzner (cheap, EU), Vultr (geo spread), DigitalOcean (familiar).
- Spectrum geo allow/deny — start permissive (capture more) or restrictive
  (less noise)? Recommend permissive for first 30 days, then tune.
- R2 retention — keep all samples forever, or age out duplicates of common
  Mirai variants? Recommend forever until storage cost becomes material.
- Operator dashboard auth — Cloudflare Access with email allowlist, or a more
  formal SSO? Cloudflare Access is sufficient for a small operator group.
- Do we want to forward to Viper as a downstream consumer (R2 → Viper
  webhook) or drop Viper entirely? Recommend dropping unless someone uses it.

## 11. Out of Scope (for a Future Spec)

- Sample analysis / classification (YARA, sandbox detonation, family tagging).
- Sharing samples with third parties (MalwareBazaar, VT, abuse@ contacts).
- A second lure protocol (SSH/22, HTTP/80, UPnP/1900).
- Active responses (e.g. notifying ISPs of compromised source IPs).
