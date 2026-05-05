# Implementation of Proposed Enhancements to the AI-SDN-SIEM Framework

## Overview

This section documents three concrete improvements implemented in the revised
codebase, addressing the design limitations identified in Section [X] of this
report. Each improvement is described with its motivation, design decision, and
the specific code changes made.

---

## 5.1 Redis-Based Persistent State Management

### 5.1.1 Problem Statement

In the original implementation, the `SecurityController` maintained all
per-flow statistics in a Python in-memory dictionary (`self.flows`). While
efficient for a single-process prototype, this design had a critical
operational flaw: if the Ryu controller process crashed or was restarted (a
routine event in production SDN deployments during upgrades or failure
recovery), all accumulated flow state was irreversibly lost. Any flow that was
mid-inspection at the time of the restart would restart its packet count from
zero, potentially causing an attack burst to escape detection if it spanned a
controller restart boundary.

### 5.1.2 Solution: Redis as an Externalized State Store

Redis, an in-memory data structure store with optional persistence, was
integrated as the externalized state backend for the Security Controller. Each
flow's statistics dictionary is serialised to JSON and stored in Redis under a
namespaced key derived from the five-tuple identifier
`(src_ip, dst_ip, src_port, dst_port, protocol)`.

Three design decisions govern the implementation:

**Key expiry (TTL):** Every flow key is stored with a Time-To-Live of 120
seconds. This serves two purposes: it prevents stale entries from accumulating
for completed legitimate flows, and it ensures that an abandoned attack flow
(one that stops sending packets) does not hold state indefinitely.

**Graceful degradation:** The controller attempts to connect to Redis on
startup. If the Redis container is unreachable (e.g., during local development
without Docker Compose), the controller automatically falls back to the
original in-memory dictionary. This ensures the system remains functional in
all environments without code changes.

**IP Blacklist persistence:** The AI service (`app.py`) also writes confirmed
attacker IPs to Redis under a `blacklist:<ip>` key with a TTL of 600 seconds,
mirroring the OpenFlow `hard_timeout` of the DROP rule installed at the
switch. This means that if a new flow from a known-bad IP arrives during the
blacklist window, the AI service returns a BLOCK decision instantly without
running inference — a significant latency saving under sustained attack.

### 5.1.3 Code Changes

**`security_controller.py`**

The `__init__` method now instantiates a `redis.Redis` client and sets a
`self.use_redis` flag. Three helper methods replace direct dictionary access:

- `_get_flow(fid)` — loads from Redis (or local dict on fallback)
- `_save_flow(fid, flow)` — persists to Redis with TTL
- `_delete_flow(fid)` — removes a completed flow entry

The packet handler calls `_save_flow` after every update and `_delete_flow`
when the flow is dispatched for AI analysis, replacing the former `del
self.flows[fid]`.

**`app.py`**

Two helper functions were added:

- `is_blacklisted(ip)` — checks for a `blacklist:<ip>` key in Redis
- `add_to_blacklist(ip)` — writes the key with a 600-second TTL

`_infer_single()`, the shared inference function, calls `is_blacklisted` as
its first action and returns a pre-formed BLOCK response immediately if the IP
is known-bad.

**`docker-compose.yml`**

The `redis-db` service was updated with:

```yaml
volumes:
  - redis-data:/data
command: redis-server --appendonly yes
```

AOF (Append-Only File) persistence ensures that Redis survives a container
restart without losing the blacklist, providing a true end-to-end persistence
guarantee.

---

## 5.2 Batch Inference

### 5.2.1 Problem Statement

The original Security Controller issued one HTTP POST request to the AI
service for every flow that reached the `PACKET_THRESHOLD`. In a high-traffic
network, this creates a 1:1 ratio between new flows and REST API calls. Each
call incurs: TCP connection overhead (or keep-alive reuse latency), JSON
serialisation/deserialisation on both ends, Flask request routing overhead,
and a blocking wait in the controller's `send_to_ai()` method. Under a
simulated DoS scenario generating hundreds of short flows per second, this
pattern becomes a bottleneck that adds latency and may cause the controller to
queue Packet-In messages.

### 5.2.2 Solution: Client-Side Batching with Timeout Flush

A batch buffering mechanism was added to the Security Controller. Instead of
sending each ready flow immediately, the controller appends it to a shared
list (`_batch_buffer`). The buffer is flushed to the AI service in two cases:

1. **Size trigger:** The buffer reaches `BATCH_SIZE` (default: 10 flows),
   sending all 10 in a single HTTP call.
2. **Timeout trigger:** A background daemon thread wakes every 0.5 seconds
   and flushes any pending flows if `BATCH_TIMEOUT` (default: 2.0 seconds)
   has elapsed since the last flush — preventing indefinite waiting in low-
   traffic periods.

The AI service was extended with a `/analyze_batch` endpoint that accepts a
JSON object `{"flows": [...]}` and returns `{"results": [...]}`, processing
each flow through the shared `_infer_single()` function. Error isolation
ensures that a single malformed flow in the batch does not abort the entire
request; a per-item error is returned for the failing entry while the rest are
processed normally.

### 5.2.3 Theoretical Throughput Improvement

The theoretical reduction in REST overhead is proportional to the batch size.
For a `BATCH_SIZE` of 10, the number of HTTP round-trips is reduced by
approximately 90% under sustained high-traffic conditions. Wall-clock latency
per flow remains similar (bounded by the 2-second timeout flush in the low-
traffic case), but controller CPU and socket utilisation are significantly
reduced.

### 5.2.4 Code Changes

**`security_controller.py`**

- `_enqueue_for_ai(flow, datapath)` replaces `send_to_ai()`. It appends to
  `_batch_buffer` and calls `_flush_batch()` if the size threshold is met.
- `_batch_flush_loop()` is a daemon thread started in `__init__` that handles
  timeout-based flushing.
- `_flush_batch()` serialises the buffer, clears it, and issues a single POST
  to `/analyze_batch`. Results are iterated in order and matched to their
  originating datapaths.
- `_build_payload(flow)` extracts the JSON payload construction logic into a
  standalone method, making both the batch and single-flow paths use identical
  serialisation.

**`app.py`**

- `_infer_single(flow_data)` refactors the entire inference pipeline (feature
  extraction → scaling → temporal buffering → model inference → mitigation
  decision → SIEM logging) into a single reusable function.
- `/analyze_flow` now delegates to `_infer_single()`, preserving backward
  compatibility.
- `/analyze_batch` iterates over the `flows` list, calling `_infer_single()`
  for each entry and collecting results into a list.

---

## 5.3 Multi-Controller Architecture

### 5.3.1 Problem Statement

The original deployment ran both `primary_controller.py` and
`security_controller.py` as two Ryu applications within the **same process**
using `ryu-manager`'s multi-app mode. While convenient for development, this
architecture has the following limitations:

- A crash in the security application (e.g., due to a malformed packet or
  an unhandled exception in the AI communication thread) would terminate the
  primary forwarding application as well, taking down the entire network.
- Both applications competed for the same Python GIL, meaning CPU-intensive
  security processing could introduce latency into the forwarding path.
- Both shared the same OpenFlow listening port (6633), preventing independent
  scaling or replacement of either component.

### 5.3.2 Solution: Separate Controller Containers on Dedicated Ports

The two controllers are now deployed as **independent Docker services**:

| Service | Container | OpenFlow Port | Role |
|---|---|---|---|
| `primary-controller` | `primary-controller` | **6633** | L2 forwarding (fast path) |
| `security-controller` | `security-controller` | **6634** | AI inspection (security path) |

Each controller runs its own `ryu-manager` process in its own container,
with the security controller explicitly launched with
`--ofp-tcp-listen-port 6634` to avoid conflict with the primary controller.

This mirrors the architecture described conceptually in the system design
documentation, making it a concrete, deployable reality rather than a logical
abstraction. Mininet topologies connect switches to both ports (6633 and 6634)
using Ryu's multi-controller support, so each switch reports Packet-In events
to both controllers simultaneously. The primary controller installs forwarding
rules; the security controller independently installs DROP rules when attacks
are detected — with DROP rules carrying priority 65535, they override any
forwarding rule the primary controller has installed.

Fault isolation is the primary benefit: the primary controller continuing to
forward traffic even if the security controller or AI service is temporarily
unavailable, ensuring network availability is never dependent on the security
pipeline's health.

### 5.3.3 Code Changes

**`docker-compose.yml`**

The single `sdn-controller` service was split into two:

```yaml
primary-controller:
  command: ryu-manager --ofp-tcp-listen-port 6633 controllers.primary_controller

security-controller:
  command: ryu-manager --ofp-tcp-listen-port 6634 controllers.security_controller
  depends_on:
    - ai-service
    - redis-db
```

The `security-controller` declares `depends_on` for `ai-service` and
`redis-db`; the `primary-controller` has no such dependency, reflecting the
design intent that forwarding should be operationally independent of the
security pipeline.

**`security_controller.py`**

A `LISTEN_PORT = 6634` constant was added for documentation clarity. No
Ryu application code changes are needed for multi-controller support; port
assignment is handled entirely through the `ryu-manager` command-line flag.

---

## 5.4 Summary of Improvements

| Issue | Original Design | Improved Design | File(s) Changed |
|---|---|---|---|
| State loss on restart | In-memory dict | Redis with TTL + AOF persistence | `security_controller.py`, `app.py`, `docker-compose.yml` |
| REST call per flow | 1 HTTP call / flow | Batched (10 flows / call) with timeout flush | `security_controller.py`, `app.py` |
| Single-process controllers | Both apps in one `ryu-manager` | Independent containers on ports 6633/6634 | `docker-compose.yml` |
| No blacklist caching | Full inference on every flow | Redis blacklist short-circuits known-bad IPs | `app.py` |
| Redis data lost on restart | No persistence | AOF-enabled Redis volume mount | `docker-compose.yml` |