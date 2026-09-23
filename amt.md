# amt.c / amt.h — an AMT (RFC 7450) gateway library

## What this is

A small, standalone C library implementing the *gateway* side of
Automatic Multicast Tunneling (AMT, RFC 7450). It lets a host with no
native multicast path to the wider network (typical for a laptop, a
cloud VM, or anything behind a non-multicast-capable link) join a
multicast channel and receive its traffic anyway, by tunneling everything
over ordinary point-to-point UDP to an AMT relay that *does* have real
multicast connectivity.

It depends only on standard BSD sockets (`<sys/socket.h>`,
`<netinet/in.h>`, `<arpa/inet.h>`) and libc — nothing from the rest of
this repository. It is usable as-is from any C or C++ program on Linux or
macOS/BSD; dbeacon is simply its first caller, via a small adapter (see
"Integration into dbeacon" below).

## Why gateway-only, and why receive-only

AMT defines two roles: **gateway** (the multicast-less host that wants
in) and **relay** (a router with real multicast connectivity that serves
gateways). This library implements only the gateway role — there is no
code here for accepting connections from other gateways.

More importantly, AMT is fundamentally **receive-only** for the gateway.
The protocol lets a gateway ask a relay "please forward group G's traffic
to me", and the relay does so by encapsulating multicast packets it
receives natively and shipping them over the tunnel. There is no AMT
message for the reverse direction — a gateway cannot inject its own
multicast traffic upstream through the relay. A tool that both sends and
receives multicast (like dbeacon) can therefore receive other
participants' packets through an AMT tunnel, but its own transmissions
still need a real multicast path (or simply go nowhere, silently, if
there isn't one) — AMT does not change that.

## Protocol walkthrough

RFC 7450 defines seven message types, sent as small UDP datagrams over
port 2268 (a few of these matter to a gateway):

| # | Name                  | Direction       | Purpose                                    |
|---|------------------------|-----------------|---------------------------------------------|
| 1 | Relay Discovery        | gateway → relay | "are you there, and what's your real address?" |
| 2 | Relay Advertisement    | relay → gateway | "yes, and here is my unicast tunnel endpoint" |
| 3 | Request                | gateway → relay | "set up a tunnel for me"                    |
| 4 | Membership Query       | relay → gateway | "what do you want to join?" (also used for periodic refresh) |
| 5 | Membership Update      | gateway → relay | "here is what I want to join" (an IGMP/MLD report) |
| 6 | Multicast Data         | relay → gateway | an encapsulated multicast packet            |
| 7 | Teardown               | either          | "tunnel is going away"                      |

`amt_gateway_open()` drives messages 1–5 synchronously to establish the
tunnel and perform the initial join:

1. **Discovery → Advertisement.** Send a Relay Discovery with a random
   nonce to the address the caller supplied (this may be an anycast
   address — production deployments often are, e.g. GEANT's AMT relay
   anycasts `62.40.96.44`). The relay answers with its *real*, specific
   unicast address to use for everything else (in the GEANT case, one of
   several relays behind the anycast address, e.g. `62.40.96.41`). This
   step also implicitly resolves an anycast relay down to one concrete
   relay instance for the life of the tunnel.

2. **Request → Membership Query.** Send a Request to that real relay
   address, carrying a second random nonce and a bit indicating whether
   IPv4 or IPv6 encapsulation is wanted. The relay responds with a
   Membership Query, echoing that nonce and including a **Response MAC**
   — an opaque value the gateway must echo back verbatim in its next
   message, which is how the relay confirms it's still talking to the
   same gateway (a lightweight anti-spoofing/session-binding check, not
   a cryptographic authentication of the gateway's identity).

3. **Membership Update (join).** Build an IGMPv3 (for IPv4 groups) or
   MLDv2 (for IPv6 groups) membership report describing the desired join
   — see "Join encoding" below — wrap it with the echoed nonce and MAC,
   and send it. From this point, the relay should start forwarding
   matching multicast traffic as Multicast Data messages.

After `amt_gateway_open()` returns a handle, the caller drives everything
else through `amt_gateway_recv()`, called whenever the gateway's socket
(from `amt_gateway_fd()`) is readable:

- **Multicast Data** (message 6): strip the 4-byte AMT header, and
  manually parse the encapsulated IPv4-or-IPv6 + UDP packet inside — this
  library does **not** hand the packet to the kernel (there is no real
  network interface to inject it into), it parses just enough of the IP
  and UDP headers by hand to recover the original source address, the
  destination (group) address, the TTL/hop-limit, and the inner UDP
  payload, and hands only that back to the caller.

- **Membership Query** (message 4), arriving again later as a periodic
  **refresh**: the relay expects a fresh Membership Update roughly every
  query interval to keep forwarding state alive. This is handled
  *transparently* — the caller never sees these; `amt_gateway_recv()`
  recognizes them, updates the stored MAC, re-sends a Membership Update
  reusing the join state, and returns 0 ("nothing to deliver this call").

Any other message type received on the socket is currently just ignored.

### Refresh scheduling (QQIC)

Relying only on the relay to *push* a fresh Membership Query and reacting
to it, as above, isn't enough on its own — if that message is ever lost
(plain UDP, no retransmission) or a given relay just doesn't send one
unprompted, nothing about that reactive path ever notices, and the tunnel
quietly goes stale until something external forces a refresh. (This
isn't hypothetical — the earlier, purely-reactive version of this library
needed exactly that kind of external forced refresh to stay alive
reliably.) RFC 7450 puts the fix in the gateway's hands: the General Query
that a Membership Query carries includes a **QQIC** (Querier's Query
Interval Code, RFC 3376 §4.1.7 / RFC 3810 §5.1.9), and the gateway is
expected to use it to *proactively* schedule its own refresh at
`(now + Query Interval)` — restarting the three-way handshake with a new
Request — rather than waiting indefinitely on the relay.

`amt_gateway_open()` and `amt_gateway_recv()` both decode the QQIC out of
every Membership Query they see (falling back to a conservative ~125s
default if one can't be parsed, e.g. the encapsulated General Query is
absent or malformed) and maintain an internal refresh deadline from it.
Two new calls expose this to the caller's event loop:

- `amt_gateway_next_timeout_ms()` — milliseconds until the next scheduled
  refresh is due; use this as the `select()`/`poll()` timeout alongside
  `amt_gateway_fd()`.
- `amt_gateway_timeout()` — call when that wait expires without the
  socket becoming readable; sends a fresh Request to restart the
  handshake. The relay's Membership Query response is then picked up by
  the next `amt_gateway_recv()` call like any other datagram.

The old purely-reactive behavior still works as a bonus on top of this —
an unsolicited refresh Query from the relay is still handled and also
reschedules the deadline — but callers should wire up the timeout pair
above rather than relying on that alone.

### Join encoding

Exactly one channel is joined per `amt_gateway_t` (see "Scope/limitations"
below). Two shapes:

- **SSM (source-specific), `ssm=1`:** builds an IGMPv3/MLDv2 report with
  one group record in **MODE_IS_INCLUDE** mode, listing exactly the one
  source address the caller supplied. This is the `(S,G)` join shape.

- **ASM (any-source), `ssm=0`:** builds a report with one group record in
  **MODE_IS_EXCLUDE** mode with zero excluded sources — the standard
  IGMPv3/MLDv2 encoding for "give me everything sent to this group,
  regardless of source." This is the `(*,G)` join shape.

### Exact field layout of Query and Update (bytes, not just fields)

RFC 7450's ASCII-art diagrams pack the Response MAC across a 16-bit
remainder of one 32-bit row plus the whole of the next row, which is easy
to misread as "the MAC starts at the next 4-byte boundary." It doesn't.
Verified byte offsets, confirmed against a real relay's packets (GEANT,
`62.40.96.44`) and cross-checked against RFC 7450 Figures 13-15
character-by-character (there are no published errata against this RFC —
the spec is correct; an earlier draft of this library misread the
diagram):

- **Request** (type 3, gateway→relay): byte 0 = version/type, byte 1 =
  reserved bits with the **P flag in the low-order bit** (not a separate
  byte), bytes 2-3 further reserved, bytes 4-7 = 32-bit Request Nonce.
  Header is 4 bytes total.
- **Membership Query** (type 4, relay→gateway): byte 0 = version/type,
  byte 1 = reserved bits with **L in bit 6 and G in bit 7** (both
  counting from the MSB), bytes **2-7 = the 48-bit (6-byte) Response
  MAC**, bytes **8-11 = the 32-bit Request Nonce**, then (if the G flag
  is set) a 2-byte Gateway Port + 4-or-16-byte Gateway Address, then the
  encapsulated IP packet carrying a real IGMPv3/MLDv2 general query
  (confirmed to include an IP Router Alert option, TTL 1, destination
  `224.0.0.1` — this library doesn't need to parse it, so it's ignored).
  Header is 2 bytes total, immediately followed by the MAC — *not* 4.
- **Membership Update** (type 5, gateway→relay): byte 0 = version/type,
  byte 1 = reserved (all zero), bytes **2-7 = the same 48-bit Response
  MAC**, echoed verbatim from the Query, bytes **8-11 = the Request
  Nonce**, echoed, then the encapsulated IGMPv3/MLDv2 report from byte 12
  onward. Header is 2 bytes total, same shape as the Query.

If you're debugging against a different relay and its bytes don't match
this: trust a packet capture over any diagram (this one included) —
decode it against fixed, recognizable landmarks (IGMP dst `224.0.0.1`,
TTL `1`, protocol number `2`, the Router Alert option bytes
`94 04 00 00`) to re-anchor the offsets, the way this layout was itself
confirmed. See `design.md` for the detailed account of getting this wrong
once, then right.

## API summary (see `amt.h` for the authoritative doc comments)

```c
amt_gateway_t *amt_gateway_open(relay, relay_len,
                                 group, group_len,
                                 source, source_len,   /* NULL/0 for ASM */
                                 ssm, timeout_ms, retries);

int      amt_gateway_fd(const amt_gateway_t *gw);

int      amt_gateway_next_timeout_ms(const amt_gateway_t *gw);
int      amt_gateway_timeout(amt_gateway_t *gw);

ssize_t  amt_gateway_recv(amt_gateway_t *gw,
                           from, from_len, to, to_len, ttl,
                           buf, buflen);

void     amt_gateway_close(amt_gateway_t *gw);
```

`amt_gateway_open()` performs the full handshake synchronously
(retrying up to `retries` times, waiting `timeout_ms` between attempts at
each step) and either returns a ready-to-use handle or `NULL` on failure.
There is currently no asynchronous/non-blocking variant of the handshake
itself — only the steady-state calls (`amt_gateway_recv()`,
`amt_gateway_next_timeout_ms()`/`amt_gateway_timeout()`) are meant to be
driven from an event loop, per "Refresh scheduling (QQIC)" above.

`amt_gateway_recv()`'s three possible outcomes:

- **> 0**: a Multicast Data payload was decapsulated and copied into
  `buf`; `from`/`to`/`ttl` describe the original packet.
- **0**: the datagram was AMT control traffic, fully handled internally
  (most commonly a refresh Membership Query). Nothing for the caller to
  do.
- **-1**: a socket error (`errno` set, e.g. `EAGAIN` on a non-blocking
  socket with nothing available).

## Scope and limitations (current version)

- **One channel per handle.** A single `amt_gateway_t` joins exactly one
  `(S,G)` or `(*,G)`. Joining several groups, or several sources within
  one SSM group, through a single tunnel would need the Membership
  Update to carry multiple group records reflecting the full current
  membership state on every update (IGMPv3/MLDv2 reports are
  state-replacing, not incremental) — not implemented. Multiple
  channels currently means multiple `amt_gateway_t` handles (and
  therefore multiple independent tunnels/handshakes), which works but is
  not bandwidth- or relay-session-efficient.

- **No IGMP/MLD checksum.** The IGMPv3/MLDv2 report built for the
  Membership Update has its checksum field left as zero. These reports
  are only ever consumed by the AMT relay's gateway-facing logic — they
  never traverse a real IGMP/MLD-speaking router — so no relay
  encountered so far has required it. A relay that validates this
  checksum strictly would need this adding.

- **No IPv6 extension header handling** when parsing encapsulated
  Multicast Data: the IPv6 path assumes UDP directly follows the fixed
  40-byte IPv6 header (Next Header must already be 17). A relay that
  ships IPv6 extension headers (e.g. a Hop-by-Hop Options header) in the
  encapsulated packet would not decapsulate correctly today.

- **No authentication beyond the relay's own nonce/MAC challenge.**
  There is no support for AMT's optional stronger security extensions;
  this implements the base gateway discovery/join/data flow only.

- **Membership Query's L (Limit) flag is not read.** Byte 1 of the
  Membership Query (bit 6, per "Exact field layout" above) is never
  inspected, so a relay signalling that it's limiting how many
  group/source records it will accept never causes the gateway to scale
  back. Currently harmless in practice only because of the "one channel
  per handle" limitation above - `build_membership_report()` never emits
  more than a single group record with at most one source, so there is
  nothing to scale back regardless. This would need real handling if
  multi-group/multi-source support is ever added to a single handle.

- **Teardown is best-effort.** `amt_gateway_close()` sends a Teardown
  message but doesn't wait for or require any acknowledgement.

- **No QRV-based retransmission.** RFC 7450 (via RFC 3376 §4.1.6 / RFC
  3810 §5.1.8's Querier's Robustness Variable, QRV) expects unsolicited
  Membership Updates and, optionally, Teardown to be sent QRV times for
  loss resilience, since neither is a request/response exchange with its
  own retry loop the way the handshake steps are (those already have
  `retries`/`timeout_ms`). `send_membership_update()` and the Teardown
  send in `amt_gateway_close()` are both single fire-and-forget `sendto()`
  calls - QRV is never read, and there's no retry if that one datagram is
  lost. `amt_gateway_timeout()`'s periodic re-Request (see "Refresh
  scheduling (QQIC)" above) gives some independent cover for a lost
  refresh specifically, but a lost Membership Update sent in direct
  response to a just-received Membership Query, or a lost Teardown, still
  isn't retried.

## Future work

- **Membership Query's G (Gateway Address) flag / NAT self-detection.**
  Byte 1 bit 7 of the Membership Query (see "Scope and limitations"
  above) is now correctly *skipped* when parsing the QQIC out of a
  Membership Query (`parse_query_interval()` knows to step over the
  Gateway Port/Address field when G=1, so QQIC parsing doesn't
  misalign), but its *contents* are still discarded rather than
  surfaced. When a relay sets G=1, that field echoes back the source
  IP/port it actually saw the gateway's Request arrive from - a
  STUN-like reflection a gateway can compare against its own local
  address to detect it's behind a NAT. Worth adding if a caller needs
  NAT self-detection, by decoding and surfacing the reflected
  address/port through the API (e.g. a new accessor, since it doesn't
  fit `amt_gateway_recv()`'s per-packet shape).

## Integration into dbeacon

dbeacon calls this library only when started with `-amt RELAY_ADDR[/PORT]`.
Because AMT is receive-only, dbeacon's own periodic reports are still
sent over its normal (native multicast) send socket exactly as before —
`-amt` only changes where dbeacon listens for *incoming* multicast, not
how it sends. The wiring lives in `dbeacon.cpp`:

- `handle_mcast()` picks between the normal `RecvMsg()` (msocket.h) and a
  small adapter, `AMTRecvMsg()`, based on whether the ready socket is the
  AMT gateway's fd. `AMTRecvMsg()` just calls `amt_gateway_recv()` and
  copies the resulting `sockaddr_storage` values into dbeacon's own
  `address` type.
- Because `AMTRecvMsg()` presents the exact same `(from, to, ttl, buffer,
  len)` shape as the native path, the existing `handle_ssm`/`handle_asm`
  callbacks are reused unchanged — the AMT gateway socket is registered
  with `ListenTo()` exactly like a native multicast socket, and the rest
  of dbeacon's beacon-processing logic has no idea the packets arrived
  over a tunnel.
