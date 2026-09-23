/*
 * libamt - a small, standalone AMT (Automatic Multicast Tunneling, RFC 7450)
 * gateway library.
 *
 * Implements the gateway side only: discover a relay, request a tunnel,
 * join a multicast channel (ASM or SSM) and receive decapsulated multicast
 * data through it. AMT is a receive-only mechanism for the gateway - there
 * is no facility in the protocol for a gateway to inject multicast traffic
 * upstream through the tunnel.
 *
 * Portable to any POSIX system exposing standard BSD sockets (Linux,
 * macOS/BSD, ...). No platform-specific code, no dependencies beyond libc.
 *
 * Distributed under the terms of the MIT License.
 */

#ifndef _amt_h_
#define _amt_h_

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct amt_gateway amt_gateway_t;

/*
 * Opens an AMT gateway tunnel to the relay at 'relay' (its UDP port, if
 * non-zero, overrides the default AMT port 2268) and joins the requested
 * channel.
 *
 * 'group' is the multicast group to join. For an SSM (source-specific) join
 * pass ssm=1 and a fully specified 'source'; for an ASM (any-source) join
 * pass ssm=0 and source=NULL/source_len=0.
 *
 * The handshake (Relay Discovery/Advertisement, Request, Membership
 * Query/Update) is performed synchronously on the calling thread, retrying
 * up to 'retries' times with 'timeout_ms' between attempts.
 *
 * Returns a new gateway handle on success, or NULL on failure (errno set).
 */
amt_gateway_t *amt_gateway_open(const struct sockaddr *relay, socklen_t relay_len,
                                 const struct sockaddr *group, socklen_t group_len,
                                 const struct sockaddr *source, socklen_t source_len,
                                 int ssm, int timeout_ms, int retries);

/*
 * Returns the underlying UDP socket file descriptor. Suitable for use with
 * select()/poll()/etc - when it becomes readable, call amt_gateway_recv().
 *
 * The tunnel's membership state also needs proactive, timed upkeep that
 * doesn't depend on the socket ever becoming readable - see
 * amt_gateway_next_timeout_ms() / amt_gateway_timeout() below. A minimal
 * event loop looks like:
 *
 *   for (;;) {
 *       int ms = amt_gateway_next_timeout_ms(gw);
 *       int r = wait_readable(amt_gateway_fd(gw), ms);  // select()/poll()
 *       if (r == 0)
 *           amt_gateway_timeout(gw);
 *       else
 *           amt_gateway_recv(gw, ...);
 *   }
 */
int amt_gateway_fd(const amt_gateway_t *gw);

/*
 * Returns how many milliseconds remain until amt_gateway_timeout() should
 * be called to keep this gateway's membership state alive at the relay
 * (RFC 7450's gateway-scheduled refresh, timed from the relay's advertised
 * Query Interval / QQIC). 0 means due now, or overdue.
 *
 * Use this as the timeout argument to select()/poll() alongside
 * amt_gateway_fd(), per the event loop sketched above.
 */
int amt_gateway_next_timeout_ms(const amt_gateway_t *gw);

/*
 * Call when a select()/poll() wait sized by amt_gateway_next_timeout_ms()
 * expires without the gateway socket becoming readable. Proactively
 * (re)initiates a Request, restarting the three-way handshake (Request /
 * Membership Query / Membership Update) to refresh this gateway's
 * membership state at the relay - this does not depend on the relay itself
 * ever sending an unsolicited refresh Membership Query.
 *
 * Skipping this call still works against a relay that reliably re-queries
 * on its own, but leaves the gateway with no fallback if that message is
 * ever lost or the relay doesn't send one - calling it is how the gateway
 * meets RFC 7450's expectation that it drive its own refresh schedule.
 *
 * Does not block; any response from the relay arrives like any other
 * datagram and is handled by the next amt_gateway_recv() call.
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int amt_gateway_timeout(amt_gateway_t *gw);

/*
 * Consumes one datagram from the gateway socket. AMT control traffic
 * (Membership Queries, whether an unsolicited refresh from the relay or a
 * response to amt_gateway_timeout()'s Request) is handled internally and
 * never surfaced to the caller; this also reschedules the deadline
 * reported by amt_gateway_next_timeout_ms() from the relay's current QQIC.
 *
 * If the datagram carried decapsulated multicast data, 'from'/'to' are
 * filled with the original packet's source/destination addresses, '*ttl'
 * with its hop limit/TTL, and up to 'buflen' bytes of the inner UDP payload
 * are copied into 'buf'; the payload length is returned (>= 0).
 *
 * Returns 0 if the datagram was control-plane only (nothing to deliver to
 * the caller this call).
 *
 * Returns -1 on error (errno set, e.g. EAGAIN if the socket is non-blocking
 * and nothing was available).
 */
ssize_t amt_gateway_recv(amt_gateway_t *gw,
                          struct sockaddr_storage *from, socklen_t *from_len,
                          struct sockaddr_storage *to, socklen_t *to_len,
                          int *ttl, uint8_t *buf, size_t buflen);

/*
 * Best-effort teardown of the tunnel and release of the handle.
 */
void amt_gateway_close(amt_gateway_t *gw);

#ifdef __cplusplus
}
#endif

#endif
