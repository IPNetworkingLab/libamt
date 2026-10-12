/*
 * libamt - a small, standalone AMT (RFC 7450) gateway library.
 * See amt.h for the public API and design notes.
 *
 * Distributed under the terms of the MIT License.
 */

#include "amt.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define AMT_PORT 2268

/* Common relay default (see amt.md); used only until the relay's actual
 * QQIC is learned from a Membership Query, or if one never parses. */
#define AMT_DEFAULT_QUERY_INTERVAL_SEC 125

enum {
	AMT_TYPE_RELAY_DISCOVERY     = 1,
	AMT_TYPE_RELAY_ADVERTISEMENT = 2,
	AMT_TYPE_REQUEST             = 3,
	AMT_TYPE_MEMBERSHIP_QUERY    = 4,
	AMT_TYPE_MEMBERSHIP_UPDATE   = 5,
	AMT_TYPE_MULTICAST_DATA      = 6,
	AMT_TYPE_TEARDOWN            = 7
};

struct amt_gateway {
	int sock;

	struct sockaddr_storage relay_disc; /* where Discovery/initial msgs go */
	socklen_t relay_disc_len;

	struct sockaddr_storage relay_tunnel; /* relay's tunnel endpoint, learned
	                                          from Relay Advertisement */
	socklen_t relay_tunnel_len;

	struct sockaddr_storage group;
	socklen_t group_len;
	struct sockaddr_storage source;
	socklen_t source_len;
	int ssm;

	uint32_t request_nonce;
	uint8_t response_mac[6];
	int have_mac;

	uint32_t query_interval_sec; /* from the relay's QQIC, or a
	                                 conservative default until learned */
	time_t refresh_deadline;     /* when to next call amt_gateway_timeout() */

	struct sockaddr_storage local_addr; /* our address as seen reaching the
	                                        relay; lazily determined, used as
	                                        the IP source when encapsulating
	                                        the Membership Update's IGMPv3
	                                        report (see determine_local_addr()) */
	socklen_t local_addr_len;
};

static uint32_t rand32(void) {
	uint32_t v;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, &v, sizeof(v));
		close(fd);
		if (n == (ssize_t)sizeof(v))
			return v;
	}

	/* Fallback if /dev/urandom can't be opened/read (e.g. a chroot/sandbox
	 * without /dev): rand()-based nonce is weaker (predictable seed/PRNG)
	 * but still avoids accidental collisions/replay within a session. */
	v = (uint32_t)rand();
	v = (v << 16) ^ (uint32_t)rand();
	return v;
}

static void put32(uint8_t *p, uint32_t v) {
	v = htonl(v);
	memcpy(p, &v, 4);
}

static uint32_t get32(const uint8_t *p) {
	uint32_t v;
	memcpy(&v, p, 4);
	return ntohl(v);
}

static uint16_t get16(const uint8_t *p) {
	uint16_t v;
	memcpy(&v, p, 2);
	return ntohs(v);
}

static void put16(uint8_t *p, uint16_t v) {
	v = htons(v);
	memcpy(p, &v, 2);
}

static int sockaddr_family(const struct sockaddr *sa) {
	return sa->sa_family;
}

static const void *addr_bytes(const struct sockaddr *sa, int *len) {
	if (sa->sa_family == AF_INET) {
		*len = 4;
		return &((const struct sockaddr_in *)sa)->sin_addr;
	} else if (sa->sa_family == AF_INET6) {
		*len = 16;
		return &((const struct sockaddr_in6 *)sa)->sin6_addr;
	}
	*len = 0;
	return NULL;
}

/* Standard Internet checksum (RFC 1071): 16-bit one's complement sum. */
static uint16_t checksum16(const void *data, size_t len) {
	const uint8_t *p = (const uint8_t *)data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += ((uint32_t)p[0] << 8) | p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (uint32_t)p[0] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static void sockaddr_set_port(struct sockaddr_storage *ss, uint16_t port) {
	if (ss->ss_family == AF_INET)
		((struct sockaddr_in *)ss)->sin_port = htons(port);
	else if (ss->ss_family == AF_INET6)
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
}

/*
 * Decodes an IGMPv3/MLDv2 QQIC byte into a Query Interval in seconds, per
 * RFC 3376 4.1.7 / RFC 3810 5.1.9's shared floating-point encoding: values
 * below 128 are the interval directly; 128 and above pack an exponent and
 * mantissa (top bit always set).
 */
static int decode_qqic(uint8_t qqic) {
	if (qqic < 128)
		return qqic;

	int exp = (qqic >> 4) & 0x7;
	int mant = qqic & 0xf;
	return (mant | 0x10) << (exp + 3);
}

/*
 * Extracts the Query Interval (seconds) from the IGMPv3/MLDv2 General
 * Query that RFC 7450 says a Membership Query carries after the Request
 * Nonce - and after the optional Gateway Port/Address, present when the G
 * flag (rbuf[1] bit 7) is set, skipped here by length only since its
 * contents aren't otherwise used. 'relay_family' sizes that optional
 * Gateway Address field (AF_INET6 -> 16 bytes, else 4); 'group_family'
 * selects whether to expect an encapsulated IGMPv3 (AF_INET) or MLDv2
 * (AF_INET6) query, matching the P flag the gateway sent in its Request.
 *
 * Returns the interval in seconds, or -1 if the message is too short or
 * doesn't look like a well-formed General Query - callers should fall back
 * to a previously-known or conservative default in that case.
 */
static int parse_query_interval(const uint8_t *rbuf, size_t n, int relay_family, int group_family) {
	size_t off = 12;

	if (n < off)
		return -1;

	if (rbuf[1] & 0x80) { /* G flag: Gateway Port(2) + Gateway Address follow */
		size_t galen = (relay_family == AF_INET6) ? 16 : 4;
		off += 2 + galen;
		if (n < off)
			return -1;
	}

	const uint8_t *pkt = rbuf + off;
	size_t len = n - off;

	if (group_family == AF_INET6) {
		if (len < 40 || pkt[6] != 58 /* Next Header: ICMPv6 */)
			return -1;

		const uint8_t *icmp = pkt + 40;
		size_t icmplen = len - 40;
		if (icmplen < 28 || icmp[0] != 130 /* MLD Query */)
			return -1;

		return decode_qqic(icmp[25]);
	} else {
		if (len < 20)
			return -1;

		int ihl = (pkt[0] & 0xf) * 4;
		if (ihl < 20 || len < (size_t)ihl + 12 || pkt[9] != 2 /* IGMP */)
			return -1;

		const uint8_t *igmp = pkt + ihl;
		if (igmp[0] != 0x11 /* Membership Query */)
			return -1;

		return decode_qqic(igmp[9]);
	}
}

/*
 * Determines the local address to use as the IP source when encapsulating
 * the Membership Update's IGMPv3 report (see build_membership_report()):
 * connect()s a throwaway UDP socket to the relay's tunnel endpoint and
 * reads back what the kernel picked as the outgoing source address, the
 * same trick a reference Python implementation of this protocol uses
 * (probe.connect() + getsockname()). Idempotent: a no-op once already
 * determined. Returns 0 on success, -1 on failure (errno set).
 */
static int determine_local_addr(amt_gateway_t *gw) {
	if (gw->local_addr_len != 0)
		return 0;

	int s = socket(sockaddr_family((const struct sockaddr *)&gw->relay_tunnel), SOCK_DGRAM, 0);
	if (s < 0)
		return -1;

	if (connect(s, (const struct sockaddr *)&gw->relay_tunnel, gw->relay_tunnel_len) != 0) {
		close(s);
		return -1;
	}

	socklen_t len = sizeof(gw->local_addr);
	if (getsockname(s, (struct sockaddr *)&gw->local_addr, &len) != 0) {
		close(s);
		return -1;
	}
	gw->local_addr_len = len;
	close(s);
	return 0;
}

/*
 * Builds a minimal IGMPv3 (AF_INET) or MLDv2 (AF_INET6) Membership Report
 * carrying a single multicast address record for 'gw's joined channel.
 * Returns the number of bytes written, or -1 if it doesn't fit in 'buf'.
 */
static int build_membership_report(struct amt_gateway *gw, uint8_t *buf, size_t buflen) {
	int family = gw->group_len ? sockaddr_family((const struct sockaddr *)&gw->group) : AF_INET;
	int alen = (family == AF_INET6) ? 16 : 4;
	int numsrc = gw->ssm ? 1 : 0;
	uint8_t rec_type = gw->ssm ? 1 /* MODE_IS_INCLUDE */ : 2 /* MODE_IS_EXCLUDE */;

	if (family == AF_INET) {
		/* IGMPv3 Membership Report:
		 * type(1) reserved(1) checksum(2) reserved(2) numgroups(2)
		 * then one Group Record: rec_type(1) auxlen(1)=0 numsrc(2)
		 *                        group(4) source[numsrc](4 each)
		 */
		uint8_t report[8 + 8 + 4];
		size_t rlen = 8 + 8 + (size_t)numsrc * 4;

		memset(report, 0, rlen);
		report[0] = 0x22; /* IGMP Membership Report v3 */
		put16(report + 6, 1); /* Number of Group Records */

		uint8_t *rec = report + 8;
		rec[0] = rec_type;
		rec[1] = 0; /* Aux Data Len */
		put16(rec + 2, (uint16_t)numsrc);

		int glen;
		const void *gbytes = addr_bytes((const struct sockaddr *)&gw->group, &glen);
		memcpy(rec + 4, gbytes, glen);

		if (numsrc) {
			int slen;
			const void *sbytes = addr_bytes((const struct sockaddr *)&gw->source, &slen);
			memcpy(rec + 4 + alen, sbytes, slen);
		}

		put16(report + 2, checksum16(report, rlen));

		/*
		 * RFC 7450 5.1.5 says this field carries "a valid IGMPv3 ...
		 * protocol message" - for IGMPv3 (RFC 3376) that means the
		 * full IP-encapsulated packet (source/destination addresses,
		 * protocol, Router Alert option, TTL 1), not just the bare
		 * group-record bytes above. A relay that actually validates
		 * that framing silently drops an Update that omits it: the
		 * handshake (Discovery/Request/Query) still completes, since
		 * none of that involves this field, but the join itself never
		 * registers and no data ever follows. Encapsulate exactly as
		 * a real IGMPv3 report would arrive on the wire, destined to
		 * 224.0.0.22 ("all IGMPv3-capable multicast routers", RFC
		 * 3376 4.2.14).
		 */
		if (determine_local_addr(gw) != 0)
			return -1;

		size_t iplen = 24 + rlen; /* 20-byte header + 4-byte Router Alert option */
		if (buflen < iplen)
			return -1;

		uint8_t *ip = buf;
		memset(ip, 0, 24);
		ip[0] = 0x46; /* version 4, IHL 6 (24 bytes, incl. Router Alert) */
		ip[1] = 0xc0; /* DSCP/ECN: matches common IGMP control-traffic marking */
		put16(ip + 2, (uint16_t)iplen);
		put16(ip + 4, (uint16_t)rand32()); /* identification */
		ip[8] = 1;  /* TTL: IGMP reports never leave the local network */
		ip[9] = 2;  /* protocol: IGMP */
		/* ip[10..11] (header checksum) filled in below, once complete */
		int llen;
		const void *lbytes = addr_bytes((const struct sockaddr *)&gw->local_addr, &llen);
		memcpy(ip + 12, lbytes, llen);
		{
			struct in_addr dst;
			inet_pton(AF_INET, "224.0.0.22", &dst);
			memcpy(ip + 16, &dst, 4);
		}
		ip[20] = 0x94; ip[21] = 0x04; ip[22] = 0x00; ip[23] = 0x00; /* Router Alert option */
		put16(ip + 10, checksum16(ip, 24));

		memcpy(ip + 24, report, rlen);
		return (int)iplen;
	} else {
		/* MLDv2 Report (ICMPv6 type 143):
		 * type(1)=143 reserved(1) checksum(2) reserved(2) numrecords(2)
		 * then one Multicast Address Record: rec_type(1) auxlen(1)=0
		 *   numsrc(2) group(16) source[numsrc](16 each)
		 */
		size_t need = 8 + (4 + 16) + (size_t)numsrc * 16;
		if (buflen < need)
			return -1;

		memset(buf, 0, need);
		buf[0] = 143;
		put16(buf + 6, 1);

		uint8_t *rec = buf + 8;
		rec[0] = rec_type;
		rec[1] = 0;
		put16(rec + 2, (uint16_t)numsrc);

		int glen;
		const void *gbytes = addr_bytes((const struct sockaddr *)&gw->group, &glen);
		memcpy(rec + 4, gbytes, glen);

		if (numsrc) {
			int slen;
			const void *sbytes = addr_bytes((const struct sockaddr *)&gw->source, &slen);
			memcpy(rec + 4 + 16, sbytes, slen);
		}

		/* Unlike the IGMPv3/AF_INET case above, this is NOT wrapped in an
		 * IPv6+Router Alert+ICMPv6-checksummed packet the way a real MLDv2
		 * report would be (RFC 3810) - the same defect that made the
		 * IGMPv3 path fail against a relay that validates the framing
		 * (see the comment there) most likely also affects this path, but
		 * it is unverified: there is no MLDv2/IPv6 relay this has been
		 * tested against, and no reference implementation to check the
		 * fix against, so it is left as-is pending an IPv6 test case. */
		return (int)need;
	}
}

static int send_membership_update(amt_gateway_t *gw) {
	uint8_t buf[96]; /* header(12) + IP-encapsulated IGMPv3 report (<= 44) */
	int off = 0;

	/* header is 2 bytes (V|Type, then Reserved); the 48-bit Response MAC
	 * immediately follows, then the 32-bit Request Nonce - see RFC 7450
	 * Figure 15. */
	buf[off++] = (0 << 4) | AMT_TYPE_MEMBERSHIP_UPDATE;
	buf[off++] = 0;

	memcpy(buf + off, gw->response_mac, 6);
	off += 6;

	put32(buf + off, gw->request_nonce);
	off += 4;

	int n = build_membership_report(gw, buf + off, sizeof(buf) - off);
	if (n < 0)
		return -1;
	off += n;

	return sendto(gw->sock, buf, off, 0,
	              (const struct sockaddr *)&gw->relay_tunnel, gw->relay_tunnel_len) == off ? 0 : -1;
}

static int wait_readable(int sock, int timeout_ms) {
	struct timeval tv;
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	return select(sock + 1, &rfds, NULL, NULL, &tv);
}

amt_gateway_t *amt_gateway_open(const struct sockaddr *relay, socklen_t relay_len,
                                  const struct sockaddr *group, socklen_t group_len,
                                  const struct sockaddr *source, socklen_t source_len,
                                  int ssm, int timeout_ms, int retries) {
	amt_gateway_t *gw = (amt_gateway_t *)calloc(1, sizeof(*gw));
	if (!gw)
		return NULL;

	gw->sock = -1;
	gw->ssm = ssm;
	gw->query_interval_sec = AMT_DEFAULT_QUERY_INTERVAL_SEC;

	memcpy(&gw->group, group, group_len);
	gw->group_len = group_len;

	if (ssm) {
		if (!source || !source_len) {
			errno = EINVAL;
			goto fail;
		}
		memcpy(&gw->source, source, source_len);
		gw->source_len = source_len;
	}

	memcpy(&gw->relay_disc, relay, relay_len);
	gw->relay_disc_len = relay_len;
	if (((struct sockaddr_storage *)&gw->relay_disc)->ss_family == AF_INET) {
		if (((struct sockaddr_in *)&gw->relay_disc)->sin_port == 0)
			sockaddr_set_port(&gw->relay_disc, AMT_PORT);
	} else if (((struct sockaddr_storage *)&gw->relay_disc)->ss_family == AF_INET6) {
		if (((struct sockaddr_in6 *)&gw->relay_disc)->sin6_port == 0)
			sockaddr_set_port(&gw->relay_disc, AMT_PORT);
	}

	gw->sock = socket(sockaddr_family(relay), SOCK_DGRAM, 0);
	if (gw->sock < 0)
		goto fail;

	srand((unsigned int)(time(NULL) ^ getpid()));

	uint8_t sbuf[1500];
	uint8_t rbuf[1500];
	uint32_t disc_nonce = rand32();
	int attempt;

	/* Step 1: Relay Discovery -> Relay Advertisement */
	for (attempt = 0; attempt <= retries; attempt++) {
		sbuf[0] = (0 << 4) | AMT_TYPE_RELAY_DISCOVERY;
		sbuf[1] = sbuf[2] = sbuf[3] = 0;
		put32(sbuf + 4, disc_nonce);

		if (sendto(gw->sock, sbuf, 8, 0, (const struct sockaddr *)&gw->relay_disc,
		           gw->relay_disc_len) != 8)
			goto fail;

		if (wait_readable(gw->sock, timeout_ms) <= 0)
			continue;

		ssize_t n = recv(gw->sock, rbuf, sizeof(rbuf), 0);
		if (n < 12)
			continue;
		if ((rbuf[0] >> 4) != 0 || (rbuf[0] & 0xf) != AMT_TYPE_RELAY_ADVERTISEMENT)
			continue;
		if (get32(rbuf + 4) != disc_nonce)
			continue;

		int alen = (int)n - 8;
		memset(&gw->relay_tunnel, 0, sizeof(gw->relay_tunnel));
		if (alen == 4) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&gw->relay_tunnel;
			sin->sin_family = AF_INET;
			memcpy(&sin->sin_addr, rbuf + 8, 4);
			sin->sin_port = htons(AMT_PORT);
			gw->relay_tunnel_len = sizeof(*sin);
		} else if (alen == 16) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&gw->relay_tunnel;
			sin6->sin6_family = AF_INET6;
			memcpy(&sin6->sin6_addr, rbuf + 8, 16);
			sin6->sin6_port = htons(AMT_PORT);
			gw->relay_tunnel_len = sizeof(*sin6);
		} else {
			continue;
		}
		break;
	}

	if (gw->relay_tunnel_len == 0) {
		errno = ETIMEDOUT;
		goto fail;
	}

	/* Step 2: Request -> Membership Query */
	gw->request_nonce = rand32();

	for (attempt = 0; attempt <= retries; attempt++) {
		/* header is 4 bytes: V|Type, then Reserved(7 bits)|P(LSB of byte1),
		 * then 16 further reserved bits - see RFC 7450 Figure 13. */
		sbuf[0] = (0 << 4) | AMT_TYPE_REQUEST;
		sbuf[1] = sockaddr_family((const struct sockaddr *)&gw->group) == AF_INET6 ? 1 : 0;
		sbuf[2] = 0;
		sbuf[3] = 0;
		put32(sbuf + 4, gw->request_nonce);

		if (sendto(gw->sock, sbuf, 8, 0, (const struct sockaddr *)&gw->relay_tunnel,
		           gw->relay_tunnel_len) != 8)
			goto fail;

		if (wait_readable(gw->sock, timeout_ms) <= 0)
			continue;

		struct sockaddr_storage from;
		socklen_t fromlen = sizeof(from);
		ssize_t n = recvfrom(gw->sock, rbuf, sizeof(rbuf), 0,
		                      (struct sockaddr *)&from, &fromlen);
		/* header is 2 bytes (V|Type, then Reserved|L|G); the 48-bit
		 * Response MAC occupies bytes 2-7, the 32-bit Request Nonce
		 * bytes 8-11 - see RFC 7450 Figure 14. */
		if (n < 12)
			continue;
		if ((rbuf[0] >> 4) != 0 || (rbuf[0] & 0xf) != AMT_TYPE_MEMBERSHIP_QUERY)
			continue;
		if (get32(rbuf + 8) != gw->request_nonce)
			continue;

		memcpy(gw->response_mac, rbuf + 2, 6);
		gw->have_mac = 1;

		int relay_family = ((const struct sockaddr_storage *)&gw->relay_tunnel)->ss_family;
		int group_family = sockaddr_family((const struct sockaddr *)&gw->group);
		int qi = parse_query_interval(rbuf, (size_t)n, relay_family, group_family);
		gw->query_interval_sec = (qi > 0) ? (uint32_t)qi : AMT_DEFAULT_QUERY_INTERVAL_SEC;
		gw->refresh_deadline = time(NULL) + (time_t)gw->query_interval_sec;
		break;
	}

	if (!gw->have_mac) {
		errno = ETIMEDOUT;
		goto fail;
	}

	/* Step 3: send the initial Membership Update (join) */
	if (send_membership_update(gw) != 0)
		goto fail;

	return gw;

fail:
	if (gw->sock >= 0)
		close(gw->sock);
	free(gw);
	return NULL;
}

int amt_gateway_fd(const amt_gateway_t *gw) {
	return gw->sock;
}

int amt_gateway_next_timeout_ms(const amt_gateway_t *gw) {
	time_t now = time(NULL);
	double diff = difftime(gw->refresh_deadline, now);

	if (diff <= 0)
		return 0;
	if (diff > (double)(INT_MAX / 1000))
		return INT_MAX;

	return (int)(diff * 1000.0);
}

int amt_gateway_timeout(amt_gateway_t *gw) {
	uint8_t sbuf[8];

	gw->request_nonce = rand32();

	/* header is 4 bytes: V|Type, then Reserved(7 bits)|P(LSB of byte1),
	 * then 16 further reserved bits - see RFC 7450 Figure 13. Same shape
	 * as the initial Request in amt_gateway_open(): this restarts the
	 * three-way handshake (Request -> Membership Query -> Membership
	 * Update) to refresh membership state at the relay, per RFC 7450's
	 * use of the relay-advertised Query Interval (QQIC) rather than
	 * relying on the relay to send an unsolicited refresh Query. */
	sbuf[0] = (0 << 4) | AMT_TYPE_REQUEST;
	sbuf[1] = sockaddr_family((const struct sockaddr *)&gw->group) == AF_INET6 ? 1 : 0;
	sbuf[2] = 0;
	sbuf[3] = 0;
	put32(sbuf + 4, gw->request_nonce);
	
	/* Re-arm immediately so a lost Request/Query doesn't silently wedge
	 * this until the full interval elapses again; refined further once a
	 * fresh Membership Query actually arrives (amt_gateway_recv() above
	 * reschedules from the relay's own QQIC at that point). */
	gw->refresh_deadline = time(NULL) + (time_t)gw->query_interval_sec;

	if (sendto(gw->sock, sbuf, 8, 0, (const struct sockaddr *)&gw->relay_tunnel,
	           gw->relay_tunnel_len) != 8)
		return -1;

	return 0;
}

int amt_gateway_query_interval_sec(const amt_gateway_t *gw) {
    return (int)gw->query_interval_sec;
}

/* Sets errno to 'err' and returns -1, for parse_encapsulated_udp(). */
static ssize_t parse_fail(int err) {
	errno = err;
	return -1;
}

/* Parses an encapsulated IPv4/IPv6+UDP packet (as delivered inside an AMT
 * Multicast Data message) and extracts source/destination/ttl and the
 * inner UDP payload. Returns the payload length, or -1 with errno set to
 * EBADMSG if the packet is malformed / truncated, or EPROTONOSUPPORT if it
 * is not UDP (or an unsupported IP version / IPv6 extension header). */
static ssize_t parse_encapsulated_udp(const uint8_t *pkt, size_t len,
                                        struct sockaddr_storage *from, socklen_t *from_len,
                                        struct sockaddr_storage *to, socklen_t *to_len,
                                        int *ttl, uint8_t *buf, size_t buflen) {
	if (len < 1)
		return parse_fail(EBADMSG);

	int version = pkt[0] >> 4;

	if (version == 4) {
		if (len < 20)
			return parse_fail(EBADMSG);
		int ihl = (pkt[0] & 0xf) * 4;
		if ((size_t)ihl < 20 || len < (size_t)ihl + 8)
			return parse_fail(EBADMSG);
		if (pkt[9] != 17) /* not UDP */
			return parse_fail(EPROTONOSUPPORT);

		int iplen = get16(pkt + 2);
		if ((size_t)iplen > len)
			iplen = (int)len;

		int hoplimit = pkt[8];

		struct sockaddr_in src, dst;
		memset(&src, 0, sizeof(src));
		memset(&dst, 0, sizeof(dst));
		src.sin_family = dst.sin_family = AF_INET;
		memcpy(&src.sin_addr, pkt + 12, 4);
		memcpy(&dst.sin_addr, pkt + 16, 4);

		const uint8_t *udp = pkt + ihl;
		if ((size_t)(udp - pkt) + 8 > (size_t)iplen)
			return parse_fail(EBADMSG);

		src.sin_port = htons(get16(udp + 0));
		dst.sin_port = htons(get16(udp + 2));

		int udplen = get16(udp + 4);
		if (udplen < 8)
			return parse_fail(EBADMSG);
		size_t paylen = (size_t)udplen - 8;
		if ((size_t)(udp - pkt) + (size_t)udplen > (size_t)iplen)
			paylen = (size_t)iplen - (udp - pkt) - 8;

		if (paylen > buflen)
			paylen = buflen;

		memcpy(buf, udp + 8, paylen);

		memcpy(from, &src, sizeof(src));
		*from_len = sizeof(src);
		memcpy(to, &dst, sizeof(dst));
		*to_len = sizeof(dst);
		*ttl = hoplimit;

		return (ssize_t)paylen;
	} else if (version == 6) {
		if (len < 40)
			return parse_fail(EBADMSG);
		if (pkt[6] != 17) /* Next Header must be UDP (no extension headers handled) */
			return parse_fail(EPROTONOSUPPORT);

		int payload_len = get16(pkt + 4);
		int hoplimit = pkt[7];

		struct sockaddr_in6 src, dst;
		memset(&src, 0, sizeof(src));
		memset(&dst, 0, sizeof(dst));
		src.sin6_family = dst.sin6_family = AF_INET6;
		memcpy(&src.sin6_addr, pkt + 8, 16);
		memcpy(&dst.sin6_addr, pkt + 24, 16);

		const uint8_t *udp = pkt + 40;
		size_t avail = len - 40;
		if (avail < 8 || (size_t)payload_len < 8)
			return parse_fail(EBADMSG);

		src.sin6_port = htons(get16(udp + 0));
		dst.sin6_port = htons(get16(udp + 2));

		int udplen = get16(udp + 4);
		if (udplen < 8)
			return parse_fail(EBADMSG);
		size_t paylen = (size_t)udplen - 8;
		if (paylen > avail - 8)
			paylen = avail - 8;

		if (paylen > buflen)
			paylen = buflen;

		memcpy(buf, udp + 8, paylen);

		memcpy(from, &src, sizeof(src));
		*from_len = sizeof(src);
		memcpy(to, &dst, sizeof(dst));
		*to_len = sizeof(dst);
		*ttl = hoplimit;

		return (ssize_t)paylen;
	}

	return parse_fail(EPROTONOSUPPORT);
}

ssize_t amt_gateway_recv(amt_gateway_t *gw,
                           struct sockaddr_storage *from, socklen_t *from_len,
                           struct sockaddr_storage *to, socklen_t *to_len,
                           int *ttl, uint8_t *buf, size_t buflen) {
	uint8_t rbuf[9000];
	struct sockaddr_storage src;
	socklen_t srclen = sizeof(src);

	ssize_t n = recvfrom(gw->sock, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&src, &srclen);
	if (n < 0)
		return -1;
	if (n < 4)
		return 0;

	if ((rbuf[0] >> 4) != 0)
		return 0;

	int type = rbuf[0] & 0xf;

	if (type == AMT_TYPE_MULTICAST_DATA) {
		/* Header is 2 bytes (V|Type, then Reserved), same shape as every
		 * other AMT message here - NOT 4, despite what an earlier reading
		 * of RFC 7450's Figure 16 concluded (see amt.md's design notes).
		 * Confirmed against a real relay's live traffic (GEANT,
		 * 62.40.96.44/41): byte 2 of the datagram is already 0x45
		 * (IPv4, IHL 5), and the IP header's Total Length field equals
		 * n - 2 exactly, not n - 4. This code path was never exercised
		 * against real traffic before now - a *different* bug (the
		 * Membership Update lacking IP encapsulation, see
		 * build_membership_report()) meant no relay ever accepted the
		 * join for real, so no genuine Multicast Data message had ever
		 * reached this function until both bugs were found together. */
		if (n < 2)
			return 0;
		return parse_encapsulated_udp(rbuf + 2, (size_t)n - 2,
		                                from, from_len, to, to_len, ttl, buf, buflen);
	}

	if (type == AMT_TYPE_MEMBERSHIP_QUERY) {
		if (n < 12)
			return 0;

		uint32_t nonce = get32(rbuf + 8);
		if (nonce != gw->request_nonce)
			return 0;

		memcpy(gw->response_mac, rbuf + 2, 6);
		gw->have_mac = 1;

		int relay_family = ((const struct sockaddr_storage *)&gw->relay_tunnel)->ss_family;
		int group_family = sockaddr_family((const struct sockaddr *)&gw->group);
		int qi = parse_query_interval(rbuf, (size_t)n, relay_family, group_family);
		gw->query_interval_sec = (qi > 0) ? (uint32_t)qi : gw->query_interval_sec;
		gw->refresh_deadline = time(NULL) + (time_t)gw->query_interval_sec;

		send_membership_update(gw);
		return 0;
	}

	/* Any other control message (stray Advertisement, etc.) is ignored. */
	return 0;
}

void amt_gateway_close(amt_gateway_t *gw) {
	if (!gw)
		return;

	if (gw->sock >= 0) {
		uint8_t buf[8];
		buf[0] = (0 << 4) | AMT_TYPE_TEARDOWN;
		buf[1] = buf[2] = buf[3] = 0;
		put32(buf + 4, gw->request_nonce);
		sendto(gw->sock, buf, 8, 0, (const struct sockaddr *)&gw->relay_tunnel, gw->relay_tunnel_len);

		close(gw->sock);
	}

	free(gw);
}
