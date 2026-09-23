/*
 * Standalone test client for libamt (amt.c/amt.h), driven by
 * tests/run_netns_test.sh across a real Linux network namespace pair (so
 * the gateway and relay are genuinely separate network stacks reached over
 * an actual routed link, not loopback).
 *
 * Usage: test_amt_gateway <relay-ip> [group-ip] [expected-src-ip]
 *
 * Exits 0 and prints "PASS" iff the handshake, ASM join, decapsulated
 * Multicast Data payload/addresses, the auto-handled refresh Membership
 * Query, and a proactive QQIC-scheduled refresh (amt_gateway_timeout())
 * all check out. Exits 1 with a diagnostic otherwise.
 */

#include "amt.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/select.h>

static void fail(const char *why) {
	fprintf(stderr, "FAIL: %s\n", why);
	exit(1);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: %s <relay-ip> [group-ip] [expected-src-ip]\n", argv[0]);
		return 2;
	}

	const char *relay_ip = argv[1];
	const char *group_ip = argc > 2 ? argv[2] : "232.1.2.3";
	const char *expect_src_ip = argc > 3 ? argv[3] : "198.51.100.7";

	struct sockaddr_in relay, group;

	memset(&relay, 0, sizeof(relay));
	relay.sin_family = AF_INET;
	if (inet_pton(AF_INET, relay_ip, &relay.sin_addr) != 1)
		fail("bad relay IP");

	memset(&group, 0, sizeof(group));
	group.sin_family = AF_INET;
	if (inet_pton(AF_INET, group_ip, &group.sin_addr) != 1)
		fail("bad group IP");

	amt_gateway_t *gw = amt_gateway_open((struct sockaddr *)&relay, sizeof(relay),
	                                       (struct sockaddr *)&group, sizeof(group),
	                                       NULL, 0, /*ssm=*/0, /*timeout_ms=*/1000, /*retries=*/5);
	if (!gw)
		fail("amt_gateway_open() did not complete the handshake");

	printf("handshake OK, gateway fd=%d\n", amt_gateway_fd(gw));

	struct sockaddr_storage from, to;
	socklen_t fl = sizeof(from), tl = sizeof(to);
	int ttl = -1;
	uint8_t buf[256];

	ssize_t n = amt_gateway_recv(gw, &from, &fl, &to, &tl, &ttl, buf, sizeof(buf) - 1);
	if (n <= 0)
		fail("amt_gateway_recv() did not deliver the Multicast Data payload");

	buf[n] = 0;

	if (strcmp((char *)buf, "hello-amt-netns") != 0)
		fail("decapsulated payload mismatch");

	if (from.ss_family != AF_INET || to.ss_family != AF_INET)
		fail("decapsulated address family mismatch");

	char fromstr[64], tostr[64];
	inet_ntop(AF_INET, &((struct sockaddr_in *)&from)->sin_addr, fromstr, sizeof(fromstr));
	inet_ntop(AF_INET, &((struct sockaddr_in *)&to)->sin_addr, tostr, sizeof(tostr));

	if (strcmp(fromstr, expect_src_ip) != 0)
		fail("decapsulated source address mismatch");
	if (strcmp(tostr, group_ip) != 0)
		fail("decapsulated destination (group) address mismatch");
	if (ttl != 64)
		fail("decapsulated TTL mismatch");

	printf("data OK: from=%s to=%s ttl=%d payload=\"%s\"\n", fromstr, tostr, ttl, buf);

	/* The relay also queued a refresh Membership Query right behind the
	 * data message; it must be consumed internally (return 0, no data
	 * delivered to the caller) and trigger an automatic re-Update. */
	n = amt_gateway_recv(gw, &from, &fl, &to, &tl, &ttl, buf, sizeof(buf) - 1);
	if (n != 0)
		fail("refresh Membership Query was not handled transparently");

	printf("refresh handled OK\n");

	/* Proactive, gateway-scheduled refresh (amt_gateway_next_timeout_ms()/
	 * amt_gateway_timeout()): the mock relay hands out a short QQIC (5s)
	 * specifically so this can be exercised without a long sleep. Drive a
	 * minimal event loop until the internally-scheduled deadline fires,
	 * confirm amt_gateway_timeout() sends a fresh Request, then confirm
	 * amt_gateway_recv() transparently handles the relay's response. */
	int fd = amt_gateway_fd(gw);
	int refreshed = 0;

	for (int i = 0; i < 20 && !refreshed; i++) {
		int ms = amt_gateway_next_timeout_ms(gw);

		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };

		int r = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (r < 0)
			fail("select() failed while waiting for the scheduled refresh");

		if (r == 0) {
			if (amt_gateway_timeout(gw) != 0)
				fail("amt_gateway_timeout() failed to send the proactive Request");
			printf("proactive refresh: sent Request (deadline was due)\n");
			refreshed = 1;
			continue;
		}

		n = amt_gateway_recv(gw, &from, &fl, &to, &tl, &ttl, buf, sizeof(buf) - 1);
		if (n != 0)
			fail("unexpected data during proactive-refresh wait");
	}
	if (!refreshed)
		fail("amt_gateway_next_timeout_ms() never became due within 20 iterations");

	/* The relay answers our proactive Request with a fresh Membership
	 * Query; amt_gateway_recv() must consume it transparently as usual. */
	n = amt_gateway_recv(gw, &from, &fl, &to, &tl, &ttl, buf, sizeof(buf) - 1);
	if (n != 0)
		fail("proactive refresh's Membership Query response was not handled transparently");

	printf("proactive refresh handled OK\n");

	amt_gateway_close(gw);

	printf("PASS\n");
	return 0;
}
