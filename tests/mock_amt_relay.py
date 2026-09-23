#!/usr/bin/env python3
#
# Minimal AMT (RFC 7450) relay stand-in for testing the dbeacon amt.c
# gateway library. Speaks just enough of the protocol to complete the
# gateway handshake, accept a Membership Update, and push back one
# Multicast Data message plus one refresh Membership Query.
#
# Not a real relay: no forwarding, no multiple gateways, no security.
# Intended only to be driven by tests/run_netns_test.sh.

import socket
import struct
import sys

AMT_PORT = 2268


def build_multicast_data(src_ip, dst_ip, src_port, dst_port, payload, ttl=64):
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    ip_total_len = 20 + udp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 0, 0, ttl, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return bytes([6, 0, 0, 0]) + ip_hdr + udp_hdr + payload


def build_general_query(relay_ip, qqic, max_resp_code=100, qrv=2):
    # IGMPv3 general query (RFC 3376 4.1), no sources: type(1)=0x11,
    # max resp code(1), checksum(2)=0 (not verified by the gateway),
    # group address(4)=0.0.0.0 (general query), resv|s|qrv(1), qqic(1),
    # number of sources(2)=0.
    igmp = struct.pack("!BBHIBBH", 0x11, max_resp_code, 0, 0,
                        qrv & 0x7, qqic, 0)

    # IPv4 header with a Router Alert option (IHL=6 words/24 bytes),
    # matching what a real relay sends (see amt.md's field-layout notes):
    # TTL 1, protocol 2 (IGMP), destination 224.0.0.1.
    ihl_words = 6
    total_len = ihl_words * 4 + len(igmp)
    ver_ihl = (4 << 4) | ihl_words
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, 0, 0, 1, 2, 0,
        socket.inet_aton(relay_ip), socket.inet_aton("224.0.0.1"),
    )
    router_alert = bytes([0x94, 0x04, 0x00, 0x00])
    return ip_hdr + router_alert + igmp


def main():
    bind_addr = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    relay_addr = sys.argv[2] if len(sys.argv) > 2 else bind_addr
    data_src_ip = sys.argv[3] if len(sys.argv) > 3 else "198.51.100.7"
    group_ip = sys.argv[4] if len(sys.argv) > 4 else "232.1.2.3"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_addr, AMT_PORT))
    print(f"mock relay listening on {bind_addr}:{AMT_PORT}, "
          f"advertising {relay_addr}", flush=True)

    # Wire format below follows RFC 7450 Figures 13-15 exactly (confirmed
    # by counting bit columns against the ASCII diagrams, and cross-checked
    # against a packet capture from a real production relay,
    # 62.40.96.44/41, GEANT): the Response MAC is 48 bits (6 bytes) in both
    # the Membership Query and the Membership Update, occupying bytes 2-7
    # (i.e. right after a 2-byte header), with the 32-bit Request Nonce in
    # bytes 8-11 and the encapsulated message from byte 12 onward. The
    # Request message's P flag is the low-order bit of byte 1, not byte 3.
    mac = b"\x11\x22\x33\x44\x55\x66"
    refresh_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    sent_data_for = set()
    # Short QQIC on purpose so the netns test can observe a proactive,
    # gateway-scheduled refresh (amt_gateway_timeout()) within a few
    # seconds, instead of waiting out a realistic ~125s interval.
    query_interval_qqic = 5
    request_count = 0

    while True:
        data, addr = sock.recvfrom(4096)
        if len(data) < 4:
            continue

        msg_type = data[0] & 0xf

        if msg_type == 1:  # Relay Discovery
            nonce = data[4:8]
            resp = bytes([2, 0, 0, 0]) + nonce + socket.inet_aton(relay_addr)
            sock.sendto(resp, addr)
            print(f"discovery from {addr}, nonce={nonce.hex()}", flush=True)

        elif msg_type == 3:  # Request
            request_count += 1
            nonce = data[4:8]
            general_query = build_general_query(relay_addr, query_interval_qqic)
            resp = bytes([4, 0]) + mac + nonce + general_query
            sock.sendto(resp, addr)
            print(f"request #{request_count} from {addr}, nonce={nonce.hex()}", flush=True)

        elif msg_type == 5:  # Membership Update
            resp_mac = data[2:8]
            nonce = data[8:12]
            report = data[12:]
            print(f"membership update from {addr}, mac={resp_mac.hex()} "
                  f"nonce={nonce.hex()} report={report.hex()}", flush=True)

            if addr not in sent_data_for:
                sent_data_for.add(addr)
                pkt = build_multicast_data(data_src_ip, group_ip, 5000, 10000,
                                            b"hello-amt-netns")
                sock.sendto(pkt, addr)
                print(f"sent multicast data to {addr}", flush=True)

                query = bytes([4, 0]) + refresh_mac + nonce
                sock.sendto(query, addr)
                print(f"sent refresh query to {addr}", flush=True)


if __name__ == "__main__":
    main()
