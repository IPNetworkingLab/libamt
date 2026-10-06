//! Usage: test_amt_gateway <relay-ip> [group-ip] [expected-src-ip]

use std::mem;
use std::net::Ipv4Addr;
use std::process::exit;
use std::ptr;

use libamt::*;

fn fail(why: &str) -> ! {
    eprintln!("FAIL: {why}");
    exit(1);
}

fn sockaddr_in_from(ip: &str, what: &str) -> libc::sockaddr_in {
    let ip: Ipv4Addr = ip.parse().unwrap_or_else(|_| fail(what));

    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from(ip).to_be();
    sin
}

fn ipv4_of(ss: &sockaddr_storage) -> Ipv4Addr {
    let sin = unsafe { &*(ss as *const sockaddr_storage as *const libc::sockaddr_in) };
    Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))
}

struct Recv {
    from: sockaddr_storage,
    to: sockaddr_storage,
    ttl: i32,
    buf: [u8; 256],
}

impl Recv {
    fn new() -> Self {
        Recv {
            from: unsafe { mem::zeroed() },
            to: unsafe { mem::zeroed() },
            ttl: -1,
            buf: [0; 256],
        }
    }

    fn recv(&mut self, gw: *mut amt_gateway_t) -> isize {
        let mut fl = mem::size_of::<sockaddr_storage>() as socklen_t;
        let mut tl = mem::size_of::<sockaddr_storage>() as socklen_t;
        unsafe {
            amt_gateway_recv(
                gw,
                &mut self.from,
                &mut fl,
                &mut self.to,
                &mut tl,
                &mut self.ttl,
                self.buf.as_mut_ptr(),
                self.buf.len() - 1,
            )
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: {} <relay-ip> [group-ip] [expected-src-ip]",
            args[0]
        );
        eprintln!("SKIP: needs a relay; run via tests/run_netns_test.sh");
        return;
    }

    let relay_ip = args[1].as_str();
    let group_ip = args.get(2).map_or("232.1.2.3", String::as_str);
    let expect_src_ip = args.get(3).map_or("198.51.100.7", String::as_str);

    let relay = sockaddr_in_from(relay_ip, "bad relay IP");
    let group = sockaddr_in_from(group_ip, "bad group IP");
    let sin_len = mem::size_of::<libc::sockaddr_in>() as socklen_t;

    let gw = unsafe {
        amt_gateway_open(
            &relay as *const libc::sockaddr_in as *const sockaddr,
            sin_len,
            &group as *const libc::sockaddr_in as *const sockaddr,
            sin_len,
            ptr::null(),
            0,
            /* ssm= */ 0,
            /* timeout_ms= */ 1000,
            /* retries= */ 5,
        )
    };
    if gw.is_null() {
        fail("amt_gateway_open() did not complete the handshake");
    }

    println!("handshake OK, gateway fd={}", unsafe { amt_gateway_fd(gw) });

    let mut r = Recv::new();

    let n = r.recv(gw);
    if n <= 0 {
        fail("amt_gateway_recv() did not deliver the Multicast Data payload");
    }

    let payload = &r.buf[..n as usize];
    if payload != b"hello-amt-netns" {
        fail("decapsulated payload mismatch");
    }

    let af_inet = libc::AF_INET as sa_family_t;
    if r.from.ss_family != af_inet || r.to.ss_family != af_inet {
        fail("decapsulated address family mismatch");
    }

    let fromstr = ipv4_of(&r.from).to_string();
    let tostr = ipv4_of(&r.to).to_string();

    if fromstr != expect_src_ip {
        fail("decapsulated source address mismatch");
    }
    if tostr != group_ip {
        fail("decapsulated destination (group) address mismatch");
    }
    if r.ttl != 64 {
        fail("decapsulated TTL mismatch");
    }

    println!(
        "data OK: from={} to={} ttl={} payload=\"{}\"",
        fromstr,
        tostr,
        r.ttl,
        String::from_utf8_lossy(payload)
    );

    // The relay also queued a refresh Membership Query right behind the
    // data message; it must be consumed internally (return 0, no data
    // delivered to the caller) and trigger an automatic re-Update.
    if r.recv(gw) != 0 {
        fail("refresh Membership Query was not handled transparently");
    }

    println!("refresh handled OK");

    // Proactive, gateway-scheduled refresh (amt_gateway_next_timeout_ms()/
    // amt_gateway_timeout()): the mock relay hands out a short QQIC (5s)
    // specifically so this can be exercised without a long sleep. Drive a
    // minimal event loop until the internally-scheduled deadline fires,
    // confirm amt_gateway_timeout() sends a fresh Request, then confirm
    // amt_gateway_recv() transparently handles the relay's response.
    let fd = unsafe { amt_gateway_fd(gw) };
    let mut refreshed = false;

    for _ in 0..20 {
        let ms = unsafe { amt_gateway_next_timeout_ms(gw) };

        let rv = unsafe {
            let mut rfds: libc::fd_set = mem::zeroed();
            libc::FD_ZERO(&mut rfds);
            libc::FD_SET(fd, &mut rfds);
            let mut tv = libc::timeval {
                tv_sec: (ms / 1000) as libc::time_t,
                tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
            };

            libc::select(
                fd + 1,
                &mut rfds,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut tv,
            )
        };
        if rv < 0 {
            fail("select() failed while waiting for the scheduled refresh");
        }

        if rv == 0 {
            if unsafe { amt_gateway_timeout(gw) } != 0 {
                fail("amt_gateway_timeout() failed to send the proactive Request");
            }
            println!("proactive refresh: sent Request (deadline was due)");
            refreshed = true;
            break;
        }

        if r.recv(gw) != 0 {
            fail("unexpected data during proactive-refresh wait");
        }
    }
    if !refreshed {
        fail("amt_gateway_next_timeout_ms() never became due within 20 iterations");
    }

    // The relay answers our proactive Request with a fresh Membership
    // Query; amt_gateway_recv() must consume it transparently as usual.
    if r.recv(gw) != 0 {
        fail("proactive refresh's Membership Query response was not handled transparently");
    }

    println!("proactive refresh handled OK");

    unsafe { amt_gateway_close(gw) };

    println!("PASS");
}
