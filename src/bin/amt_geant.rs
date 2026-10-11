use std::mem;
use std::net::Ipv4Addr;
use std::process::exit;

use libamt::*;

fn fail(why: &str) -> ! {
    eprintln!("FAIL: {why}");
    exit(1);
}

fn sockaddr_in_from(
    ip: &str, port: Option<u16>, what: &str,
) -> libc::sockaddr_in {
    let ip: Ipv4Addr = ip.parse().unwrap_or_else(|_| fail(what));

    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from(ip).to_be();

    if let Some(port_nbr) = port {
        sin.sin_port = port_nbr;
    }
    sin
}

fn ipv4_of(ss: &sockaddr_storage) -> Ipv4Addr {
    let sin =
        unsafe { &*(ss as *const sockaddr_storage as *const libc::sockaddr_in) };
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
    let relay_ip = "62.40.96.44";
    let source_ip = "193.190.248.24";
    let group_ip = "239.239.239.35";

    let relay = sockaddr_in_from(relay_ip, None, "bad relay IP");
    let source = sockaddr_in_from(source_ip, None, "bad source IP");
    let group = sockaddr_in_from(group_ip, None, "bad group IP");
    let sin_len = mem::size_of::<libc::sockaddr_in>() as socklen_t;

    let gw = unsafe {
        amt_gateway_open(
            &relay as *const libc::sockaddr_in as *const sockaddr,
            sin_len,
            &group as *const libc::sockaddr_in as *const sockaddr,
            sin_len,
            &source as *const libc::sockaddr_in as *const sockaddr,
            sin_len,
            // ssm=
            1,
            // timeout_ms=
            1000,
            // retries=
            5,
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

    let af_inet = libc::AF_INET as sa_family_t;
    if r.from.ss_family != af_inet || r.to.ss_family != af_inet {
        fail("decapsulated address family mismatch");
    }
    let fromstr = ipv4_of(&r.from).to_string();
    let tostr = ipv4_of(&r.to).to_string();

    // the send.py script send the number of the current packet as big endian
    // unsigned long long (equivalent of u64 I guess)
    let packet_num = u64::from_be_bytes(
        payload
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .unwrap_or_else(|| {
                fail("didn't receive enough bytes to parse the packet number")
            }),
    );

    println!(
        "data OK: from={} to={} ttl={} len={} packet_num={}",
        fromstr,
        tostr,
        r.ttl,
        payload.len(),
        packet_num,
    );

    let ms = unsafe { amt_gateway_next_timeout_ms(gw) };
    println!("Time until next scheduled refresh: {ms}");

    unsafe { amt_gateway_close(gw) };
}
