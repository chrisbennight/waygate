//! Network-address classification shared by outbound request guards.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// True when an address is globally routable unicast rather than loopback,
/// link-local, private, shared, reserved, multicast, or unspecified space.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.octets()[0] == 0
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || is_shared_v4(v4)
                || is_protocol_assignment_v4(v4)
                || is_benchmarking_v4(v4)
                || is_reserved_v4(v4))
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            if let Some(v4) = translated_ipv4(v6) {
                return is_public_ip(&IpAddr::V4(v4));
            }
            let segments = v6.segments();
            if is_ipv4_compatible_v6(v6)
                || is_ipv4_mapped_v6(v6)
                || matches!(segments, [0x64, 0xff9b, 1, _, _, _, _, _])
                || matches!(segments, [0x100, 0, 0, 0, _, _, _, _])
                || is_non_public_ietf_assignment_v6(v6)
                || matches!(segments, [0x2002, _, _, _, _, _, _, _])
                || is_documentation_v6(v6)
                || matches!(segments, [0x5f00, ..])
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
            {
                return false;
            }
            true
        }
    }
}

fn is_shared_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn is_protocol_assignment_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 192 && octets[1] == 0 && octets[2] == 0 && octets[3] != 9 && octets[3] != 10
}

fn is_benchmarking_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
}

fn is_reserved_v4(ip: &Ipv4Addr) -> bool {
    ip.octets()[0] >= 240
}

fn is_ipv4_mapped_v6(ip: &Ipv6Addr) -> bool {
    matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
}

/// The deprecated IPv4-compatible block `::/96` (`::a.b.c.d`). Nothing in it is
/// globally routable, and `to_ipv4_mapped` does not recognise it — it matches
/// only `::ffff:0:0/96` — so without this an address like `::7f00:1` would
/// classify as public while naming 127.0.0.1 to any stack that still honours
/// the form.
fn is_ipv4_compatible_v6(ip: &Ipv6Addr) -> bool {
    matches!(ip.segments(), [0, 0, 0, 0, 0, 0, _, _])
}

fn translated_ipv4(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if !matches!(
        segments,
        [0x64, 0xff9b, 0, 0, 0, 0, _, _] | [0, 0, 0, 0, 0xffff, 0, _, _]
    ) {
        return None;
    }
    let octets = ip.octets();
    Some(Ipv4Addr::new(
        octets[12], octets[13], octets[14], octets[15],
    ))
}

fn is_non_public_ietf_assignment_v6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    if !matches!(segments, [0x2001, second, _, _, _, _, _, _] if second < 0x200) {
        return false;
    }
    let value = u128::from_be_bytes(ip.octets());
    let public_exception = value == 0x2001_0001_0000_0000_0000_0000_0000_0001
        || value == 0x2001_0001_0000_0000_0000_0000_0000_0002
        || matches!(segments, [0x2001, 3, _, _, _, _, _, _])
        || matches!(segments, [0x2001, 4, 0x112, _, _, _, _, _])
        || matches!(segments, [0x2001, second, _, _, _, _, _, _] if (0x20..=0x3f).contains(&second));
    !public_exception
}

fn is_documentation_v6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    matches!(segments, [0x2001, 0x0db8, _, _, _, _, _, _]) || (segments[0] & 0xfff0) == 0x3ff0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn blocks_non_public_address_ranges() {
        for address in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(192, 0, 0, 8),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
        ] {
            assert!(!is_public_ip(&IpAddr::V4(address)), "{address}");
        }
        assert!(is_public_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(is_public_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 0, 9))));
        assert!(is_public_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 0, 10))));
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1,
        ))));
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1,
        ))));
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,
        ))));
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0x64, 0xff9b, 1, 0, 0, 0, 0, 1,
        ))));
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0x100, 0, 0, 0, 0, 0, 0, 1,
        ))));
        for address in [
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x7f00, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0x7f00, 1),
        ] {
            assert!(!is_public_ip(&IpAddr::V6(address)), "{address}");
        }
        for address in [
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0101, 0x0101),
            Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0x0101, 0x0101),
        ] {
            assert!(is_public_ip(&IpAddr::V6(address)), "{address}");
        }
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2002, 0, 0, 0, 0, 0, 0, 1,
        ))));
        // Deprecated IPv4-compatible `::a.b.c.d` (RFC 4291 §2.5.5). Nothing in
        // `::/96` is globally routable, and `to_ipv4_mapped` does not recognise
        // the form — it matches only `::ffff:0:0/96` — so without an explicit
        // rule `::7f00:1` would classify as public while naming 127.0.0.1.
        for address in [
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x7f00, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0a00, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0101, 0x0101),
        ] {
            assert!(!is_public_ip(&IpAddr::V6(address)), "{address}");
        }
        assert!(!is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0x3fff, 0, 0, 0, 0, 0, 0, 1,
        ))));
        assert!(is_public_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 1,
        ))));
    }
}
