use axum::http::HeaderMap;
use std::net::IpAddr;

/// Resolves the effective client IP from the TCP peer address and proxy headers.
/// X-Forwarded-For => X-Real-IP => TCP peer address
/// When using `X-Real-IP`, the reverse proxy must overwrite (not append to / pass through).
pub fn resolve_client_ip(peer_ip: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> IpAddr {
	if trusted_proxies.contains(&peer_ip) {
		// Proxies may append X-Forwarded-For as a separate header line instead of
		// merging into a comma list; treat all instances as one appended chain and
		// walk it right-to-left so attacker-supplied leading values are ignored.
		if let Some(ip) = headers
			.get_all("x-forwarded-for")
			.iter()
			.rev()
			.filter_map(|v| v.to_str().ok())
			.flat_map(|s| s.split(',').rev())
			.filter_map(|p| p.trim().parse::<IpAddr>().ok())
			.find(|ip| !trusted_proxies.contains(ip))
		{
			return ip;
		}
		// X-Real-IP must be a single overwritten value; multiple instances mean the
		// proxy passed through a client-supplied header, so ignore it entirely.
		let mut real_ip_values = headers.get_all("x-real-ip").iter();
		if let (Some(v), None) = (real_ip_values.next(), real_ip_values.next())
			&& let Some(ip) = v
				.to_str()
				.ok()
				.and_then(|s| s.trim().parse::<IpAddr>().ok())
				.filter(|ip| !trusted_proxies.contains(ip))
		{
			return ip;
		}
	}
	peer_ip
}

/// Normalizes an IP for blocking/rate-limiting purposes.
/// IPv4 addresses are returned as-is; IPv6 addresses are truncated to their /64.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V4(_) => ip,
		IpAddr::V6(v6) => {
			let masked = u128::from(v6) & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000;
			IpAddr::V6(std::net::Ipv6Addr::from(masked))
		}
	}
}
