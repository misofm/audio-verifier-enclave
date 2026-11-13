use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::{Host, Url};

/// Host suffix of R2's S3 endpoints, `<account-id>.r2.cloudflarestorage.com` and
/// `<account-id>.<jurisdiction>.r2.cloudflarestorage.com`.
pub const R2_HOST_SUFFIX: &str = ".r2.cloudflarestorage.com";

/// Which download URLs `/measure` accepts.
#[derive(Debug, Clone)]
pub struct UrlPolicy {
    /// Lowercase suffixes, each starting with `.`; a host must end with one and be longer.
    pub host_suffixes: Vec<String>,
    /// Accept only `https` on port 443. Off only in tests, which serve plain HTTP locally.
    pub require_https: bool,
}

impl Default for UrlPolicy {
    fn default() -> Self {
        Self {
            host_suffixes: vec![R2_HOST_SUFFIX.into()],
            require_https: true,
        }
    }
}

impl UrlPolicy {
    /// Parses `raw` and accepts it only if its scheme, port and host are allowed and it carries
    /// no credentials. IP-literal hosts are refused, since they bypass the resolver's checks.
    pub fn check(&self, raw: &str) -> Result<Url, String> {
        let url = Url::parse(raw).map_err(|error| format!("not a URL: {error}"))?;
        match url.scheme() {
            "https" => {}
            "http" if !self.require_https => {}
            _ => return Err("the URL must be https".into()),
        }
        if self.require_https && url.port().is_some() {
            return Err("the URL must use the default port".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("the URL must not carry credentials".into());
        }
        let Some(Host::Domain(host)) = url.host() else {
            return Err("the URL's host must be a domain name".into());
        };
        let allowed = self
            .host_suffixes
            .iter()
            .any(|suffix| host.len() > suffix.len() && host.ends_with(suffix.as_str()));
        if !allowed {
            return Err(format!("{host} is not an allowed host"));
        }
        Ok(url)
    }
}

/// Whether `ip` is a public unicast address: not loopback, private, link-local (including
/// 169.254.169.254, the instance metadata service), shared, documentation, multicast or
/// reserved. IPv6 accepts only global unicast `2000::/3`, which excludes IPv4-mapped and
/// NAT64 addresses and AWS's `fd00:ec2::254`, without 6to4, Teredo or documentation ranges.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let [a, b, ..] = ip.segments();
    a & 0xe000 == 0x2000 && a != 0x2002 && !(a == 0x2001 && (b < 0x0200 || b == 0x0db8))
}

/// The system resolver, keeping only public addresses. The download connects to the addresses
/// it returns, so a name cannot pass the check and then connect elsewhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| is_public(addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} has no public address").into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r2_endpoints_are_allowed() {
        let policy = UrlPolicy::default();
        for url in [
            "https://0123456789abcdef.r2.cloudflarestorage.com/bucket/key.flac?X-Amz-Signature=ab",
            "https://0123456789abcdef.eu.r2.cloudflarestorage.com/bucket/key.flac",
            "https://ACCOUNT.R2.CloudflareStorage.com/bucket/key",
            "https://account.r2.cloudflarestorage.com:443/bucket/key",
        ] {
            assert!(policy.check(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn other_urls_are_refused() {
        let policy = UrlPolicy::default();
        for url in [
            "http://account.r2.cloudflarestorage.com/bucket/key",
            "ftp://account.r2.cloudflarestorage.com/bucket/key",
            "file:///etc/passwd",
            "https://account.r2.cloudflarestorage.com:8443/bucket/key",
            "https://r2.cloudflarestorage.com/bucket/key",
            "https://.r2.cloudflarestorage.com/bucket/key",
            "https://cloudflarestorage.com/bucket/key",
            "https://account.r2.cloudflarestorage.com.evil.com/key",
            "https://accountr2.cloudflarestorage.com/key",
            "https://evil.com/account.r2.cloudflarestorage.com",
            "https://account.r2.cloudflarestorage.com@evil.com/key",
            "https://user:pass@account.r2.cloudflarestorage.com/key",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/key",
            "https://[::1]/key",
            "https://localhost/key",
            "not a url",
            "",
        ] {
            assert!(policy.check(url).is_err(), "{url}");
        }
    }

    #[test]
    fn suffixes_are_configurable() {
        let policy = UrlPolicy {
            host_suffixes: vec![".eu.r2.cloudflarestorage.com".into()],
            require_https: true,
        };
        assert!(
            policy
                .check("https://a.eu.r2.cloudflarestorage.com/k")
                .is_ok()
        );
        assert!(
            policy
                .check("https://a.r2.cloudflarestorage.com/k")
                .is_err()
        );
        let local = UrlPolicy {
            host_suffixes: vec![".r2.test".into()],
            require_https: false,
        };
        assert!(local.check("http://a.r2.test:8080/k").is_ok());
        assert!(local.check("http://127.0.0.1:8080/k").is_err());
    }

    #[test]
    fn private_addresses_are_not_public() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "169.254.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "fd00:ec2::254",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "2002:a9fe:a9fe::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn public_addresses_are_public() {
        for ip in [
            "1.1.1.1",
            "104.18.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "198.20.0.1",
            "2606:4700::6810:84e5",
            "2a06:98c1:3120::3",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn the_resolver_refuses_names_without_public_addresses() {
        let resolving = PublicResolver.resolve("localhost".parse().unwrap());
        assert!(resolving.await.is_err());
    }
}
