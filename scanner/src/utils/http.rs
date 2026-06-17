use reqwest::{Client, redirect::Policy};
use std::time::Duration;
use std::sync::OnceLock;
use std::net::{IpAddr, ToSocketAddrs};
use tracing::warn;

static GLOBAL_CLIENT: OnceLock<Client> = OnceLock::new();

/// SSRF Protection: Check if an IP is private or loopback
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

pub fn get_global_client() -> Client {
    GLOBAL_CLIENT.get_or_init(|| {
        let custom_policy = Policy::custom(|attempt| {
            // Stop after 10 redirects
            if attempt.previous().len() > 10 {
                return attempt.error("Too many redirects");
            }
            
            let url = attempt.url();
            if let Some(host) = url.host_str() {
                // SSRF check: resolve host and verify IP
                let host_port = format!("{}:80", host);
                if let Ok(mut addrs) = host_port.to_socket_addrs() {
                    if let Some(ip) = addrs.next() {
                        if is_private_ip(ip.ip()) {
                            warn!("SSRF blocked: Attempted redirect to private IP {}", ip.ip());
                            return attempt.error("Blocked redirect to private/internal IP address");
                        }
                    }
                }
            }
            attempt.follow()
        });

        Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .user_agent("SecurityScanner/1.0 (Educational)")
            .redirect(custom_policy)
            .build()
            .expect("Failed to build global HTTP client")
    }).clone()
}
