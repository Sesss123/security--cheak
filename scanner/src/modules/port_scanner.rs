use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use anyhow::Result;
use tracing::{info, debug};
use crate::models::scan::{PortResult, PortState, PortRange};

/// [FIX #32] Common ports to scan — deduplicated and sorted.
/// Previous array had 16 duplicate entries (e.g., 80, 443 appeared 3× each).
/// The scan() method called .dedup() at runtime, but the raw const was still messy.
const COMMON_PORTS: &[u16] = &[
    // FTP, SSH, Telnet, SMTP, DNS
    21, 22, 23, 25, 53,
    // HTTP/HTTPS and common web alternates
    80, 443, 8000, 8001, 8008, 8080, 8443, 8888, 9000, 9090,
    // Mail
    110, 111, 143, 993, 995,
    // Misc services
    135, 139, 389, 445, 636, 1723, 3389, 5900,
    // Databases
    1433, 1521, 3306, 5432, 5984, 6379, 9200, 27017,
];

/// Service detection based on port number
fn detect_service(port: u16) -> Option<&'static str> {
    match port {
        21    => Some("FTP"),
        22    => Some("SSH"),
        23    => Some("Telnet"),
        25    => Some("SMTP"),
        53    => Some("DNS"),
        80    => Some("HTTP"),
        110   => Some("POP3"),
        143   => Some("IMAP"),
        389   => Some("LDAP"),
        443   => Some("HTTPS"),
        445   => Some("SMB"),
        636   => Some("LDAPS"),
        993   => Some("IMAPS"),
        995   => Some("POP3S"),
        1433  => Some("MSSQL"),
        1521  => Some("Oracle"),
        3306  => Some("MySQL"),
        3389  => Some("RDP"),
        5432  => Some("PostgreSQL"),
        5900  => Some("VNC"),
        6379  => Some("Redis"),
        8080  => Some("HTTP-Alt"),
        8443  => Some("HTTPS-Alt"),
        9200  => Some("Elasticsearch"),
        27017 => Some("MongoDB"),
        _     => None,
    }
}

/// Port scanner with async concurrent scanning
pub struct PortScanner {
    target_ip: IpAddr,
    timeout_ms: u64,
    concurrency: usize,
}

impl PortScanner {
    pub fn new(target_ip: IpAddr, timeout_ms: u64) -> Self {
        Self {
            target_ip,
            timeout_ms,
            concurrency: 100, // scan 100 ports concurrently
        }
    }

    /// Scan a single port
    async fn scan_port(&self, port: u16) -> PortResult {
        let addr = SocketAddr::new(self.target_ip, port);
        let duration = Duration::from_millis(self.timeout_ms);

        let state = match timeout(duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                debug!("Port {} is OPEN", port);
                PortState::Open
            }
            Ok(Err(_)) => {
                PortState::Closed
            }
            Err(_) => {
                // Timeout = filtered
                PortState::Filtered
            }
        };

        let service = detect_service(port).map(String::from);

        PortResult {
            port,
            state,
            service,
            version: None,
            banner: None,
        }
    }

    /// Grab banner from open port
    async fn grab_banner(&self, port: u16) -> Option<String> {
        use tokio::io::AsyncReadExt;

        let addr = SocketAddr::new(self.target_ip, port);
        let duration = Duration::from_millis(2000);

        if let Ok(Ok(mut stream)) = timeout(duration, TcpStream::connect(addr)).await {
            let mut banner = vec![0u8; 256];
            if let Ok(n) = timeout(
                Duration::from_millis(1000),
                stream.read(&mut banner)
            ).await.unwrap_or(Ok(0)) {
                if n > 0 {
                    return Some(
                        String::from_utf8_lossy(&banner[..n])
                            .trim()
                            .to_string()
                    );
                }
            }
        }
        None
    }

    /// Scan all ports in the given range
    pub async fn scan(&self, port_range: &PortRange) -> Result<Vec<PortResult>> {
        let ports: Vec<u16> = match port_range {
            PortRange::Common => {
                let mut p = COMMON_PORTS.to_vec();
                p.sort_unstable();
                p.dedup();
                p
            }
            PortRange::Extended => (1..=1024).collect(),
            PortRange::Full     => (1..=65535).collect(),
            PortRange::Custom(p) => p.clone(),
        };

        info!("Starting port scan on {} ports for {}", ports.len(), self.target_ip);

        // Scan ports in chunks for concurrency control
        let mut all_results = Vec::new();
        for chunk in ports.chunks(self.concurrency) {
            let futures: Vec<_> = chunk.iter()
                .map(|&port| self.scan_port(port))
                .collect();

            let results = futures::future::join_all(futures).await;
            all_results.extend(results);
        }

        // Only keep open ports + enrich with banners
        let mut open_ports: Vec<PortResult> = all_results
            .into_iter()
            .filter(|r| r.state == PortState::Open)
            .collect();

        // Grab banners for open ports (limit to avoid delays)
        for result in open_ports.iter_mut().take(10) {
            result.banner = self.grab_banner(result.port).await;
        }

        info!("Found {} open ports", open_ports.len());
        Ok(open_ports)
    }
}

/// Check for dangerous open ports
pub fn flag_dangerous_ports(ports: &[PortResult]) -> Vec<String> {
    let dangerous = [23, 21, 3389, 5900, 27017, 6379, 9200];
    let mut warnings = vec![];

    for port in ports {
        if port.state == PortState::Open && dangerous.contains(&port.port) {
            let msg = match port.port {
                23   => "Telnet (port 23) is open - unencrypted protocol, HIGH RISK",
                21   => "FTP (port 21) is open - sends credentials in plaintext",
                3389 => "RDP (port 3389) exposed to internet - brute force risk",
                5900 => "VNC (port 5900) is open - remote desktop exposed",
                27017 => "MongoDB (27017) exposed - check if auth is required",
                6379 => "Redis (6379) exposed - often runs without authentication",
                9200 => "Elasticsearch (9200) exposed - check access controls",
                _    => continue,
            };
            warnings.push(msg.to_string());
        }
    }

    warnings
}
