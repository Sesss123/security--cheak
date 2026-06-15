use reqwest::Client;
use std::time::Duration;

pub fn build_client(timeout_secs: u64, accept_invalid_certs: bool) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(accept_invalid_certs)
        .user_agent("SecurityScanner/1.0 (Educational)")
        .build()
        .expect("Failed to build HTTP client")
}
