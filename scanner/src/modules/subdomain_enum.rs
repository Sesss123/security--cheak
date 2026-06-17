use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;
use tracing::info;
// trust-dns-resolver was renamed to hickory-resolver (Issue #9)
use hickory_resolver::TokioAsyncResolver;
use url::Url;

pub struct SubdomainEnumerator {
    client: Client,
    resolver: TokioAsyncResolver,
}

impl SubdomainEnumerator {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap();
            
        // Use default system resolver
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .unwrap_or_else(|_| {
                // Fall back to Google DNS if system resolver config is unavailable
                let cfg = hickory_resolver::config::ResolverConfig::default();
                let opts = hickory_resolver::config::ResolverOpts::default();
                TokioAsyncResolver::tokio(cfg, opts)
            });
        
        Self { client, resolver }
    }

    pub async fn enumerate(&self, base_url: &str) -> Vec<String> {
        info!("Starting subdomain enumeration for {}", base_url);
        
        // Extract domain from URL
        let domain = match Url::parse(base_url) {
            Ok(url) => url.host_str().unwrap_or(base_url).to_string(),
            Err(_) => {
                let trimmed = base_url.trim_start_matches("http://").trim_start_matches("https://");
                let end = trimmed.find('/').unwrap_or(trimmed.len());
                trimmed[..end].to_string()
            }
        };

        let mut subdomains = HashSet::new();

        // 1. Passive Recon: crt.sh (Certificate Transparency)
        let crt_url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        if let Ok(resp) = self.client.get(&crt_url).send().await {
            if let Ok(json) = resp.json::<Vec<Value>>().await {
                for entry in json {
                    if let Some(name) = entry.get("name_value").and_then(|v| v.as_str()) {
                        for sub in name.split('\n') {
                            let clean_sub = sub.trim().trim_start_matches("*.");
                            if clean_sub.ends_with(&domain) && clean_sub != domain {
                                subdomains.insert(clean_sub.to_string());
                            }
                        }
                    }
                }
            }
        }

        // 2. Active Recon: DNS Brute force (small common list)
        let common_subs = ["www", "api", "dev", "staging", "test", "admin", "blog", "mail", "cdn", "vpn"];
        
        for sub in common_subs {
            let target = format!("{}.{}", sub, domain);
            if let Ok(response) = self.resolver.lookup_ip(&target).await {
                if response.iter().next().is_some() {
                    subdomains.insert(target);
                }
            }
        }

        let mut result: Vec<String> = subdomains.into_iter().collect();
        result.sort();
        info!("Found {} subdomains", result.len());
        result
    }
}
