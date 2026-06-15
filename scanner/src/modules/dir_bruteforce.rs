use reqwest::Client;
use std::collections::HashSet;
use tracing::{info, warn};
use futures::stream::{self, StreamExt};

pub struct DirBruteforcer {
    client: Client,
    base_url: String,
}

impl DirBruteforcer {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            // Do not follow redirects so we can detect 301/302 admin panel redirects
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
            
        Self { client, base_url }
    }

    pub async fn bruteforce(&self) -> Vec<String> {
        info!("Starting directory bruteforce for {}", self.base_url);
        
        // A built-in highly effective small wordlist
        let common_paths = vec![
            "admin", "administrator", "login", "dashboard", "api", "api/v1", 
            "backup", "backups", "config", ".git", ".env", ".env.local", 
            "phpinfo.php", "server-status", "robots.txt", "sitemap.xml",
            "swagger-ui.html", "swagger", "openapi.json", "wp-admin", 
            "wp-login.php", "test", "dev", "staging", "old", "new", 
            "assets", "uploads", "images", "css", "js"
        ];

        let base = self.base_url.trim_end_matches('/');
        let mut discovered = HashSet::new();

        // Use a stream to run requests concurrently (max 10 at a time)
        let fetches = stream::iter(common_paths.into_iter().map(|path| {
            let url = format!("{}/{}", base, path);
            let client = self.client.clone();
            
            async move {
                match client.head(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        // 200 OK, 401 Unauthorized, 403 Forbidden, 301/302 Redirect
                        if status == 200 || status == 401 || status == 403 || (301..=302).contains(&status) {
                            Some((url, status))
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            }
        }))
        .buffer_unordered(10)
        .collect::<Vec<Option<(String, u16)>>>()
        .await;

        for result in fetches.into_iter().flatten() {
            let (url, status) = result;
            info!("Found path: {} (Status: {})", url, status);
            discovered.insert(url);
        }

        let mut result: Vec<String> = discovered.into_iter().collect();
        result.sort();
        info!("Found {} hidden directories/files", result.len());
        result
    }
}
