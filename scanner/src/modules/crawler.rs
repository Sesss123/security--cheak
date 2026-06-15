use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use tracing::{info, warn};
use url::Url;

#[derive(Debug, Clone)]
pub struct DiscoveredForm {
    pub action: String,
    pub method: String,
    pub inputs: Vec<String>,
}

#[derive(Debug)]
pub struct CrawlResult {
    pub urls: HashSet<String>,
    pub forms: Vec<DiscoveredForm>,
}

pub struct Crawler {
    client: Client,
    base_url: String,
    max_depth: u32,
}

impl Crawler {
    pub fn new(base_url: String, max_depth: u32) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        Self {
            client,
            base_url,
            max_depth,
        }
    }

    pub async fn crawl_site(&self) -> CrawlResult {
        info!("Starting crawl on {} with max depth {}", self.base_url, self.max_depth);
        let mut visited = HashSet::new();
        let mut to_visit = vec![(self.base_url.clone(), 0)];
        let mut all_forms = vec![];

        while let Some((current_url, depth)) = to_visit.pop() {
            if depth > self.max_depth || visited.contains(&current_url) {
                continue;
            }

            visited.insert(current_url.clone());
            info!("Crawling: {}", current_url);

            match self.client.get(&current_url).send().await {
                Ok(resp) => {
                    if let Ok(body) = resp.text().await {
                        let document = Html::parse_document(&body);

                        // Extract links
                        let link_selector = Selector::parse("a[href]").unwrap();
                        for element in document.select(&link_selector) {
                            if let Some(href) = element.value().attr("href") {
                                if let Some(absolute_url) = self.resolve_url(&current_url, href) {
                                    if !visited.contains(&absolute_url) && absolute_url.starts_with(&self.base_url) {
                                        to_visit.push((absolute_url, depth + 1));
                                    }
                                }
                            }
                        }

                        // Extract forms
                        let form_selector = Selector::parse("form").unwrap();
                        let input_selector = Selector::parse("input[name], textarea[name]").unwrap();
                        
                        for form in document.select(&form_selector) {
                            let action = form.value().attr("action").unwrap_or(&current_url).to_string();
                            let method = form.value().attr("method").unwrap_or("GET").to_uppercase();
                            let mut inputs = vec![];

                            for input in form.select(&input_selector) {
                                if let Some(name) = input.value().attr("name") {
                                    inputs.push(name.to_string());
                                }
                            }

                            if let Some(resolved_action) = self.resolve_url(&current_url, &action) {
                                all_forms.push(DiscoveredForm {
                                    action: resolved_action,
                                    method,
                                    inputs,
                                });
                            }
                        }
                    }
                }
                Err(e) => warn!("Failed to fetch {}: {}", current_url, e),
            }
        }

        info!("Crawl finished. Found {} URLs and {} forms.", visited.len(), all_forms.len());
        CrawlResult {
            urls: visited,
            forms: all_forms,
        }
    }

    fn resolve_url(&self, base: &str, target: &str) -> Option<String> {
        if target.starts_with("javascript:") || target.starts_with("mailto:") || target.starts_with('#') {
            return None;
        }
        
        match Url::parse(base) {
            Ok(base_url) => match base_url.join(target) {
                Ok(joined) => {
                    let mut s = joined.to_string();
                    if let Some(pos) = s.find('#') {
                        s.truncate(pos);
                    }
                    Some(s)
                }
                Err(_) => None,
            },
            Err(_) => None,
        }
    }
}
