use tracing::info;
use crate::models::vulnerability::Vulnerability;

pub struct SmartScanner {
    target_url: String,
    framework: String,
}

impl SmartScanner {
    pub fn new(target_url: String, framework: String) -> Self {
        Self {
            target_url,
            framework,
        }
    }

    pub async fn run(&self) -> Vec<Vulnerability> {
        info!("Running Smart Scan for {} on {}", self.framework, self.target_url);
        let mut vulns = vec![];

        match self.framework.to_lowercase().as_str() {
            "wordpress" => {
                let wp_vulns = crate::profiles::wordpress::scan(&self.target_url).await;
                vulns.extend(wp_vulns);
            }
            "laravel" => {
                let laravel_vulns = crate::profiles::laravel::scan(&self.target_url).await;
                vulns.extend(laravel_vulns);
            }
            _ => {
                info!("No specific profile for {}, falling back to generic scan", self.framework);
            }
        }

        vulns
    }
}
