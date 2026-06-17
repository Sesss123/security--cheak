use reqwest::{Client, StatusCode};
use tracing::{info, warn};
use crate::models::vulnerability::{Vulnerability, VulnCategory, Evidence, EvidenceType, OwaspCategory};
use crate::models::scan::Severity;

pub struct CloudScanner {
    client: Client,
    base_url: String,
}

impl CloudScanner {
    pub fn new(base_url: String) -> Self {
        let client = crate::utils::http::get_global_client();

        Self { client, base_url: base_url.trim_end_matches('/').to_string() }
    }

    pub async fn detect(&self) -> Vec<Vulnerability> {
        info!("Scanning for exposed Cloud Infrastructure...");
        let mut vulns = vec![];

        if let Ok(url) = url::Url::parse(&self.base_url) {
            if let Some(host) = url.host_str() {
                let root_domain = host.strip_prefix("www.").unwrap_or(host);
                let target_name = root_domain.split('.').next().unwrap_or(root_domain);

                // 1. Check AWS S3 Buckets
                let s3_vulns = self.check_s3_buckets(target_name).await;
                vulns.extend(s3_vulns);

                // 2. Check Firebase
                let firebase_vulns = self.check_firebase(target_name).await;
                vulns.extend(firebase_vulns);
            }
        }

        vulns
    }

    async fn check_s3_buckets(&self, target_name: &str) -> Vec<Vulnerability> {
        let mut vulns = vec![];
        let environments = ["", "-dev", "-staging", "-prod", "-test", "-backup", "-assets"];
        
        for env in environments {
            let bucket_name = format!("{}{}", target_name, env);
            let s3_urls = [
                format!("https://{}.s3.amazonaws.com", bucket_name),
                format!("https://s3.amazonaws.com/{}", bucket_name),
            ];

            for url in &s3_urls {
                if let Ok(resp) = self.client.get(url).send().await {
                    let status = resp.status();
                    if status == StatusCode::OK {
                        if let Ok(body) = resp.text().await {
                            if body.contains("<ListBucketResult>") {
                                warn!("Public S3 Bucket found: {}", url);
                                vulns.push(Vulnerability::new(
                                    "Public AWS S3 Bucket Exposed",
                                    format!("An Amazon S3 bucket '{}' is publicly listable. Attackers can view and potentially download sensitive files stored in the bucket.", bucket_name),
                                    Severity::High,
                                    VulnCategory::InformationDisclosure,
                                    url.clone()
                                )
                                .with_remediation("Configure the S3 bucket to 'Block Public Access'. Remove 's3:ListBucket' permissions from the anonymous user or 'AllUsers' group.")
                                .with_owasp(OwaspCategory::A01BrokenAccessControl)
                                .with_evidence(Evidence {
                                    evidence_type: EvidenceType::HttpResponse,
                                    request: None,
                                    response: Some(body.chars().take(300).collect()),
                                    payload: None,
                                    screenshot_path: None,
                                    description: "Bucket listing XML response".to_string(),
                                }));
                                break; // Found for this bucket
                            }
                        }
                    } else if status == StatusCode::FORBIDDEN {
                        // Exists but private - still good to know, but maybe just Info
                        vulns.push(Vulnerability::new(
                            "AWS S3 Bucket Discovered (Access Denied)",
                            format!("The S3 bucket '{}' exists but is correctly configured to deny public access.", bucket_name),
                            Severity::Info,
                            VulnCategory::InformationDisclosure,
                            url.clone()
                        ));
                        break;
                    }
                }
            }
        }
        vulns
    }

    async fn check_firebase(&self, target_name: &str) -> Vec<Vulnerability> {
        let mut vulns = vec![];
        let firebase_url = format!("https://{}.firebaseio.com/.json", target_name);

        if let Ok(resp) = self.client.get(&firebase_url).send().await {
            let status = resp.status();
            if status == StatusCode::OK {
                if let Ok(body) = resp.text().await {
                    if !body.contains("Permission denied") {
                        warn!("Open Firebase DB found: {}", firebase_url);
                        vulns.push(Vulnerability::new(
                            "Exposed Firebase Database",
                            format!("The Firebase Realtime Database for '{}' is publicly accessible. Attackers can read the entire database content.", target_name),
                            Severity::Critical,
                            VulnCategory::InformationDisclosure,
                            firebase_url.clone()
                        )
                        .with_remediation("Update Firebase Security Rules to require authentication (e.g., `\"auth != null\"`) before allowing read or write access.")
                        .with_owasp(OwaspCategory::A01BrokenAccessControl)
                        .with_evidence(Evidence {
                            evidence_type: EvidenceType::HttpResponse,
                            request: None,
                            response: Some(body.chars().take(300).collect()),
                            payload: None,
                            screenshot_path: None,
                            description: "Public JSON database dump".to_string(),
                        }));
                    }
                }
            }
        }
        vulns
    }
}
