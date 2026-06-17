use reqwest::Client;
use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory};
use crate::models::scan::Severity;
use crate::modules::crawler::CrawlResult;
use tracing::{info, warn};

pub struct FileUploadDetector {
    client: Client,
    #[allow(dead_code)]
    base_url: String,
}

impl FileUploadDetector {
    pub fn new(base_url: String) -> Self {
        let client = crate::utils::http::get_global_client();
        Self { client, base_url }
    }

    pub async fn detect(&self, crawl_result: &CrawlResult) -> Vec<Vulnerability> {
        info!("Testing for File Upload Vulnerabilities...");
        let mut vulns = vec![];

        for form in &crawl_result.forms {
            if form.method == "POST" {
                // Heuristic to check if this might be a file upload form
                let mut is_upload = false;
                let mut file_input_name = String::new();
                
                for input in &form.inputs {
                    let i_lower = input.to_lowercase();
                    if i_lower.contains("file") || i_lower.contains("upload") || i_lower.contains("image") || i_lower.contains("avatar") {
                        is_upload = true;
                        file_input_name = input.clone();
                        break;
                    }
                }

                if is_upload {
                    // Try to upload a web shell using multipart/form-data
                    let part = reqwest::multipart::Part::text("<?php echo 'vulnerable'; ?>")
                        .file_name("shell.php")
                        .mime_str("image/jpeg") // Spoof MIME type
                        .unwrap();
                        
                    let form_data = reqwest::multipart::Form::new()
                        .part(file_input_name, part);

                    if let Ok(resp) = self.client.post(&form.action)
                        .multipart(form_data)
                        .send()
                        .await 
                    {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        
                        // If it responds with 200/201 and mentions "success", "uploaded", or echoes the file name, it likely accepted the PHP file.
                        if (status == 200 || status == 201) && (body.to_lowercase().contains("success") || body.contains("shell.php")) {
                            warn!("File Upload Vulnerability found at {}", form.action);
                            
                            vulns.push(Vulnerability::new(
                                "Unrestricted File Upload",
                                "The application allows uploading files with executable extensions (.php) by spoofing the MIME type. This can lead to Remote Code Execution (RCE) if the uploaded file is accessible in the web root.",
                                Severity::Critical,
                                VulnCategory::SecurityMisconfiguration,
                                form.action.clone(),
                            )
                            .with_remediation("1. Validate file extensions against a strict allow-list (e.g., .jpg, .png).\n2. Verify the actual file content/magic bytes, not just the MIME type.\n3. Rename uploaded files to random strings.\n4. Store uploaded files outside the web root or in a cloud storage bucket (S3).")
                            .with_owasp(OwaspCategory::A04InsecureDesign)
                            .with_cwe(434));
                        }
                    }
                }
            }
        }

        vulns
    }
}
