use std::fs;
use std::path::Path;
use regex::Regex;
use tracing::{info, warn, error};

use crate::models::vulnerability::{
    Vulnerability, VulnCategory, OwaspCategory, Evidence, EvidenceType,
};
use crate::models::scan::Severity;

pub struct SastAnalyzer {
    target_path: String,
}

impl SastAnalyzer {
    pub fn new(target_path: String) -> Self {
        Self { target_path }
    }

    pub async fn analyze(&self) -> Vec<Vulnerability> {
        info!("Starting SAST analysis on directory: {}", self.target_path);
        let mut vulns = Vec::new();
        let path = Path::new(&self.target_path);

        if !path.exists() || !path.is_dir() {
            error!("Target path does not exist or is not a directory: {}", self.target_path);
            return vulns;
        }

        self.scan_directory(path, &mut vulns);
        
        info!("SAST completed. Found {} source code vulnerabilities.", vulns.len());
        vulns
    }

    fn scan_directory(&self, dir: &Path, vulns: &mut Vec<Vulnerability>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Skip .git, node_modules, target, etc.
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    if name != ".git" && name != "node_modules" && name != "target" && name != "dist" {
                        self.scan_directory(&path, vulns);
                    }
                } else {
                    self.scan_file(&path, vulns);
                }
            }
        }
    }

    fn scan_file(&self, path: &Path, vulns: &mut Vec<Vulnerability>) {
        // Only scan text/source files based on extension
        let ext = path.extension().unwrap_or_default().to_string_lossy().to_lowercase();
        let allowed_exts = ["js", "ts", "py", "rs", "go", "java", "php", "c", "cpp", "env", "yml", "yaml", "json"];
        if !allowed_exts.contains(&ext.as_str()) {
            return;
        }

        if let Ok(content) = fs::read_to_string(path) {
            let relative_path = path.to_string_lossy().to_string();
            
            // Check for Hardcoded Secrets
            self.check_secrets(&content, &relative_path, vulns);
            
            // Check for Dangerous Functions
            self.check_dangerous_functions(&content, &relative_path, &ext, vulns);
        }
    }

    fn check_secrets(&self, content: &str, file_path: &str, vulns: &mut Vec<Vulnerability>) {
        // Common regex patterns for secrets
        let patterns = [
            (
                "AWS Access Key",
                Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").unwrap(),
                Severity::Critical,
            ),
            (
                "Generic API Key / Secret",
                Regex::new(r#"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)['\s:=]+(['"][A-Za-z0-9\-_]{16,}['"])"#).unwrap(),
                Severity::High,
            ),
            (
                "JWT Token",
                Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
                Severity::High,
            ),
            (
                "Database Password",
                Regex::new(r#"(?i)(password|pass|db_pass)['\s:=]+(['"][^'"]{6,}['"])"#).unwrap(),
                Severity::Critical,
            )
        ];

        for (name, re, severity) in &patterns {
            for cap in re.captures_iter(content) {
                let matched_text = cap.get(0).unwrap().as_str();
                // Avoid logging the full secret, truncate it
                let safe_match = if matched_text.len() > 10 {
                    format!("{}...", &matched_text[..10])
                } else {
                    "*****".to_string()
                };

                warn!("SAST: Found {} in {}", name, file_path);

                vulns.push(
                    Vulnerability::new(
                        format!("Hardcoded {} in Source Code", name),
                        format!("A hardcoded {} was found in {}. Hardcoding secrets in source code leads to credential leaks if the code is exposed.", name, file_path),
                        severity.clone(),
                        VulnCategory::HardcodedSecret,
                        file_path.to_string(),
                    )
                    .with_remediation("Use environment variables, AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault to inject secrets at runtime. Never commit secrets to version control.")
                    .with_owasp(OwaspCategory::A07AuthenticationFailures)
                    .with_cwe(798) // CWE-798: Use of Hard-coded Credentials
                    .with_evidence(Evidence {
                        evidence_type: EvidenceType::CodeSnippet,
                        request: None,
                        response: None,
                        payload: None,
                        screenshot_path: None,
                        description: format!("Match found: {}", safe_match),
                    })
                );
            }
        }
    }

    fn check_dangerous_functions(&self, content: &str, file_path: &str, ext: &str, vulns: &mut Vec<Vulnerability>) {
        let mut checks = Vec::new();

        if ext == "js" || ext == "ts" {
            checks.push((
                "Usage of eval()",
                Regex::new(r"\beval\s*\(").unwrap(),
                Severity::High,
                OwaspCategory::A03Injection,
                94, // CWE-94: Code Injection
                "Avoid using eval() as it can execute arbitrary code. Use safer alternatives like JSON.parse()."
            ));
            checks.push((
                "Dangerous DOM API (innerHTML)",
                Regex::new(r"\.innerHTML\s*=").unwrap(),
                Severity::Medium,
                OwaspCategory::A03Injection,
                79, // CWE-79: XSS
                "Using innerHTML can lead to DOM-based XSS. Use textContent or DOMPurify."
            ));
        }

        if ext == "py" {
            checks.push((
                "Usage of eval() or exec()",
                Regex::new(r"\b(eval|exec)\s*\(").unwrap(),
                Severity::High,
                OwaspCategory::A03Injection,
                94,
                "eval() and exec() execute arbitrary code. Use ast.literal_eval() instead."
            ));
            checks.push((
                "Usage of os.system()",
                Regex::new(r"os\.system\s*\(").unwrap(),
                Severity::High,
                OwaspCategory::A03Injection,
                78, // CWE-78: OS Command Injection
                "os.system() is vulnerable to command injection. Use the subprocess module with proper argument arrays."
            ));
        }

        if ext == "php" {
            checks.push((
                "Usage of system/exec",
                Regex::new(r"\b(system|exec|passthru|shell_exec)\s*\(").unwrap(),
                Severity::High,
                OwaspCategory::A03Injection,
                78,
                "Command execution functions can lead to RCE. Validate and sanitize all inputs using escapeshellarg()."
            ));
        }

        for (name, re, severity, owasp, cwe, remediation) in checks {
            for cap in re.captures_iter(content) {
                warn!("SAST: Found {} in {}", name, file_path);
                
                // Get line number roughly
                let match_start = cap.get(0).unwrap().start();
                let line_num = content[..match_start].lines().count() + 1;

                vulns.push(
                    Vulnerability::new(
                        name.to_string(),
                        format!("Dangerous function '{}' detected in {} at line {}.", name, file_path, line_num),
                        severity.clone(),
                        VulnCategory::SastFinding,
                        file_path.to_string(),
                    )
                    .with_remediation(remediation.to_string())
                    .with_owasp(owasp.clone())
                    .with_cwe(cwe)
                    .with_evidence(Evidence {
                        evidence_type: EvidenceType::CodeSnippet,
                        request: None,
                        response: None,
                        payload: None,
                        screenshot_path: None,
                        description: format!("Found pattern at line {}", line_num),
                    })
                );
            }
        }
    }
}
