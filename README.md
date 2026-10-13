# AWS API Gateway Security Auditor (`API_final.py`)

A Python-based security auditing tool designed to automate the scanning and assessment of AWS API Gateway deployments. This script helps cloud security teams identify common misconfigurations, weak authentication controls, and insecure transport mechanisms before they can be exploited.

## 🚀 Features & Scope

The script evaluates AWS API Gateway instances against key security benchmarks:
* **Missing Authentication:** Detects open endpoints lacking proper authorizers or API keys.
* **Weak Authentication:** Identifies legacy or weak auth schemes (e.g., plain Basic Auth instead of robust standards like OAuth2 or IAM roles).
* **Insecure Transport:** Flags HTTP usage or endpoints permitting unencrypted traffic.
* **Permissive CORS:** Checks for overly permissive Cross-Origin Resource Sharing (CORS) configurations (e.g., overly broad `Access-Control-Allow-Origin: *` headers).

## 🛠️ Tech Stack
* **Language:** Python 3.x
* **Cloud Provider:** Amazon Web Services (AWS) via `boto3`
* **Environment:** VS Code, Linux / CLI

## 📋 Usage Instructions

1. Clone the repository and navigate to the project directory:
   ```bash
   git clone [https://github.com/your-username/aws-api-security-scanner.git](https://github.com/your-username/aws-api-security-scanner.git)
   cd aws-api-security-scanner
