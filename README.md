# Day 30: Final Practical VAPT Engagement Report (DVWA)

## 📌 Student & Assessment Details
* **Lead Penetration Tester:** Azeez Umar Opeyemi
* **Academic Program:** Undergraduate Cybersecurity Science, LAUTECH
* **Target Application Sandbox:** Damn Vulnerable Web Application (DVWA v1.8)
* **Target Environment Host:** TriosCyber & Ernith Internship Practice Lab (OWASP BWA VM)
* **Document Version:** 1.0 (Final Deliverable - Day 30 Milestone)

---

## 1. Executive Summary & Scope
This repository houses the final consolidated technical assessment report for **Day 30** of the VAPT Internship with **TriosCyber** (in partnership with **Ernith**). This document synthesizes the security flaws, structural misconfigurations, risk classifications, exploit evidence, and defensive hardening roadmaps identified during the scoped evaluation of the target web deployment.

* **Target Organization / Testing Range:** TriosCyber Internship Practice Lab
* **Target Host IP Address:** `192.168.145.134`
* **In-Scope URL Framework Path:** `http://192.168.145` (Security Context: `low`)
* **Assessment Timeline Date:** September 29, 2026
* **Engagement Core Objective:** Map perimeter exposure, fuzz hidden application routing tables, execute automated posture assessments, and perform manual request validation to deliver actionable, enterprise-grade remediation guidance.

---

## 2. Assessment Methodology
The engagement adhered to a rigorous, four-stage industry-standard testing methodology to eliminate false positives and thoroughly map the target's attack surface:

1. **Active Reconnaissance:** Full-port TCP version detection scans and default script sweeps executed via **Nmap** (`-sC -sV`) targeting core web layer infrastructure ports `80` and `443`.
2. **Endpoint Discovery:** Multi-threaded web path enumeration and directory brute-forcing conducted using **FFUF** paired with active low-level session parameters to uncover hidden routes beneath `/dvwa/vulnerabilities/`.
3. **Automated Vulnerability Scanning:** Broad-spectrum configuration audits, informational disclosure mapping, and header analysis completed via **Nikto v2.6.1**.
4. **Manual Exploitation & Triage:** Granular out-of-band HTTP request manipulation, boundary parameter fuzzing, and behavior analysis inside **Burp Suite Community Edition (Repeater)** to confirm exploit vectors and classify severity models.

---

## 3. Vulnerability Findings & Technical Deep-Dives

### Finding 1: OS Command Injection / Remote Code Execution (RCE)
* **Risk Severity:** 🔴 **High (CVSS v3.1 Score: 9.8)**
* **Vulnerable Endpoint Route:** `POST /dvwa/vulnerabilities/exec/`
* **Vulnerable Input Parameter:** `ip` body parameter variable
* **Exploit Evidence (Burp Repeater Data Log):** Intercepted the baseline request via Burp Proxy, appended a raw terminal shell command separator operator (`%3B`), and successfully chained arbitrary Linux secondary system queries (`whoami` and `uname -a`) into the input buffer container:

```http
POST /dvwa/vulnerabilities/exec/ HTTP/1.1
Host: 192.168.145.134
Content-Type: application/x-www-form-urlencoded
Cookie: security=low; PHPSESSID=c8q05ruidd0b6otc507c15co0

ip=172.0.0.1%3B+whoami%3B+uname+-a&Submit=Submit
```

* **Observed Server Response:** The host backend processed the malicious payload directly, executing the appended terminal strings and rendering the system commands' output (confirming user identity `www-data` and active Linux 2.6.32 kernel metrics) natively inside HTML `<pre>` layout tags in the response pane.
* **Operational Threat Impact:** Complete host environment compromise. Attackers can execute arbitrary operating system commands under the security context of the web daemon server service account (`www-data`), permitting unauthorized local filesystem reads, binary uploads, privilege escalation to root, and full persistent network persistence takeover.
* **Defensive Remediation:**
  1. Completely remove code dependencies on unsafe native shell invocation wrapper functions (e.g., PHP's `system()`, `exec()`, `passthru()`, or `shell_exec()`).
  2. Enforce rigid server-side input type validation checks using built-in programmatic syntax filters (such as `filter_var($ip, FILTER_VALIDATE_IP)`) to guarantee parameters match an explicit address structure before parsing blocks interface with system layers.

---

### Finding 2: Reflected Cross-Site Scripting (XSS)
* **Risk Severity:** 🟡 **Medium (CVSS v3.1 Score: 6.1)**
* **Vulnerable Endpoint Route:** `GET /dvwa/vulnerabilities/xss_r/?name=`
* **Vulnerable Input Parameter:** `name` query string parameter
* **Exploit Evidence (Burp Repeater Data Log):** Injected an unescaped client-side browser script execution token tag structure into the target vector:

```http
GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1
Host: 192.168.145.134
Cookie: security=low; PHPSESSID=c8q05ruidd0b6otc507c15co0
```

* **Observed Server Response:** The application reflected the injected characters verbatim into the DOM without filtering or applying HTML entity encoding strings. The web browser rendered the text output `Hello <script>alert(1)</script>` and instantly parsed the instructions to pop up a script dialog.
* **Operational Threat Impact:** Client-side user session exploitation. Malicious actors can construct spear-phishing payloads embedding active scripts to siphon active authorization parameters out of target browsers via `document.cookie` or execute unauthorized data state changes on behalf of the victim.
* **Defensive Remediation:**
  1. Enforce strict context-aware output encoding routines on all dynamic user parameters prior to rendering data bounds into the browser screen frame canvas (e.g., calling PHP `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')`).
  2. Deploy a robust Content-Security-Policy (CSP) HTTP response configuration header to restrict the initialization of inline script blocks natively within browser clients.

---

### Finding 3: Verbose Service Banners & Enabled HTTP TRACE Protocol
* **Risk Severity:** ℹ️ **Informational (CVSS v3.1 Score: 3.7)**
* **Vulnerable Endpoint Route:** System-wide Scope (Web Infrastructure Ports 80 & 443)
* **Exploit Evidence:** Network fingerprinting via Nmap and configuration auditing via Nikto confirmed explicit software stack version disclosures (`Apache/2.2.14`, `PHP/5.3.2-1ubuntu4.30`, `OpenSSL/0.9.8k`) and revealed active support for the `HTTP TRACE` protocol.
* **Operational Threat Impact:** Simplifies target reconnaissance sweeps, allowing malicious actors to match running services against known public CVE vulnerability indexes, and exposes authenticated sessions to potential Cross-Site Tracing (XST) session cookie siphoning vectors.
* **Defensive Remediation:**
  1. Inject core configuration directives `ServerTokens Prod` and `ServerSignature Off` within central Apache site properties to hide build information from public-facing response headers.
  2. Append parameter declaration `TraceEnable Off` into the root `httpd.conf` server manual folder to block the processing of the insecure TRACE protocol globally.

---

## 4. Consolidated Vulnerability Triage Matrix

| Vulnerability Title / Finding | Affected Endpoint Scope | Risk Severity | Manual Exploitation Status | Operational Technical Impact |
| :--- | :--- | :---: | :---: | :--- |
| **OS Command Injection** | `POST /dvwa/vulnerabilities/exec/` `(ip)` | 🔴 **High** | **Confirmed (RCE)** | Bypasses functional application boundaries to achieve full server code execution. |
| **Reflected XSS** | `GET /dvwa/vulnerabilities/xss_r/` `(name)` | 🟡 **Medium** | **Confirmed (XSS)** | Client-side scripting execution, session token hijacking, and data tampering. |
| **Verbose Banners & TRACE** | Server Headers / Ports 80 & 443 | ℹ️ **Info** | **Confirmed** | Web server architecture profiling and exposure to legacy XST token theft. |

---

## 5. Actionable Remediation Roadmap

1. **Immediate Patch Window (0–24 Hours):** Remediate the critical OS Command Injection bug within the networking tool interface path by scrubbing raw shell execution methods out of development scripts and enforcing programmatic address casting restrictions.
2. **High-Priority Mitigation Phase (1–3 Days):** Apply rigorous context-appropriate HTML entity encoding frameworks across all dynamic user input parameters mapping onto application output screens to kill Reflected XSS vectors.
3. **Medium-Priority Hardening Sprint (1 Week):** Hard-lock server configuration templates by completely killing global HTTP TRACE support, masking software version banners, and enforcing perimeter browser defense headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`).

---

## 📂 Repository Structure
```plaintext
.
├── README.md
└── report/
    └── final_vapt_summary_report.pdf
```

---

## 👤 Author
**Azeez Umar Opeyemi**
* 💼 **Role:** VAPT Intern at TriosCyber 
* 📧 **Email:** umaropeyemiazeez@gmail.com 
* 🐙 **GitHub:** [itzumaz](https://github.com/itzumaz)
* 🔗 **LinkedIn:** [Azeez Umar Opeyemi](https://www.linkedin.com/in/azeez-umar-opeyemi-201a433a4/)