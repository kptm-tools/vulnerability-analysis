# 🔍 Vulnerability Analysis Service

This microservice is responsible for managing tools that scan vulnerabilities within the Kali Linux ecosystem.

The service uses [Nmap Scripts](https://nmap.org/book/man-nse.html) and [Nikto](https://github.com/sullo/nikto) to analyze vulnerabilities.

## 🛡️ Vulnerabilities to Detect

### 🌐 Open Ports
- **Services (Applications):** Detected services running on each open port.
- **Service Versions:** Specific versions of services identified on the open ports.

### 🖥️ Operating System Information
- **🗂️ Data Scanned:** Operating system and version of the target server.
- **📋 Description:** Information about the operating system (e.g., Windows, Mac, Linux) of the target can be gathered.

Each operating system has its own set of potential weaknesses or bugs that can be exploited by attackers. When someone knows the specific OS and version a system is running, they can look up these weaknesses and create targeted attacks.  
Operating systems regularly receive updates that fix security issues. If a system is running an older version, it might not have the latest security patches installed.

#### ⚠️ Vulnerabilities

The system provides an interface with details on detected vulnerabilities per scan. Each vulnerability in this list will show:

1. **🆔 Vulnerability Name and ID:** A clear title and unique identifier (e.g., CVE or custom ID) for quick reference.
2. **🔴 Severity Level:** The risk associated with the vulnerability, using a standardized scale like Critical, High, Medium, Low.
3. **📝 Description:** A brief, non-technical explanation of the vulnerability.
4. **🎯 Affected Targets/Assets:** Specific domains, IP addresses, or other assets impacted.
5. **🔗 Additional References:** Links to external resources for further reading on CVE database entries, if applicable.


