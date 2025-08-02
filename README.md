# TheOSuite

TheOSuite is a comprehensive, open-source collection of security testing tools designed for identifying vulnerabilities, misconfigurations, and compliance issues in web applications, networks, and systems. Each tool focuses on specific aspects of security, such as XSS detection, cryptographic failures, access control testing, and more. This suite consolidates them into a single repository for easy access and management, with a centralized GUI launcher for seamless usage.

All tools are built primarily in Python and utilize Tkinter for graphical interfaces where applicable. Each tool resides in its own subdirectory and includes a detailed, tool-specific README.md file with in-depth installation, usage, features, and examples.

## Tools Included

Here is a list of all included tools, with brief descriptions. For full details, refer to the README.md in each tool's directory (e.g., `./oXSS/README.md`).

- **oBAC: Broken Access Control Testing Application** - Tests for broken access control vulnerabilities in web applications.
- **oCF: Cryptographic Failure Testing Application** - Identifies cryptographic failures and weaknesses in applications.
- **oIAF: Identification and Authentication Failures Tester** - Detects issues related to identification and authentication mechanisms.
- **oJSS3: S3 Bucket and JavaScript Endpoint Extractor** - Extracts S3 buckets and JavaScript endpoints from web sources.
- **oLSM: Local Security Monitor** - Monitors local system security and detects potential threats.
- **oMITM: Man In The Middle Attack Tester** - Simulates and tests for man-in-the-middle attacks.
- **oPFC: Privacy Framework Checklist** - Provides a checklist for privacy framework compliance.
- **oPKI: ePKI - A Certificate Authority and Certificate Management Utility** - Manages certificates and acts as a simple certificate authority.
- **oSDIS: Software and Data Integrity Scanner** - Scans for integrity issues in software and data.
- **oSLMF: Security Logging and Monitoring Failures Tester** - Tests for failures in security logging and monitoring.
- **oSMS: Security Misconfiguration Scanner** - Scans for security misconfigurations in systems and applications.
- **oSSLC: SSL Certificate Analyzer** - Analyzes SSL certificates for validity and vulnerabilities.
- **oSSRF: Server-Side Request Forgery Testing Utility** - Tests for server-side request forgery vulnerabilities.
- **oVOC: Vulnerable and Outdated Components Tester** - Identifies vulnerable or outdated components in applications.
- **oXSS: Enhanced Cross Site Scripting Scanner** - Scans for cross-site scripting (XSS) vulnerabilities with enhanced detection.
- **paygen: Payload Generator** - Generates payloads for security testing purposes.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/TheOSuite/TheOSuite.git
   cd TheOSuite
   ```

2. Install dependencies. Each tool may have specific requirements, but a combined `requirements.txt` is provided in the root for common libraries (e.g., `requests`, `beautifulsoup4`, `selenium`, etc.). Run:
   ```
   pip install -r requirements.txt
   ```

   Note: Some tools require additional setup, such as ChromeDriver for Selenium-based tools. Refer to individual tool READMEs for details.

3. (Optional) For tools using Selenium, ensure Chrome and ChromeDriver are installed and compatible.

## Usage

The suite includes a centralized GUI launcher for easy access to all tools:

1. Run the launcher:
   ```
   python TheOSuite.py
   ```

2. In the GUI window, select a tool from the list and click "Launch Selected Tool". This will open the chosen tool's interface in a new window.

Each tool can also be run independently by navigating to its directory and executing its entry script (e.g., `cd oXSS && python oXSS.py`). See the tool's README for specific commands and options.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. Individual tools may have their own licenses if specified in their directories.

## Contact

For questions or support, open an issue on the GitHub repository.
