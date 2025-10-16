import ast
import re
import logging
from typing import List, Dict, Any
import bandit
from bandit.core import manager as bandit_manager
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AdvancedVulnerabilityScanner:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.code_lines: List[str] = []
        self.ast_tree: ast.AST = None
        self.vulnerability_db = self.load_vulnerability_db()

    def load_vulnerability_db(self):
        # Mock vulnerability database
        return {
            'requests': {'2.25.0': ['CVE-2021-12345']},
            'django': {'2.2.0': ['CVE-2021-67890']}
        }

    def parse_file(self):
        logging.info(f"Parsing file: {self.file_path}")
        with open(self.file_path, 'r', encoding='utf-8') as file:
            self.code_lines = file.readlines()
            self.ast_tree = ast.parse(''.join(self.code_lines))
        logging.info(f"File parsed. Total lines: {len(self.code_lines)}")

    def check_hardcoded_secrets(self):
        """Custom rule to detect hardcoded secrets like passwords, keys, etc."""
        logging.info("Checking for hardcoded secrets...")
        pattern = re.compile(r'(?i)(password|secret|key|token)\s*=\s*["\'][^"\']+["\']')
        for i, line in enumerate(self.code_lines, start=1):
            matches = pattern.findall(line)
            if matches:
                self.add_vulnerability('Hardcoded Secret', f"Hardcoded secret found: {matches[0]}", i, 'HIGH', 'HIGH')

    def check_sql_injection(self):
        """Custom rule to detect potential SQL injection vulnerabilities."""
        logging.info("Checking for SQL injection vulnerabilities...")
        sql_patterns = [
            r'(?i)(?:execute|cursor\.execute)\s*\(.*?%s.*?\)',
            r'(?i)(?:execute|cursor\.execute)\s*\(.*?f["\'].*?\{.*?\}.*?["\'].*?\)'
        ]
        for i, line in enumerate(self.code_lines, start=1):
            for pattern in sql_patterns:
                if re.search(pattern, line):
                    self.add_vulnerability('SQL Injection', "Potential SQL injection vulnerability", i, 'HIGH', 'MEDIUM')

    def check_xss_vulnerabilities(self):
        """Custom rule to detect potential XSS vulnerabilities."""
        logging.info("Checking for XSS vulnerabilities...")
        pattern = re.compile(r'(?i)render_template\(.+\)|response\.write\(.+\)|print\(.+\)')
        for i, line in enumerate(self.code_lines, start=1):
            if pattern.search(line):
                self.add_vulnerability('XSS Vulnerability', "Potential XSS vulnerability", i, 'HIGH', 'MEDIUM')

    def check_xml_external_entities(self):
        """Custom rule to detect XML External Entities (XXE) vulnerabilities."""
        logging.info("Checking for XXE vulnerabilities...")
        pattern = re.compile(r'(?i)xml\.etree\.ElementTree\.parse|xml\.etree\.ElementTree\.fromstring')
        for i, line in enumerate(self.code_lines, start=1):
            if pattern.search(line):
                self.add_vulnerability('XML External Entities (XXE)', "Potential XXE vulnerability", i, 'HIGH', 'HIGH')

    def check_insecure_defaults(self):
        """Custom rule to detect insecure default configurations."""
        logging.info("Checking for insecure default configurations...")
        pattern = re.compile(r'(?i)app\.run\(|debug\s*=\s*True|0\.0\.0\.0')
        for i, line in enumerate(self.code_lines, start=1):
            if pattern.search(line):
                self.add_vulnerability('Insecure Defaults', "Potential insecure default configuration", i, 'MEDIUM', 'MEDIUM')

    def check_vulnerable_components(self):
        """Custom rule to detect the use of vulnerable libraries or components."""
        logging.info("Checking for vulnerable components...")
        for i, line in enumerate(self.code_lines, start=1):
            for lib, versions in self.vulnerability_db.items():
                if lib in line:
                    for version, cves in versions.items():
                        if version in line:
                            self.add_vulnerability('Vulnerable Component', f"Use of vulnerable component {lib} version {version} (CVE: {', '.join(cves)})", i, 'HIGH', 'HIGH')

    def run_bandit(self):
        """Integrates Bandit to run additional security checks."""
        b_mgr = bandit_manager.BanditManager(bandit.config.BanditConfig(), agg_type='file')
        b_mgr.discover_files([self.file_path])
        b_mgr.run_tests()
        return b_mgr.get_issue_list()

    def run_semgrep(self):
        """Integrates Semgrep for additional code analysis."""
        logging.info("Running Semgrep analysis...")
        result = subprocess.run(['semgrep', '--config', 'auto', self.file_path], capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"Semgrep encountered an error: {result.stderr}")
        return result.stdout

    def add_vulnerability(self, category: str, description: str, line_number: int, severity: str, confidence: str):
        """Adds a detected vulnerability to the list."""
        self.vulnerabilities.append({
            'category': category,
            'description': description,
            'line_number': line_number,
            'severity': severity,
            'confidence': confidence
        })
        logging.info(f"Vulnerability added: {category} at line {line_number}")

    def perform_taint_analysis(self):
        """Performs taint analysis to detect unsafe use of user input."""
        logging.info("Performing taint analysis")
        tainted_vars = set()
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id in ['input', 'request.form.get']:
                            tainted_vars.add(target.id)
            elif isinstance(node, ast.Name) and node.id in tainted_vars:
                if isinstance(node.ctx, ast.Load):
                    self.add_vulnerability('Tainted Variable Usage', f"Potentially tainted variable used: {node.id}", getattr(node, 'lineno', 0), 'MEDIUM', 'MEDIUM')

    def analyze(self):
        """Runs all checks and generates a comprehensive security report."""
        try:
            self.parse_file()
            self.check_hardcoded_secrets()
            self.check_sql_injection()
            self.check_xss_vulnerabilities()
            self.check_xml_external_entities()
            self.check_insecure_defaults()
            self.check_vulnerable_components()
            self.perform_taint_analysis()

            # Run Bandit for additional checks
            bandit_issues = self.run_bandit()
            for issue in bandit_issues:
                self.add_vulnerability(f"Bandit: {issue.test_id}", issue.text, issue.lineno, issue.severity, issue.confidence)

            # Run Semgrep for additional checks
            semgrep_results = self.run_semgrep()
            if semgrep_results:
                logging.info(f"Semgrep results:\n{semgrep_results}")

            logging.info("Analysis completed successfully")
        except Exception as e:
            logging.error(f"An error occurred during analysis: {str(e)}")

    def generate_report(self):
        """Generates a detailed report of the detected vulnerabilities."""
        print(f"Advanced Vulnerability Scan Results for {self.file_path}:")
        print(f"Total lines of code: {len(self.code_lines)}")
        print("\nDetected Vulnerabilities:")
        if not self.vulnerabilities:
            print("No vulnerabilities detected.")
        else:
            for vuln in sorted(self.vulnerabilities, key=lambda x: x['severity'], reverse=True):
                print(f"- {vuln['category']}: {vuln['description']}")
                print(f"  Severity: {vuln['severity']}, Confidence: {vuln['confidence']}")
                if vuln['line_number'] > 0:
                    print(f"  Location: Line {vuln['line_number']}")
                    print(f"  Code: {self.code_lines[vuln['line_number']-1].strip()}")
                print()

def main():
    file_path = "vulnerable.py"  # Change this to the path of the file you want to scan
    scanner = AdvancedVulnerabilityScanner(file_path)
    scanner.analyze()
    scanner.generate_report()

if __name__ == "__main__":
    main()
