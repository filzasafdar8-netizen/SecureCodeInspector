import os
import re

# Supported file extensions
EXTENSIONS = [".py", ".js", ".java", ".cpp"]

# Vulnerability rules
VULNERABILITY_RULES = [
    # Hardcoded secrets
    {
        "pattern": r'(password|api_key|secret)\s*=\s*["\'].*["\']',
        "issue": "Hardcoded Secret",
        "risk": "HIGH"
    },
    # eval usage
    {
        "pattern": r'eval\(',
        "issue": "Use of eval()",
        "risk": "HIGH"
    },
    # Weak hashing
    {
        "pattern": r'\b(md5|sha1)\(',
        "issue": "Weak Hashing Algorithm",
        "risk": "MEDIUM"
    },
    # Dangerous imports / system calls
    {
        "pattern": r'\b(os\.system|subprocess\.Popen|subprocess\.call)\(',
        "issue": "Dangerous System Call (potential RCE)",
        "risk": "HIGH"
    },
    # Pickle deserialization (Python)
    {
        "pattern": r'\bpickle\.(load|loads)\(',
        "issue": "Pickle Deserialization (Python)",
        "risk": "HIGH"
    },
    # Simple SQL injection pattern
    {
        "pattern": r'(execute|query).*\+.*["\']',
        "issue": "Potential SQL Injection",
        "risk": "HIGH"
    },
    # Insecure HTTP / requests
    {
        "pattern": r'requests\.get\(',
        "issue": "Unverified HTTP request (Insecure)",
        "risk": "MEDIUM"
    },
    # Insecure FTP
    {
        "pattern": r'\bftp\.connect\(',
        "issue": "Insecure FTP",
        "risk": "MEDIUM"
    },
    # Unsafe JavaScript eval / Function
    {
        "pattern": r'new Function\(',
        "issue": "JavaScript new Function() (RCE risk)",
        "risk": "HIGH"
    },
]

def scan_project(folder_path):
    """
    Scans a project folder for vulnerabilities
    Returns a list of dictionaries:
    [
        {
            "file": "file.py",
            "full_path": "C:/Users/.../file.py",
            "line": 10,
            "issue": "Hardcoded Secret",
            "risk": "HIGH"
        }
    ]
    """
    results = []

    for root, _, files in os.walk(folder_path):
        for file in files:
            if any(file.endswith(ext) for ext in EXTENSIONS):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                except Exception:
                    # Skip unreadable files
                    continue

                for i, line in enumerate(lines):
                    for rule in VULNERABILITY_RULES:
                        if re.search(rule["pattern"], line):
                            results.append({
                                "file": file,
                                "full_path": file_path,
                                "line": i + 1,
                                "issue": rule["issue"],
                                "risk": rule["risk"]
                            })

    return results