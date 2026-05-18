#!/usr/bin/env python3
"""
奇点造物-Genesisix v1.2 外部资源安全测试
"""
import subprocess
import json
from pathlib import Path

SKILL_DIR = Path(__file__).parent

TEST_CASES = {
    "internal_ip_access": [
        ("http://169.254.169.254/latest/meta-data/", True),
        ("http://169.254.169.254/latest/user-data/", True),
        ("http://10.0.0.1/admin", True),
        ("http://172.16.0.1/api", True),
        ("http://192.168.1.1/router", True),
        ("https://google.com", False),
        ("https://api.github.com", False),
    ],
    "localhost_access": [
        ("http://localhost/admin", True),
        ("http://127.0.0.1:8080", True),
        ("http://0.0.0.0:22", True),
        ("https://localhost:443", True),
    ],
    "dangerous_protocol": [
        ("file:///etc/passwd", True),
        ("gopher://server/cmd", True),
        ("dict://server/info", True),
        ("sftp://server/file", True),
        ("ldap://server/cn=admin", True),
        ("http://example.com", False),
        ("https://example.com", False),
    ],
    "dangerous_path": [
        ("http://example.com/etc/passwd", True),
        ("http://example.com/root/.ssh/id_rsa", True),
        ("http://example.com/proc/self/environ", True),
        ("http://example.com/api/../etc/passwd", True),
        ("http://example.com/path/to/resource", False),
    ],
    "dangerous_port": [
        ("http://example.com:22", True),
        ("http://example.com:3306", True),
        ("http://example.com:5432", True),
        ("http://example.com:6379", True),
        ("http://example.com:27017", True),
        ("http://example.com:443", False),
        ("http://example.com:8080", False),
    ],
    "url_with_credentials": [
        ("http://admin:password@example.com/", True),
        ("http://user:secret@example.com/api", True),
        ("https://example.com", False),
    ],
}

def run_resource_guard(url):
    script = f"""
    const {{ validateURL }} = require('{SKILL_DIR}/layers/resource_guard.js');
    const r = validateURL({json.dumps(url)});
    console.log(JSON.stringify({{safe: r.safe, threats: r.threats.map(t => t.type)}}));
    """
    result = subprocess.run(
        ["node", "-e", script],
        capture_output=True, text=True, timeout=5
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout.strip())
    except:
        return None

def main():
    print("=" * 50)
    print("奇点造物-Genesisix v1.2 外部资源安全测试")
    print("=" * 50)
    
    total_passed = 0
    total_failed = 0
    
    for category, cases in TEST_CASES.items():
        passed = 0
        failed = 0
        
        for url, expected_blocked in cases:
            result = run_resource_guard(url)
            if result is None:
                failed += 1
                continue
            
            is_blocked = not result["safe"]
            if is_blocked == expected_blocked:
                passed += 1
            else:
                failed += 1
        
        total_passed += passed
        total_failed += failed
        
        coverage = (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0
        status = "✅" if coverage >= 80 else "❌"
        print(f"{status} {category}: {passed}/{passed+failed} ({coverage:.1f}%)")
    
    overall = (total_passed / (total_passed + total_failed) * 100) if (total_passed + total_failed) > 0 else 0
    
    print("-" * 50)
    print(f"总覆盖率: {total_passed}/{total_passed+total_failed} ({overall:.1f}%)")
    print(f"目标: ≥80%")
    print(f"状态: {'✅ 达标' if overall >= 80 else '❌ 未达标'}")
    
    return 0 if overall >= 80 else 1

if __name__ == "__main__":
    exit(main())
