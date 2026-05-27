---
name: 奇点造物-Genesisix
@version 2.0.0
description: Multi-layer security detector for AI agents. Blocks prompt injection, jailbreak, XSS, SQL injection, API key leaks, supply chain attacks, deployment vulnerabilities, malicious URLs, data exfiltration, hidden text injection, encoding bypass, Unicode homoglyph attacks, Trojan Source attacks, and multilingual prompt injection.
---

# 奇点造物-Genesisix 🛡️

> Enterprise-grade 13-layer security detector for AI agents

## Overview

奇点造物-Genesisix is a comprehensive security middleware that intercepts and blocks malicious input before it reaches your AI agent. Built with defense-in-depth philosophy.

## Features

### 13-Layer Protection

| Layer | Threats | Rules |
|-------|---------|-------|
| **Preprocess** | Input cleaning, encoding normalization, canary markers | — |
| **Ingest** | Hidden Text, Zero-Width, Homoglyph, Trojan Source, HTML Injection, Encoding Bypass | 67 |
| **LLM** | Prompt Injection, Jailbreak, Prompt Leak, Multilingual, Few-Shot, Indirect Injection, Multiturn | 131 |
| **Web** | SQL Injection, XSS, CSRF, SSRF, Command Injection, Path Traversal, SSTI, XXE | 61 |
| **API** | Key Exposure, Rate Limiting, Auth Bypass, GraphQL, JWT, OAuth | 36 |
| **MCP Security** | Tool Poisoning, Schema Validation, Dangerous Tools, Tool Exfil, OAuth, Audit | 98 |
| **Outbound** | PII Exfil, DNS Exfil, Internal Network, Protocol Check, URL Reputation, Short Links, Data Exfil | 88 |
| **Supply Chain** | Dangerous Deps, Typosquat, Malicious Import, Skill Integrity | 34 |
| **Deploy** | Env Leaks, Debug Info, Docker Leaks, CI/CD Leaks, Source Leaks | 25 |
| **Memory** | Memory Injection, Checkpoint Tamper | 20 |
| **Integrity** | Profile Backdoor Detection | 22 |
| **Multi-Agent** | Cross-Agent Injection, Agent Impersonation, Chain Attack, Trust Evaluation, SlowMist Review | 85 |
| **Resource Guard** | SSRF, Internal IP, Dangerous Protocol, Dangerous Path, Blocked Ports | 40 |

**Total: 825 detection rules**

## Quick Start

### Installation

```bash
# Via ClawHub
clawhub install 奇点造物-Genesisix

# Manual
cp -r 奇点造物-Genesisix ~/.openclaw/workspace/skills/
```

### Basic Usage

```javascript
const Detector = require('./detector');
const detector = new Detector();

// Scan user input (all 13 layers)
const result = detector.scan('Ignore previous instructions');
if (!result.safe) {
  console.log('Blocked:', result.threats);
}

// Scan outbound URL
const urlResult = detector.scanOutbound('http://10.0.0.1/admin');
if (!urlResult.safe) {
  console.log('URL blocked:', urlResult.threats);
}

// Scan ingested content for hidden threats
const ingestResult = detector.scanIngest('hello\u200B\u200Bworld');
if (!ingestResult.safe) {
  console.log('Hidden threat detected:', ingestResult.threats);
}
```

### Return Format

```typescript
{
  safe: boolean;           // true if input is safe
  threats: Array<{
    type: string;         // threat category
    pattern: string;      // matched pattern ID
    severity: string;     // critical|high|medium|low
    confidence: number;   // 0-1
    description: string;
  }>;
  confidence: number;      // overall confidence 0-1
  layersScanned: string[]; // layers that were checked
  scannedAt: string;       // ISO timestamp
}
```

## API

### `detector.scan(input, options?)`
Main scan — runs all enabled layers. Options: `{ layer: 'llm' | 'web' | 'api' | 'outbound' | 'ingest' | 'all' }`

### `detector.scanOutbound(url, options?)`
Outbound scan — checks URLs for malicious domains, internal network, protocol abuse, data exfiltration. Options: `{ includeWebSsrf: boolean }`

### `detector.scanIngest(content, options?)`
Ingest scan — detects hidden text, zero-width characters, HTML injection, encoding bypass. Options: `{ includeLlm: boolean }`

### `detector.scanCode(code)`
Code scan — detects API key leaks, dangerous functions, deploy issues, URL threats in code.

### `detector.quickCheck(input)`
Fast check — LLM layer only, returns boolean.

### `detector.getStats()`
Returns rule counts and layer enablement status.

### `detector.reload()`
Reloads all config and rules from disk.

## Configuration

### config.json

```json
{
  "enabled": true,
  "layers": {
    "llm": { "enabled": true },
    "web": { "enabled": true },
    "api": { "enabled": true },
    "supply_chain": { "enabled": true },
    "deploy": { "enabled": true },
    "outbound": { "enabled": true },
    "ingest": { "enabled": true }
  },
  "detection": {
    "confidenceThreshold": 0.6
  }
}
```

## New in v2.0

### Outbound Layer
- **URL Reputation**: Phishing domains, homoglyph attacks, suspicious TLDs, punycode
- **Short Link Detection**: bit.ly, tinyurl, t.co, goo.gl, t.cn, url.cn, and 9 more
- **Internal Network**: 10.x, 172.16.x, 192.168.x, localhost, cloud metadata endpoints
- **Protocol Check**: Blocks file://, gopher://, javascript://, jar://, dict://, smb://
- **Data Exfiltration**: AWS keys, private keys, JWT tokens, credit cards, PII, service tokens

### Ingest Layer
- **Hidden Text**: CSS display:none, font-size:0, offscreen positioning, hidden attributes with prompt injection
- **Zero-Width Characters**: U+200B/200C/200D/FEFF, RLO/LRO reversal, tag characters, dense zero-width detection
- **HTML Injection**: Script tags, event handlers, meta refresh, base tags, iframes, SVG+script, form action
- **Encoding Bypass**: eval(atob()), String.fromCharCode chains, double URL encoding, mixed encoding, hex/unicode escapes

## Self-Learning Loop (自循环学习)

奇点造物-Genesisix v2.0.0 引入自循环机制，可从漏报中自动学习并更新规则。

### 核心流程

```
漏报记录 → 案例分析 → 规则建议 → 人工审核 → 落地规则 → 验证闭环
```

### 使用方法

```javascript
const { SelfLoop, integrateWithDetector } = require('./self_loop');
const Detector = require('./detector');

// 初始化
const detector = new Detector();
const selfLoop = new SelfLoop(__dirname);

// 与检测器集成（自动记录拦截/漏报）
integrateWithDetector(detector, selfLoop);

// 手动记录漏报
selfLoop.logMissedCase({
  input: '被漏检的输入',
  expectedThreat: 'prompt_injection',
  layer: 'llm',
  severity: 'critical'
});

// 分析并生成建议
const suggestions = selfLoop.analyzeAndSuggest();

// 查看待审核建议
const pending = selfLoop.getPendingSuggestions();

// 审核通过（自动落地为规则）
selfLoop.approveSuggestion(suggestions[0].id);

// 拒绝建议
selfLoop.rejectSuggestion(suggestions[0].id, '误报');

// 查看统计
const stats = selfLoop.getStats();
```

### CLI 命令

```bash
node self_loop.js log-missed --input="..." --threat="..."
node self_loop.js log-false-positive --layer="..." --threat="..."
node self_loop.js stats
node self_loop.js pending
node self_loop.js analyze
node self_loop.js approve --id="..."
node self_loop.js reject --id="..." --reason="..."
```

### 测试

```bash
node test/test_self_loop.js
```

## Testing

```bash
# Full test suite (70+ test cases, all 13 layers + boundaries)
node examples/full-test.js

# Self-loop test (9 test cases)
node test/test_self_loop.js

# Interactive mode
node examples/test-interactive.js

# Demo
node detector.js
```

## Performance

- **Latency**: < 10ms per scan (all 13 layers)
- **Memory**: ~100KB
- **Rules**: 825 (JSON-based, lazy load)

## License

MIT

## Changelog

### v2.0.0
- Added **Multilingual Injection** to LLM layer (20 rules) — detects Chinese/Japanese/Korean/French/German/Spanish/Russian/Arabic jailbreak attempts
- Added **Unicode Homoglyph** detection to Ingest layer (12 rules) — detects Cyrillic→Latin substitution attacks
- Added **Trojan Source** detection to Ingest layer (10 rules) — detects Unicode Bidi control characters used to hide malicious code
- Added **Context Overflow** protection — blocks inputs exceeding 100K characters
- Added Outbound layer (5 rule sets, 62 patterns)
- Added Ingest layer (4 rule sets, 45 patterns)
- Added Resource Guard layer (4 rule sets, 40 patterns)
- New `scanOutbound()`, `scanIngest()`, `scanResource()` methods
- Updated `getStats()` to include all 13 layers
- 70+ test cases with boundary testing
- Total rules: 825

### v1.0.0
- Initial release
- 5-layer protection
- 113+ detection rules
