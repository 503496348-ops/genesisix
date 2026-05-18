---
name: 奇点造物-Genesisix
version: 1.5.0
description: Multi-layer security detector for AI agents with self learning loop. 6-Layer Protection + Resource Guard + Self-Learning. Blocks prompt injection, jailbreak, XSS, SQL injection, API key leaks, SSRF, internal IP access, and more.
---

# 奇点造物-Genesisix 🛡️ v1.5

> Enterprise-grade security detector with self learning loop

## v1.5 修复内容

### Bug修复
1. **Resource Guard集成到scan()** ✅ — 现在自动检测输入中的URL并验证安全性
2. **空catch块修复** ✅ — 所有catch块现在至少记录错误日志
3. **approveSuggestion()真正写入** ✅ — 规则自动追加到JSON文件

## 6-Layer Protection + Resource Guard

| Layer | Threats | 
|-------|---------|
| **LLM** | Prompt Injection, Jailbreak, Encoding |
| **Web** | SQL Injection, XSS, CSRF, SSRF |
| **API** | Key Exposure, Rate Limiting |
| **Supply Chain** | Dangerous Dependencies |
| **Deploy** | Env Leaks, Debug Info |
| **Resource Guard** | SSRF, Internal IP, Dangerous Protocol |

## Usage

```javascript
const { scan, ResourceGuard } = require('./detector');

// 扫描用户输入（自动检测URL）
const result = scan('user input or URL');

// 自循环
const { logCase, logMissedCase, getStats, approveSuggestion } = require('./self_loop');
```

## Testing

```bash
node examples/test.js
python3 test_coverage.py
python3 test_resource_guard.py
```
