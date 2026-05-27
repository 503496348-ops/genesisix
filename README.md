# 奇点造物-Genesisix v2.0.0

> AI Agent 多层安全检测框架 — 13层防护 + 自循环学习 + Hook系统 + 825条规则

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](_meta.json)

## 这是什么

奇点造物-Genesisix 是专为 AI Agent 系统设计的安全中间件，在输入到达大模型之前进行多层扫描，拦截恶意指令、数据外泄、工具投毒等攻击。

**OpenClaw版**是JavaScript/Node.js实现，适用于OpenClaw多Agent系统。

## 快速开始

```javascript
const Detector = require('./detector');
const detector = new Detector();

// 扫描用户输入
const result = detector.scanSync('用户说的话');
if (!result.safe) {
  console.log('拦截:', result.threats);
  console.log('动作:', result.action); // 'pass' | 'alert' | 'block'
}
```

## 13层防护

| 层 | 检测内容 | 规则数 |
|----|---------|--------|
| Resource Guard | SSRF/内网IP/危险协议/危险路径/域名白名单/端口扫描 | 40 |
| Preprocess | 结构化清理/编码归一化/金丝雀注入/元数据提取 | — |
| Ingest | 零宽字符/同形字/Trojan Source/隐藏文本/编码绕过 | 67 |
| LLM | Prompt注入/越狱/多语言绕过/Few-Shot/间接注入/多轮越狱/提示泄露 | 141 |
| Web | SQL注入/XSS/CSRF/SSRF/命令注入/路径遍历/SSTI/XXE | 88 |
| API | 密钥泄露/速率限制/认证绕过/GraphQL/JWT/OAuth | 53 |
| Outbound | PII泄露/DNS外泄/恶意URL/短链接/内网地址 | 88 |
| MCP Security | 工具投毒/Schema验证/危险工具/数据外泄/OAuth/签名 | 111 |
| Supply Chain | 危险依赖/Typosquat/恶意导入/Skill完整性 | 49 |
| Deploy | 环境变量泄露/Docker/CI-CD/源码泄露 | 25 |
| Memory | 记忆投毒/Checkpoint篡改 | 20 |
| Integrity | Profile后门/反向Shell/凭据窃取 | 22 |
| Multi-Agent | 跨Agent注入/身份冒充/工具链攻击/信任评估 | 85 |

## 专用 API

```javascript
const detector = new Detector();

// 资源安全扫描（SSRF/协议/路径/端口）
detector.scanResource('http://127.0.0.1:6379/');

// MCP工具扫描
detector.scanMCP(toolSchema, toolOutput);

// 外发数据扫描
detector.scanOutbound('https://api.example.com/data');

// 记忆安全扫描
detector.scanMemory(memoryContent);

// Profile完整性扫描
detector.scanIntegrity(agentsMdContent, 'AGENTS.md');

// 多Agent安全扫描
detector.scanMultiAgent(message, { sourceAgent: 'user', targetAgent: 'coder' });

// 多轮越狱扫描
detector.scanMultiturn(recentMessages, { windowSize: 10 });

// 摄入层扫描
detector.scanIngest(content, { includeLlm: true });

// 代码扫描
detector.scanCode(codeContent);

// 快速检查（仅LLM层）
const safe = detector.quickCheck(inputText);

// 统计信息
const stats = detector.getStats();

// 热重载
detector.reload();
```

## Hook 系统

```javascript
const detector = new Detector();

// 扫描前拦截
detector.beforeScan((ctx) => {
  if (ctx.input.length > 50000) return { reject: true, rejectReason: 'too long' };
  return ctx;
});

// 发现威胁时记录
detector.onThreat((ctx) => console.log('威胁:', ctx.threat));

// 扫描后修改结果
detector.afterScan((ctx) => ctx);

// 注销hook
const unsub = detector.onThreat(myCallback);
unsub(); // 移除
```

## 白名单

在 `whitelist.json` 中配置：

```json
{
  "users": ["admin-user-id"],
  "sessions": ["trusted-session-id"],
  "keywords": ["系统状态查询"],
  "patterns": ["^test_.*"]
}
```

## 置信度阈值

在 `config.json` 中配置：

```json
{
  "detection": {
    "alert_threshold": 0.5,
    "block_threshold": 0.8
  }
}
```

## 自循环学习

```javascript
const SelfLoop = require('./self_loop');
const loop = new SelfLoop();

// 记录漏报
loop.logMissedCase({ input: '恶意输入', expectedThreat: 'prompt_injection', layer: 'llm' });

// 分析并生成规则建议
const suggestions = loop.analyzeAndSuggest();

// 审核落地
loop.approveSuggestion(suggestions[0].id);
```

## 安装

```bash
# 克隆仓库
git clone https://github.com/503496348-ops/genesisix.git
cd genesisix

# 安装依赖（可选）
npm install

# 运行测试
node test/comprehensive-test.js
```

## 外部工具集成

| 工具 | Stars | 集成方式 |
|------|-------|---------|
| safe-mcp | 337 | MCP威胁分类体系 |
| agentseal | 239 | Skill完整性校验 |
| slowmist | 445 | 零信任审查 |
| claude-forge | 685 | 6层安全hooks |
| fireclaw | 17 | 4-stage预处理 |
| SchemaPin | 15 | Schema签名验证 |
| deepsafe-scan | 69 | Profile后门检测 |
| g0 | 46 | 规则扩展 |
| ClawArmor | 18 | 多Agent防护 |

## 版本历史

| 版本 | 变化 |
|------|------|
| v2.0.0 | +7层(Resource Guard/Preprocess/Ingest/Outbound/MCP/Memory/Integrity/Multi-Agent) +Hook系统 +白名单 +置信度阈值 +全部专用API +SelfLoop集成 +825条规则 |
| v1.5.0 | 6层防护 + 自循环门禁 |
| v1.0.0 | 初始版本 |

## License

MIT © 2026 奇点造物-Genesisix Security Lab
