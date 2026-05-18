# 🛡️ 奇点造物-Genesisix OpenClaw版

**版本**: V1.5 | **日期**: 2026-05-19 | **作者**: 小乖（守夜人）

---

**企业级 AI Agent 多层安全检测框架**，专为 OpenClaw 多智能体系统量身打造。

## 核心能力

### 🚀 6层防护
- LLM层：提示词注入、越狱、编码绕过
- Web层：SQL 注入、XSS、SSRF
- API层：密钥泄露、认证问题
- 供应链层：危险依赖
- 部署层：环境变量泄露
- 资源守卫：内网 IP 访问

### 🔄 自循环门禁
```
拦截事件 → 记录案例库 → 分析漏报 → 生成规则建议 → 人工审核 → 更新规则库
```

## 🚀 快速开始

```bash
git clone https://github.com/503496348-ops/genesisix.git
cd genesisix
npm install
node examples/test.js
```

```javascript
const genesisix = require('./detector.js');
const result = genesisix.detector.scan('用户输入内容');
if (!result.safe) console.log('检测到威胁:', result.threats);
```

## 📁 文件结构

```
genesisix/
├── detector.js / self_loop.js / unified_logger.js
├── layers/     # LLM/Web/API/SupplyChain/Deploy/ResourceGuard
├── rules/     # llm/web/api/deploy/supply_chain
├── hook/      # OpenClaw Hook 集成
├── examples/  # 使用示例
├── SKILL.md   # Skill说明书
└── PRD_V1.5.md # 完整PRD
```

## 🤝 关联项目

- **Hermes版**: https://github.com/503496348-ops/genesisix-hermes
- **Wanderix**: https://github.com/503496348-ops/Wanderix

---

**敬自由，敬热爱，敬同行，敬来日方长。**

*MIT License | 🛡️ by Genesisix Security Lab*
