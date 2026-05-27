/**
 * Supply Chain Detector / 供应链安全检测器
 * Detects: Malicious Dependencies, Dangerous Imports, Code Execution
 * 检测: 恶意依赖、危险导入、代码执行
 */

const fs = require('fs');
const path = require('path');

class SupplyChainDetector {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.rules = {};
    this._loadRules();
  }

  _loadRules() {
    const rulesDir = path.join(this.skillPath, 'rules', 'supply_chain');
    const ruleFiles = ['deps.json', 'typosquat.json', 'malicious_import.json', 'skill_integrity.json'];
    this.allRules = [];

    ruleFiles.forEach(file => {
      const filePath = path.join(rulesDir, file);
      if (fs.existsSync(filePath)) {
        const ruleData = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        this.allRules.push(ruleData);
        // 兼容旧逻辑：deps.json 仍写入 this.rules
        if (file === 'deps.json') {
          this.rules = ruleData;
        }
      }
    });
  }

  detect(input) {
    if (!input || typeof input !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    // 遍历所有加载的规则集（deps.json + typosquat.json + malicious_import.json）
    for (const ruleSet of (this.allRules || [this.rules])) {
      if (!ruleSet || !ruleSet.patterns) continue;

      for (const pattern of ruleSet.patterns) {
        try {
          const { safeRegexTestGlobal } = require('../utils/regex_safety');
          const result = safeRegexTestGlobal(pattern.pattern, input);
          if (result.timeout) {
            threats.push({ type: 'supply_chain', pattern: pattern.id + '-REDoS', severity: 'medium', confidence: 0.5, description: '正则超时跳过: ' + pattern.id });
            maxConfidence = Math.max(maxConfidence, 0.5);
            continue;
          }
          if (result.error) continue;
          if (result.matched) {
            threats.push({
              type: pattern.category || ruleSet.category || 'supply_chain',
              pattern: pattern.id,
              severity: pattern.severity,
              confidence: pattern.weight,
              description: pattern.description
            });
            maxConfidence = Math.max(maxConfidence, pattern.weight);
          }
        } catch (e) {
          // Skip invalid regex
        }
      }
    }

    return {
      safe: threats.length === 0,
      threats,
      confidence: maxConfidence
    };
  }
}

module.exports = SupplyChainDetector;
