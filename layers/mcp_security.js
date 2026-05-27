/**
 * MCP Security Detector / MCP安全检测器
 * Detects: Tool Poisoning, Schema Validation, Dangerous Tools, Output Exfiltration
 * 检测: 工具描述投毒、Schema格式验证、高危工具名/模式、工具返回值数据外泄
 *
 * @version 2.2.0
 */

const fs = require('fs');
const path = require('path');

class MCPSecurityDetector {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.rules = {};
    this._loadRules();
  }

  _loadRules() {
    const rulesDir = path.join(this.skillPath, 'rules', 'mcp_security');
    if (!fs.existsSync(rulesDir)) return;

    const ruleFiles = ['tool_poisoning.json', 'schema_validation.json', 'dangerous_tools.json', 'tool_exfil.json', 'mcp_audit.json', 'safe_mcp_threats.json', 'oauth_security.json', 'schema_signature.json'];

    ruleFiles.forEach(file => {
      const filePath = path.join(rulesDir, file);
      if (fs.existsSync(filePath)) {
        const ruleData = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        const category = ruleData.category || file.replace('.json', '');
        this.rules[category] = ruleData;
      }
    });
  }

  /**
   * 扫描MCP工具Schema（工具描述、参数定义）
   * @param {string|object} toolSchema - 工具schema（JSON字符串或对象）
   * @returns {object} { safe, threats, confidence }
   */
  detectSchema(toolSchema) {
    if (!toolSchema) {
      return { safe: true, threats: [], confidence: 0 };
    }

    // 规范化为字符串以便正则匹配
    const input = typeof toolSchema === 'string' ? toolSchema : JSON.stringify(toolSchema);

    const threats = [];
    let maxConfidence = 0;

    // 扫描工具投毒、schema验证、MCP审计和safe-mcp威胁规则
    const relevantCategories = ['tool_poisoning', 'schema_validation', 'dangerous_tools', 'mcp_audit', 'safe_mcp_threats', 'oauth_security', 'schema_signature'];

    for (const category of relevantCategories) {
      const ruleData = this.rules[category];
      if (!ruleData || !ruleData.patterns) continue;

      for (const pattern of ruleData.patterns) {
        try {
          const { safeRegexTestGlobal } = require('../utils/regex_safety');
          const result = safeRegexTestGlobal(pattern.pattern, input);
          if (result.timeout) {
            threats.push({ type: category, pattern: pattern.id + '-REDoS', severity: 'medium', confidence: 0.5, description: '正则超时跳过: ' + pattern.id });
            maxConfidence = Math.max(maxConfidence, 0.5);
            continue;
          }
          if (result.error) continue;
          if (result.matched) {
            threats.push({
              type: category,
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

  /**
   * 扫描MCP工具输出值（检测数据外泄）
   * @param {string} toolOutput - 工具返回值
   * @returns {object} { safe, threats, confidence }
   */
  detectOutput(toolOutput) {
    if (!toolOutput || typeof toolOutput !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    // 仅扫描工具输出外泄规则
    const ruleData = this.rules['tool_exfil'];
    if (!ruleData || !ruleData.patterns) {
      return { safe: true, threats: [], confidence: 0 };
    }

    for (const pattern of ruleData.patterns) {
      try {
        const { safeRegexTestGlobal } = require('../utils/regex_safety');
        const result = safeRegexTestGlobal(pattern.pattern, toolOutput);
        if (result.timeout) {
          threats.push({ type: 'tool_exfil', pattern: pattern.id + '-REDoS', severity: 'medium', confidence: 0.5, description: '正则超时跳过: ' + pattern.id });
          maxConfidence = Math.max(maxConfidence, 0.5);
          continue;
        }
        if (result.error) continue;
        if (result.matched) {
          threats.push({
            type: 'tool_exfil',
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

    return {
      safe: threats.length === 0,
      threats,
      confidence: maxConfidence
    };
  }

  /**
   * 综合扫描MCP工具Schema和输出
   * @param {string|object} toolSchema - 工具schema
   * @param {string} toolOutput - 工具返回值
   * @returns {object} { safe, threats, confidence, details }
   */
  detect(toolSchema, toolOutput) {
    const schemaResult = this.detectSchema(toolSchema);
    const outputResult = this.detectOutput(toolOutput);

    const allThreats = [...schemaResult.threats, ...outputResult.threats];
    const maxConfidence = Math.max(schemaResult.confidence, outputResult.confidence);

    return {
      safe: allThreats.length === 0,
      threats: allThreats,
      confidence: maxConfidence,
      details: {
        schema: { safe: schemaResult.safe, threatCount: schemaResult.threats.length },
        output: { safe: outputResult.safe, threatCount: outputResult.threats.length }
      }
    };
  }

  reload() {
    this.rules = {};
    this._loadRules();
  }
}

module.exports = MCPSecurityDetector;
