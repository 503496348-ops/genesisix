/**
 * Memory Layer Detector / 记忆层安全检测器
 * Detects: Memory Injection, Checkpoint Tampering
 * 检测: 记忆注入、Checkpoint篡改
 */

const fs = require('fs');
const path = require('path');

class MemoryDetector {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.rules = {};
    this._loadRules();
  }

  _loadRules() {
    const rulesDir = path.join(this.skillPath, 'rules', 'memory');
    if (!fs.existsSync(rulesDir)) return;

    const ruleFiles = [
      'memory_injection.json',
      'checkpoint_tamper.json'
    ];

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
   * 记忆层检测入口
   * @param {string} content - 待检测的记忆内容/checkpoint数据
   * @returns {object} { safe, threats, confidence }
   */
  detect(content) {
    if (!content || typeof content !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    const results = [
      this._detectMemoryInjection(content),
      this._detectCheckpointTamper(content)
    ];

    results.forEach(result => {
      if (result.threats.length > 0) {
        threats.push(...result.threats);
        maxConfidence = Math.max(maxConfidence, result.confidence);
      }
    });

    return {
      safe: threats.length === 0,
      threats,
      confidence: maxConfidence
    };
  }

  _detectMemoryInjection(content) {
    return this._matchRules(content, this.rules.memory_injection, 'memory_injection');
  }

  _detectCheckpointTamper(content) {
    return this._matchRules(content, this.rules.checkpoint_tamper, 'checkpoint_tamper');
  }

  _matchRules(input, ruleSet, type) {
    if (!ruleSet || !ruleSet.patterns) {
      return { threats: [], confidence: 0 };
    }

    const { safeRegexTestGlobal } = require('../utils/regex_safety');
    const threats = [];

    for (const pattern of ruleSet.patterns) {
      const result = safeRegexTestGlobal(pattern.pattern, input);
      if (result.timeout) {
        threats.push({ type, id: pattern.id + '-REDoS', severity: 'medium', description: '正则超时跳过: ' + pattern.id, confidence: 0.5, pattern: pattern.pattern });
        continue;
      }
      if (result.error) continue;
      if (result.matched) {
          threats.push({
            type,
            id: pattern.id,
            name: ruleSet.name,
            severity: pattern.severity,
            description: pattern.description,
            confidence: pattern.weight,
            pattern: pattern.pattern
          });
        }

    }

    const confidence = threats.length > 0
      ? Math.max(...threats.map(t => t.confidence))
      : 0;

    return { threats, confidence };
  }

  reload() {
    this.rules = {};
    this._loadRules();
  }
}

module.exports = MemoryDetector;
