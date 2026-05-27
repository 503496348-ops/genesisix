/**
 * Ingest Layer Detector / 输入层安全检测器
 * Detects: Hidden Text, Zero-Width Characters, HTML Injection, Encoding Bypass
 * 检测: 隐藏文本、零宽字符、HTML注入、编码混淆绕过
 */

const fs = require('fs');
const path = require('path');

class IngestDetector {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.rules = {};
    this._loadRules();
  }

  _loadRules() {
    const rulesDir = path.join(this.skillPath, 'rules', 'ingest');
    if (!fs.existsSync(rulesDir)) return;

    const ruleFiles = [
      'hidden_text.json',
      'zero_width.json',
      'html_injection.json',
      'encoding_bypass.json',
      'homoglyph.json',
      'trojan_source.json'
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
   * 输入层检测入口
   * @param {string} input - 待检测的原始输入内容
   * @returns {object} { safe, threats, confidence }
   */
  detect(input) {
    if (!input || typeof input !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    const results = [
      this._detectHiddenText(input),
      this._detectZeroWidth(input),
      this._detectHtmlInjection(input),
      this._detectEncodingBypass(input),
      this._detectHomoglyph(input),
      this._detectTrojanSource(input)
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

  _detectHiddenText(input) {
    return this._matchRules(input, this.rules.hidden_text, 'hidden_text');
  }

  _detectZeroWidth(input) {
    return this._matchRules(input, this.rules.zero_width, 'zero_width');
  }

  _detectHtmlInjection(input) {
    return this._matchRules(input, this.rules.html_injection, 'html_injection');
  }

  _detectEncodingBypass(input) {
    return this._matchRules(input, this.rules.encoding_bypass, 'encoding_bypass');
  }

  _detectHomoglyph(input) {
    return this._matchRules(input, this.rules.homoglyph, 'homoglyph');
  }

  _detectTrojanSource(input) {
    return this._matchRules(input, this.rules.trojan_source, 'trojan_source');
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

module.exports = IngestDetector;
