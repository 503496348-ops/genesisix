/**
 * Outbound Layer Detector / 出站层安全检测器
 * Detects: Malicious URLs, Short Links, Internal Network, Protocol Abuse, Data Exfiltration, PII Exfil, DNS Exfil
 * 检测: 恶意URL、短链接、内网地址、协议滥用、数据外泄、PII泄露、DNS外泄
 */

const fs = require('fs');
const path = require('path');

class OutboundDetector {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.rules = {};
    this._loadRules();
  }

  _loadRules() {
    const rulesDir = path.join(this.skillPath, 'rules', 'outbound');
    if (!fs.existsSync(rulesDir)) return;

    const ruleFiles = [
      'url_reputation.json',
      'short_link.json',
      'internal_network.json',
      'protocol_check.json',
      'data_exfiltration.json',
      'pii_exfil.json',
      'dns_exfil.json'
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
   * 出站层检测入口
   * @param {string} input - URL / 请求内容 / 请求 body
   * @returns {object} { safe, threats, confidence }
   */
  detect(input) {
    if (!input || typeof input !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    const results = [
      this._detectUrlReputation(input),
      this._detectShortLink(input),
      this._detectInternalNetwork(input),
      this._detectProtocolCheck(input),
      this._detectDataExfiltration(input),
      this._detectPiiExfil(input),
      this._detectDnsExfil(input)
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

  _detectUrlReputation(input) {
    return this._matchRules(input, this.rules.url_reputation, 'url_reputation');
  }

  _detectShortLink(input) {
    return this._matchRules(input, this.rules.short_link, 'short_link');
  }

  _detectInternalNetwork(input) {
    return this._matchRules(input, this.rules.internal_network, 'internal_network');
  }

  _detectProtocolCheck(input) {
    return this._matchRules(input, this.rules.protocol_check, 'protocol_check');
  }

  _detectDataExfiltration(input) {
    return this._matchRules(input, this.rules.data_exfiltration, 'data_exfiltration');
  }

  _detectPiiExfil(input) {
    return this._matchRules(input, this.rules.pii_exfil, 'pii_exfil');
  }

  _detectDnsExfil(input) {
    return this._matchRules(input, this.rules.dns_exfil, 'dns_exfil');
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

module.exports = OutboundDetector;
