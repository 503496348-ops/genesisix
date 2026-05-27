/**
 * Profile Integrity Detector / Profile完整性检测层
 * Detects: AGENTS.md/SOUL.md/CLAUDE.md/.cursorrules/.windsurfrules后门、Hooks注入、凭证泄露
 * 基于: deepsafe-scan hooks module + g0 goal-integrity/code-execution rules
 *
 * @version 2.3.0
 */

const fs = require('fs');
const path = require('path');

class IntegrityDetector {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.rules = {};
    this._loadRules();
  }

  _loadRules() {
    const rulesDir = path.join(this.skillPath, 'rules', 'integrity');
    if (!fs.existsSync(rulesDir)) return;

    const ruleFiles = ['profile_backdoor.json'];

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
   * 检测Profile配置文件中的后门和恶意注入
   * @param {string} content - Profile配置文件内容（AGENTS.md/SOUL.md/CLAUDE.md等）
   * @param {object} options - 可选参数 { filename?: string }
   * @returns {object} { safe, threats, confidence }
   */
  detect(content, options = {}) {
    if (!content || typeof content !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    // 扫描所有后门规则
    const ruleData = this.rules['profile_backdoor'];
    if (!ruleData || !ruleData.patterns) {
      return { safe: true, threats: [], confidence: 0 };
    }

    for (const pattern of ruleData.patterns) {
      try {
        const { safeRegexTestGlobal } = require('../utils/regex_safety');
        const result = safeRegexTestGlobal(pattern.pattern, content);
        if (result.timeout) {
          threats.push({ type: 'integrity', id: pattern.id + '-REDoS', severity: 'medium', description: '正则超时跳过: ' + pattern.id, confidence: 0.5 });
          maxConfidence = Math.max(maxConfidence, 0.5);
          continue;
        }
        if (result.error) continue;
        if (result.matched) {
          threats.push({
            type: 'profile_backdoor',
            pattern: pattern.id,
            severity: pattern.severity,
            confidence: pattern.weight,
            description: pattern.description,
            source: options.filename || 'unknown_profile'
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
   * 扫描Profile文件路径列表
   * @param {string} dir - 要扫描的目录
   * @returns {object} { safe, threats, filesScanned }
   */
  scanDirectory(dir) {
    const profileFiles = [
      'AGENTS.md', 'SOUL.md', 'CLAUDE.md', 'SKILL.md', 'MEMORY.md',
      '.cursorrules', '.windsurfrules', '.clinerules',
      '.cursor/rules.md', '.windsurf/rules.md', '.github/copilot-instructions.md',
      '.claude/settings.json', '.claude/settings.local.json',
      '.vscode/tasks.json', '.vscode/settings.json'
    ];

    const allThreats = [];
    const filesScanned = [];

    for (const filename of profileFiles) {
      const filePath = path.join(dir, filename);
      if (fs.existsSync(filePath)) {
        try {
          const content = fs.readFileSync(filePath, 'utf-8');
          const result = this.detect(content, { filename });
          if (!result.safe) {
            allThreats.push(...result.threats);
          }
          filesScanned.push(filePath);
        } catch (e) {
          // Skip unreadable files
        }
      }
    }

    return {
      safe: allThreats.length === 0,
      threats: allThreats,
      confidence: allThreats.length > 0 ? Math.max(...allThreats.map(t => t.confidence)) : 0,
      filesScanned
    };
  }

  reload() {
    this.rules = {};
    this._loadRules();
  }
}

module.exports = IntegrityDetector;
