/**
 * LLM Layer Detector / LLM层检测器
 * Detects: Prompt Injection, Jailbreak, Prompt Leaking, Encoding Obfuscation, Multilingual Injection,
 *          Indirect Injection (RAG/External), Few-Shot Injection
 * 检测: 提示注入、越狱、提示泄露、编码混淆、多语言注入、间接注入、Few-Shot注入
 */

const fs = require('fs');
const path = require('path');

class LLMDetector {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.rules = {};
    this.config = {};
    this.whitelist = {};
    this._init();
  }

  _init() {
    // 加载配置
    const configPath = path.join(this.skillPath, 'config.json');
    if (fs.existsSync(configPath)) {
      this.config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    }

    // 加载白名单
    const whitelistPath = path.join(this.skillPath, 'whitelist.json');
    if (fs.existsSync(whitelistPath)) {
      this.whitelist = JSON.parse(fs.readFileSync(whitelistPath, 'utf-8'));
    }

    // 加载规则文件
    const rulesDir = path.join(this.skillPath, 'rules');
    if (fs.existsSync(rulesDir)) {
      const ruleFiles = [
        'injection.json',
        'jailbreak.json',
        'prompt_leak.json',
        'encoding.json',
        'llm/multilingual_injection.json',
        'llm/indirect_injection.json',
        'llm/few_shot_injection.json',
        'llm/prompt_firewall.json',
        'llm/multiturn_jailbreak.json',
        'indirect_injection.json'
      ];
      ruleFiles.forEach(file => {
        const filePath = path.join(rulesDir, file);
        if (fs.existsSync(filePath)) {
          const ruleData = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
          this.rules[ruleData.category] = ruleData;
        }
      });
    }
  }

  /**
   * 检查是否匹配白名单
   * @param {string} input - 用户输入
   * @returns {boolean}
   */
  _checkWhitelist(input) {
    if (!this.whitelist.patterns) return false;

    for (const pattern of this.whitelist.patterns) {
      const { safeRegexTest } = require('../utils/regex_safety');
      const result = safeRegexTest(pattern, input);
      if (result.timeout || result.error) continue; // 超时/错误跳过白名单检查
      if (result.matched) {
        return true;
      }
    }

    if (this.whitelist.keywords) {
      for (const keyword of this.whitelist.keywords) {
        if (input.toLowerCase().includes(keyword.toLowerCase())) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * 检测单个规则类别
   * @param {string} input - 用户输入
   * @param {object} ruleSet - 规则集
   * @returns {Array} 匹配的威胁
   */
  _detectCategory(input, ruleSet) {
    const threats = [];
    if (!ruleSet || !ruleSet.patterns) return threats;

    for (const rule of ruleSet.patterns) {
      try {
        const { safeRegexTest } = require('../utils/regex_safety');
        const result = safeRegexTest(rule.pattern, input);
        if (result.timeout) {
          threats.push({
            id: rule.id + '-REDoS',
            category: ruleSet.category,
            name: ruleSet.name,
            severity: 'medium',
            weight: 0.5,
            matched: 'REGEX_TIMEOUT'
          });
          continue;
        }
        if (result.error) continue;
        if (result.matched) {
          const regex = new RegExp(rule.pattern, 'i');
          threats.push({
            id: rule.id,
            category: ruleSet.category,
            name: ruleSet.name,
            severity: rule.severity,
            weight: rule.weight,
            matched: input.match(regex)?.[0] || ''
          });
        }
      } catch (e) {
        console.error(`Regex error for rule ${rule.id}:`, e.message);
      }
    }

    return threats;
  }

  /**
   * 执行检测
   * @param {string} input - 用户输入
   * @returns {object} 检测结果
   */
  detect(input) {
    // 类型守卫
    if (!input || typeof input !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    // 白名单检查
    if (this._checkWhitelist(input)) {
      return {
        safe: true,
        threats: [],
        confidence: 1.0,
        whitelist: true
      };
    }

    const allThreats = [];
    const categories = [
      'injection',
      'jailbreak',
      'prompt_leak',
      'encoding',
      'multilingual_injection',
      'indirect_injection',
      'rag_indirect_injection',
      'few_shot_injection',
      'prompt_firewall'
    ];

    for (const category of categories) {
      if (this.rules[category]) {
        const threats = this._detectCategory(input, this.rules[category]);
        allThreats.push(...threats);
      }
    }

    // 计算置信度
    const confidence = this._calculateConfidence(allThreats);
    const safe = allThreats.length === 0 || confidence < (this.config.detection?.confidenceThreshold || 0.6);

    return {
      safe,
      threats: allThreats,
      confidence,
      scannedAt: new Date().toISOString()
    };
  }

  /**
   * 计算威胁置信度
   * @param {Array} threats - 威胁列表
   * @returns {number} 置信度 0-1
   */
  _calculateConfidence(threats) {
    if (threats.length === 0) return 0;

    // 按权重和严重性计算
    const severityWeights = {
      critical: 1.0,
      high: 0.8,
      medium: 0.5,
      low: 0.2
    };

    let totalWeight = 0;
    let maxSeverity = 0;

    for (const threat of threats) {
      const severityValue = severityWeights[threat.severity] || 0.5;
      totalWeight += (threat.weight || 0.5) * severityValue;
      maxSeverity = Math.max(maxSeverity, severityValue);
    }

    // 组合计算
    const avgWeight = totalWeight / threats.length;
    const combined = (avgWeight + maxSeverity) / 2;

    return Math.min(combined, 1.0);
  }

  /**
   * 多轮对话越狱检测
   * @param {Array<string|object>} messages - 最近N条消息，可以是字符串或 {role, content} 对象
   * @param {object} options - { windowSize?, phaseThreshold? }
   * @returns {object} { safe, threats, confidence, phases }
   */
  detectMultiturn(messages, options = {}) {
    if (!Array.isArray(messages) || messages.length === 0) {
      return { safe: true, threats: [], confidence: 0, phases: [] };
    }

    const windowSize = options.windowSize || 10;
    const recentMessages = messages.slice(-windowSize);
    
    // 提取用户消息文本
    const userTexts = recentMessages.map(m => {
      if (typeof m === 'string') return m;
      return m?.content || m?.text || '';
    }).filter(t => t.length > 0);

    if (userTexts.length === 0) {
      return { safe: true, threats: [], confidence: 0, phases: [] };
    }

    // 合并文本用于模式匹配
    const combinedText = userTexts.join('\n');
    const allThreats = [];
    const detectedPhases = new Set();

    // 加载多轮越狱规则
    const mtRules = this.rules['multiturn_jailbreak'];
    if (mtRules && mtRules.patterns) {
      for (const rule of mtRules.patterns) {
        try {
          const { safeRegexTest } = require('../utils/regex_safety');
          // 在每条用户消息上单独检测
          for (let i = 0; i < userTexts.length; i++) {
            const mtResult = safeRegexTest(rule.pattern, userTexts[i]);
            if (mtResult.timeout || mtResult.error) continue;
            if (mtResult.matched) {
              const regex = new RegExp(rule.pattern, 'i');
              allThreats.push({
                id: rule.id,
                category: 'multiturn_jailbreak',
                name: 'Multi-Turn Jailbreak',
                severity: rule.severity,
                weight: rule.weight,
                matched: userTexts[i].match(regex)?.[0] || '',
                messageIndex: i,
                phase: rule.multiturn_phase || 'unknown'
              });
              if (rule.multiturn_phase) {
                detectedPhases.add(rule.multiturn_phase);
              }
            }
          }
        } catch (e) {
          console.error(`Multiturn regex error for rule ${rule.id}:`, e.message);
        }
      }
    }

    // 阶段分析：检测渐进式攻击模式
    const phaseAnalysis = this._analyzePhases(detectedPhases, userTexts.length);

    // 计算置信度（阶段越完整，置信度越高）
    const baseConfidence = this._calculateConfidence(allThreats);
    const phaseBonus = phaseAnalysis.escalationScore * 0.3;
    const confidence = Math.min(baseConfidence + phaseBonus, 1.0);

    const safe = allThreats.length === 0 || confidence < (this.config.detection?.confidenceThreshold || 0.6);

    return {
      safe,
      threats: allThreats,
      confidence,
      phases: [...detectedPhases],
      phaseAnalysis,
      messagesAnalyzed: userTexts.length,
      scannedAt: new Date().toISOString()
    };
  }

  /**
   * 分析攻击阶段进展
   * @private
   */
  _analyzePhases(detectedPhases, messageCount) {
    const phaseOrder = ['probe', 'hypothetical', 'escalate', 'execute'];
    const detected = phaseOrder.filter(p => detectedPhases.has(p));
    
    // 阶段连续性评分
    let maxConsecutive = 0;
    let current = 0;
    for (const phase of phaseOrder) {
      if (detectedPhases.has(phase)) {
        current++;
        maxConsecutive = Math.max(maxConsecutive, current);
      } else {
        current = 0;
      }
    }

    return {
      detectedPhases: detected,
      totalPhasesDetected: detected.length,
      maxConsecutivePhases: maxConsecutive,
      escalationScore: maxConsecutive / phaseOrder.length,
      riskLevel: maxConsecutive >= 3 ? 'critical' : maxConsecutive >= 2 ? 'high' : maxConsecutive >= 1 ? 'medium' : 'low',
      pattern: detected.length >= 3 ? 'progressive_escalation' : detected.length >= 2 ? 'partial_escalation' : 'single_phase'
    };
  }

  /**
   * 重新加载规则
   */
  reload() {
    this._init();
  }
}

module.exports = LLMDetector;
