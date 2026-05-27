/**
 * 奇点造物-Genesisix Self-Learning Loop / 自循环学习模块
 * 
 * 核心流程：漏报记录 → 案例分析 → 规则建议 → 人工审核 → 落地规则 → 验证闭环
 * 
 * 基于 Genesisix 自循环机制，适配 奇点造物-Genesisix 12层/713规则架构
 * 
 * @author 码仔 (ma_coder)
 * @version 1.0.0
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============================================================
// 常量
// ============================================================

const DEFAULT_CONFIG = {
  caseDbPath: 'data/case_database.jsonl',
  suggestionsPath: 'data/rule_suggestions.json',
  rulesDir: 'rules',
  minCasesForSuggestion: 3,      // 最少漏报数才触发建议
  maxCaseInputLength: 500,        // 输入截断长度
  autoApproveThreshold: 0,        // 0 = 不自动审核，需人工
  statsWindowSize: 1000,          // 统计窗口大小
};

// ============================================================
// 数据模型
// ============================================================

/**
 * @typedef {Object} MissedCase
 * @property {string} id - 唯一ID
 * @property {string} timestamp - ISO时间戳
 * @property {string} type - 'missed'
 * @property {string} input - 被漏检的输入（截断）
 * @property {string} expectedThreat - 期望检测到的威胁类型
 * @property {string} actualResult - 实际检测结果
 * @property {string} layer - 漏报发生的层
 * @property {string} severity - critical/high/medium/low
 * @property {string} notes - 备注
 * @property {Object} metadata - 额外元数据
 */

/**
 * @typedef {Object} BlockedCase
 * @property {string} id - 唯一ID
 * @property {string} timestamp - ISO时间戳
 * @property {string} type - 'blocked'
 * @property {string} layer - 拦截层
 * @property {string} threatType - 威胁类型
 * @property {string} threatDescription - 威胁描述
 * @property {boolean} falsePositive - 是否误报
 * @property {Object} metadata - 额外元数据
 */

/**
 * @typedef {Object} RuleSuggestion
 * @property {string} id - 建议ID
 * @property {string} timestamp - 生成时间
 * @property {string} layer - 目标层
 * @property {string} ruleSet - 目标规则集
 * @property {string} pattern - 建议的模式
 * @property {string} description - 描述
 * @property {string} severity - 严重程度
 * @property {number} confidence - 置信度 0-1
 * @property {string[]} sourceCases - 来源案例ID列表
 * @property {string} status - pending/approved/rejected
 * @property {string} [approvedAt] - 审核时间
 * @property {string} [rejectedAt] - 拒绝时间
 * @property {string} [rejectionReason] - 拒绝原因
 */

// ============================================================
// SelfLoop 核心类
// ============================================================

class SelfLoop {
  /**
   * @param {string} skillPath - 奇点造物-Genesisix 根目录
   * @param {Object} config - 配置覆盖
   */
  constructor(skillPath = __dirname, config = {}) {
    this.skillPath = skillPath;
    this.config = { ...DEFAULT_CONFIG, ...config };
    
    // 解析绝对路径
    this.caseDbPath = path.resolve(skillPath, this.config.caseDbPath);
    this.suggestionsPath = path.resolve(skillPath, this.config.suggestionsPath);
    this.rulesDir = path.resolve(skillPath, this.config.rulesDir);
    
    // 确保数据目录存在
    this._ensureDir(path.dirname(this.caseDbPath));
  }

  // ============================================================
  // 内部工具
  // ============================================================

  _ensureDir(dir) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  _now() {
    return new Date().toISOString();
  }

  _generateId(prefix = 'case') {
    const ts = Date.now().toString(36);
    const rand = crypto.randomBytes(4).toString('hex');
    return `${prefix}_${ts}_${rand}`;
  }

  _appendJsonl(filePath, record) {
    this._ensureDir(path.dirname(filePath));
    const line = JSON.stringify(record) + '\n';
    fs.appendFileSync(filePath, line, 'utf-8');
    return true;
  }

  _readJsonl(filePath) {
    if (!fs.existsSync(filePath)) return [];
    const content = fs.readFileSync(filePath, 'utf-8');
    return content.trim().split('\n')
      .filter(l => l.trim())
      .map(l => {
        try { return JSON.parse(l); } catch { return null; }
      })
      .filter(Boolean);
  }

  _readJson(filePath, defaultValue = []) {
    if (!fs.existsSync(filePath)) return defaultValue;
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    } catch {
      return defaultValue;
    }
  }

  _writeJson(filePath, data) {
    this._ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  // ============================================================
  // 案例记录
  // ============================================================

  /**
   * 记录漏报案例
   * @param {Object} params
   * @returns {MissedCase} 记录的案例
   */
  logMissedCase({ input, expectedThreat, actualResult = 'safe', layer = 'unknown', severity = 'high', notes = '', metadata = {} }) {
    const record = {
      id: this._generateId('missed'),
      timestamp: this._now(),
      type: 'missed',
      input: (input || '').substring(0, this.config.maxCaseInputLength),
      expectedThreat,
      actualResult,
      layer,
      severity,
      notes,
      metadata
    };

    this._appendJsonl(this.caseDbPath, record);
    return record;
  }

  /**
   * 记录拦截案例
   * @param {Object} params
   * @returns {BlockedCase} 记录的案例
   */
  logBlockedCase({ layer, threatType, threatDescription, falsePositive = false, metadata = {} }) {
    const record = {
      id: this._generateId('blocked'),
      timestamp: this._now(),
      type: 'blocked',
      layer,
      threatType,
      threatDescription,
      falsePositive,
      metadata
    };

    this._appendJsonl(this.caseDbPath, record);
    return record;
  }

  /**
   * 记录扫描结果（自动判断漏报/拦截）
   * @param {string} input - 扫描输入
   * @param {Object} scanResult - detector.scan() 的结果
   * @param {Object} options - { expectedThreat?, layer? }
   */
  logScanResult(input, scanResult, options = {}) {
    if (scanResult.safe && options.expectedThreat) {
      // 检测为安全但实际有威胁 → 漏报
      return this.logMissedCase({
        input,
        expectedThreat: options.expectedThreat,
        actualResult: 'safe',
        layer: options.layer || 'unknown',
        severity: options.severity || 'high'
      });
    } else if (!scanResult.safe && scanResult.threats) {
      // 检测到威胁 → 记录拦截
      const records = [];
      for (const threat of scanResult.threats) {
        records.push(this.logBlockedCase({
          layer: threat.layer || options.layer || 'unknown',
          threatType: threat.type,
          threatDescription: threat.description,
          falsePositive: options.falsePositive || false
        }));
      }
      return records;
    }
    return null;
  }

  // ============================================================
  // 案例分析与规则建议
  // ============================================================

  /**
   * 分析漏报案例，生成规则建议
   * @param {Object} options - { minCases?, dryRun? }
   * @returns {RuleSuggestion[]}
   */
  analyzeAndSuggest(options = {}) {
    const minCases = options.minCases || this.config.minCasesForSuggestion;
    const dryRun = options.dryRun || false;

    // 读取所有漏报案例
    const allCases = this._readJsonl(this.caseDbPath);
    const missedCases = allCases.filter(c => c.type === 'missed');

    if (missedCases.length < minCases) {
      return [];
    }

    // 按 (layer, expectedThreat) 分组
    const groups = {};
    for (const c of missedCases) {
      const key = `${c.layer || 'unknown'}:${c.expectedThreat}`;
      if (!groups[key]) groups[key] = [];
      groups[key].push(c);
    }

    const suggestions = [];

    for (const [key, cases] of Object.entries(groups)) {
      if (cases.length < minCases) continue;

      const [layer, threat] = key.split(':');
      const latest = cases[cases.length - 1];

      // 提取模式
      const patterns = this._extractPatterns(cases);
      if (patterns.length === 0) continue;

      const suggestion = {
        id: this._generateId('sug'),
        timestamp: this._now(),
        layer,
        ruleSet: this._inferRuleSet(layer, threat),
        pattern: patterns[0], // 取最显著的模式
        description: `基于${cases.length}个漏报案例自动生成: ${threat}`,
        severity: latest.severity || 'medium',
        confidence: this._calculateConfidence(cases, patterns),
        sourceCases: cases.map(c => c.id),
        status: 'pending'
      };

      suggestions.push(suggestion);
    }

    // 保存建议（非dryRun时）
    if (!dryRun && suggestions.length > 0) {
      const existing = this._readJson(this.suggestionsPath, []);
      const allSuggestions = [...existing, ...suggestions];
      this._writeJson(this.suggestionsPath, allSuggestions);
    }

    return suggestions;
  }

  /**
   * 从案例中提取攻击模式
   * @private
   */
  _extractPatterns(cases) {
    const patterns = [];
    const inputs = cases.map(c => c.input).filter(Boolean);

    if (inputs.length === 0) return patterns;

    // 简单启发式：找共同子串
    const commonSubstrs = this._findCommonSubstrings(inputs);
    if (commonSubstrs.length > 0) {
      patterns.push(...commonSubstrs);
    }

    // 提取关键词
    const keywords = this._extractKeywords(inputs);
    if (keywords.length > 0) {
      patterns.push(...keywords.map(k => `\\b${this._escapeRegex(k)}\\b`));
    }

    return [...new Set(patterns)].slice(0, 5); // 最多5个模式
  }

  /**
   * 找共同子串
   * @private
   */
  _findCommonSubstrings(strings) {
    if (strings.length < 2) return [];

    // 简化：找长度>=4的共同子串
    const base = strings[0];
    const substrings = [];

    for (let len = 4; len <= Math.min(base.length, 50); len++) {
      for (let i = 0; i <= base.length - len; i++) {
        const sub = base.substring(i, i + len);
        const escaped = this._escapeRegex(sub);
        if (strings.every(s => s.includes(sub))) {
          substrings.push(escaped);
        }
      }
    }

    // 去重并按长度排序
    return [...new Set(substrings)]
      .sort((a, b) => b.length - a.length)
      .slice(0, 3);
  }

  /**
   * 提取关键词
   * @private
   */
  _extractKeywords(inputs) {
    // 合并所有输入，提取高频词
    const wordCount = {};
    for (const input of inputs) {
      const words = input.toLowerCase()
        .replace(/[^a-z0-9\s]/g, ' ')
        .split(/\s+/)
        .filter(w => w.length > 3);
      for (const w of words) {
        wordCount[w] = (wordCount[w] || 0) + 1;
      }
    }

    return Object.entries(wordCount)
      .filter(([_, count]) => count >= inputs.length * 0.5) // 出现率>=50%
      .map(([word]) => word)
      .slice(0, 5);
  }

  /**
   * 转义正则特殊字符
   * @private
   */
  _escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * 计算置信度
   * @private
   */
  _calculateConfidence(cases, patterns) {
    let score = 0.5;
    score += Math.min(cases.length * 0.05, 0.3); // 案例数加成，最多0.3
    score += Math.min(patterns.length * 0.05, 0.15); // 模式数加成，最多0.15
    return Math.min(Math.round(score * 100) / 100, 0.95);
  }

  /**
   * 推断规则集名称
   * @private
   */
  _inferRuleSet(layer, threat) {
    const mapping = {
      'llm:prompt_injection': 'injection',
      'llm:jailbreak': 'jailbreak',
      'llm:prompt_leak': 'prompt_leak',
      'web:sql_injection': 'sql_injection',
      'web:xss': 'xss',
      'web:csrf': 'csrf',
      'web:ssrf': 'ssrf',
      'outbound:url_reputation': 'url_reputation',
      'outbound:data_exfiltration': 'data_exfiltration',
      'ingest:hidden_text': 'hidden_text',
      'ingest:zero_width': 'zero_width',
      'memory:memory_injection': 'memory_injection',
    };
    return mapping[`${layer}:${threat}`] || threat || 'general';
  }

  // ============================================================
  // 审核与落地
  // ============================================================

  /**
   * 获取待审核建议
   * @returns {RuleSuggestion[]}
   */
  getPendingSuggestions() {
    const all = this._readJson(this.suggestionsPath, []);
    return all.filter(s => s.status === 'pending');
  }

  /**
   * 获取所有建议
   * @returns {RuleSuggestion[]}
   */
  getAllSuggestions() {
    return this._readJson(this.suggestionsPath, []);
  }

  /**
   * 审核通过建议并落地为规则
   * @param {string} suggestionId - 建议ID
   * @param {Object} options - { targetFile?, modifyPattern? }
   * @returns {{ success: boolean, ruleFile?: string, error?: string }}
   */
  approveSuggestion(suggestionId, options = {}) {
    const suggestions = this._readJson(this.suggestionsPath, []);
    const idx = suggestions.findIndex(s => s.id === suggestionId);
    
    if (idx === -1) {
      return { success: false, error: 'Suggestion not found' };
    }

    const suggestion = suggestions[idx];
    if (suggestion.status !== 'pending') {
      return { success: false, error: `Suggestion already ${suggestion.status}` };
    }

    // 确定目标规则文件
    const ruleFile = options.targetFile || 
      path.join(this.rulesDir, suggestion.layer, `${suggestion.ruleSet}.json`);
    
    const absRuleFile = path.resolve(this.skillPath, ruleFile);

    // 读取现有规则
    let ruleData = this._readJson(absRuleFile, { patterns: [] });
    if (!ruleData.patterns) ruleData.patterns = [];

    // 构建新规则
    const newRule = {
      id: `auto_${this._generateId('rule')}`,
      pattern: options.modifyPattern || suggestion.pattern,
      weight: suggestion.confidence,
      severity: suggestion.severity,
      source: 'self_loop',
      sourceSuggestion: suggestion.id,
      created: this._now(),
      description: suggestion.description
    };

    // 检查重复
    const isDuplicate = ruleData.patterns.some(p => p.pattern === newRule.pattern);
    if (isDuplicate) {
      return { success: false, error: 'Duplicate pattern already exists' };
    }

    // 落地
    ruleData.patterns.push(newRule);
    this._writeJson(absRuleFile, ruleData);

    // 更新建议状态
    suggestions[idx].status = 'approved';
    suggestions[idx].approvedAt = this._now();
    suggestions[idx].ruleFile = ruleFile;
    this._writeJson(this.suggestionsPath, suggestions);

    return { success: true, ruleFile, rule: newRule };
  }

  /**
   * 拒绝建议
   * @param {string} suggestionId
   * @param {string} reason
   * @returns {{ success: boolean, error?: string }}
   */
  rejectSuggestion(suggestionId, reason = '') {
    const suggestions = this._readJson(this.suggestionsPath, []);
    const idx = suggestions.findIndex(s => s.id === suggestionId);
    
    if (idx === -1) {
      return { success: false, error: 'Suggestion not found' };
    }

    suggestions[idx].status = 'rejected';
    suggestions[idx].rejectedAt = this._now();
    suggestions[idx].rejectionReason = reason;
    this._writeJson(this.suggestionsPath, suggestions);

    return { success: true };
  }

  // ============================================================
  // 统计
  // ============================================================

  /**
   * 获取统计信息
   * @returns {Object}
   */
  getStats() {
    const allCases = this._readJsonl(this.caseDbPath);
    const suggestions = this._readJson(this.suggestionsPath, []);

    const missed = allCases.filter(c => c.type === 'missed');
    const blocked = allCases.filter(c => c.type === 'blocked');
    const falsePositives = blocked.filter(c => c.falsePositive);

    // 按层统计
    const byLayer = {};
    for (const c of allCases) {
      const layer = c.layer || 'unknown';
      if (!byLayer[layer]) byLayer[layer] = { missed: 0, blocked: 0, falsePositive: 0 };
      if (c.type === 'missed') byLayer[layer].missed++;
      if (c.type === 'blocked') {
        byLayer[layer].blocked++;
        if (c.falsePositive) byLayer[layer].falsePositive++;
      }
    }

    // 按威胁类型统计
    const byThreat = {};
    for (const c of missed) {
      const threat = c.expectedThreat || 'unknown';
      byThreat[threat] = (byThreat[threat] || 0) + 1;
    }

    return {
      totalCases: allCases.length,
      missedCases: missed.length,
      blockedCases: blocked.length,
      falsePositives: falsePositives.length,
      falsePositiveRate: blocked.length > 0 
        ? (falsePositives.length / blocked.length * 100).toFixed(1) + '%'
        : 'N/A',
      pendingSuggestions: suggestions.filter(s => s.status === 'pending').length,
      approvedSuggestions: suggestions.filter(s => s.status === 'approved').length,
      rejectedSuggestions: suggestions.filter(s => s.status === 'rejected').length,
      byLayer,
      byThreat,
      recentMissed: missed.slice(-5).map(c => ({
        id: c.id,
        timestamp: c.timestamp,
        input: c.input?.substring(0, 50) + '...',
        expectedThreat: c.expectedThreat
      }))
    };
  }

  /**
   * 清理旧案例（保留最近N条）
   * @param {number} keepRecent - 保留数量
   */
  cleanup(keepRecent = this.config.statsWindowSize) {
    const allCases = this._readJsonl(this.caseDbPath);
    if (allCases.length <= keepRecent) return 0;

    const toRemove = allCases.length - keepRecent;
    const kept = allCases.slice(-keepRecent);
    
    // 重写为JSONL格式
    const content = kept.map(c => JSON.stringify(c)).join('\n') + '\n';
    fs.writeFileSync(this.caseDbPath, content, 'utf-8');

    return toRemove;
  }
}

// ============================================================
// 与 奇点造物-Genesisix Hook 系统集成
// ============================================================

/**
 * 将 SelfLoop 注册为 奇点造物-Genesisix 的 hook
 * @param {Object} detector - 奇点造物-Genesisix Detector 实例
 * @param {SelfLoop} selfLoop - SelfLoop 实例
 * @returns {Object} { unhook: Function }
 */
function integrateWithDetector(detector, selfLoop) {
  const unhookers = [];

  // onThreat hook: 记录拦截
  unhookers.push(detector.onThreat(({ threat, input }) => {
    selfLoop.logBlockedCase({
      layer: threat.layer || 'unknown',
      threatType: threat.type,
      threatDescription: threat.description,
      falsePositive: false
    });
  }));

  // onBypass hook: 记录漏报
  unhookers.push(detector.onBypass(({ canary, input }) => {
    selfLoop.logMissedCase({
      input,
      expectedThreat: 'canary_bypass',
      actualResult: 'bypass_detected',
      layer: 'preprocessing',
      severity: 'critical',
      notes: `Canary survived: ${canary}`
    });
  }));

  return {
    unhook: () => unhookers.forEach(fn => fn())
  };
}

// ============================================================
// CLI 入口
// ============================================================

function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const selfLoop = new SelfLoop();

  const commands = {
    'log-missed': () => {
      const input = args.find(a => a.startsWith('--input='))?.split('=')[1] || '';
      const threat = args.find(a => a.startsWith('--threat='))?.split('=')[1] || '';
      const result = selfLoop.logMissedCase({ input, expectedThreat: threat });
      console.log('✅ 漏报已记录:', result.id);
    },
    'log-false-positive': () => {
      const layer = args.find(a => a.startsWith('--layer='))?.split('=')[1] || '';
      const threat = args.find(a => a.startsWith('--threat='))?.split('=')[1] || '';
      const result = selfLoop.logBlockedCase({ layer, threatType: threat, falsePositive: true });
      console.log('✅ 误报已记录:', result.id);
    },
    'stats': () => {
      console.log(JSON.stringify(selfLoop.getStats(), null, 2));
    },
    'pending': () => {
      console.log(JSON.stringify(selfLoop.getPendingSuggestions(), null, 2));
    },
    'analyze': () => {
      const suggestions = selfLoop.analyzeAndSuggest();
      console.log(`生成 ${suggestions.length} 条建议:`);
      suggestions.forEach(s => console.log(`  - ${s.id}: ${s.description}`));
    },
    'approve': () => {
      const id = args.find(a => a.startsWith('--id='))?.split('=')[1] || '';
      const result = selfLoop.approveSuggestion(id);
      console.log(result.success ? '✅ 建议已落地' : `❌ ${result.error}`);
    },
    'reject': () => {
      const id = args.find(a => a.startsWith('--id='))?.split('=')[1] || '';
      const reason = args.find(a => a.startsWith('--reason='))?.split('=')[1] || '';
      const result = selfLoop.rejectSuggestion(id, reason);
      console.log(result.success ? '✅ 建议已拒绝' : `❌ ${result.error}`);
    },
    'help': () => {
      console.log(`奇点造物-Genesisix Self-Learning Loop

Usage:
  node self_loop.js log-missed --input="..." --threat="..."
  node self_loop.js log-false-positive --layer="..." --threat="..."
  node self_loop.js stats
  node self_loop.js pending
  node self_loop.js analyze
  node self_loop.js approve --id="..."
  node self_loop.js reject --id="..." --reason="..."`);
    }
  };

  if (!command || !commands[command]) {
    commands.help();
  } else {
    commands[command]();
  }
}

// ============================================================
// 导出
// ============================================================

module.exports = { SelfLoop, integrateWithDetector };

if (require.main === module) {
  main();
}
