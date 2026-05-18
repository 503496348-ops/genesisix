#!/usr/bin/env node
/**
 * 奇点造物-Genesisix v1.3 — 自循环门禁系统
 * 
 * 自闭环机制：
 * 拦截事件 → 记录案例库 → 分析漏报 → 更新规则 → 验证闭环
 */

const fs = require('fs');
const path = require('path');

const CASE_DB_PATH = path.join(__dirname, 'case_database.jsonl');
const RULES_DIR = path.join(__dirname, 'rules');

/**
 * 记录拦截案例
 * @param {Object} event - 拦截事件
 */
function logCase(event) {
  const record = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    type: event.type || 'unknown',
    input: event.input?.substring(0, 200), // 截断保护隐私
    threats: event.threats || [],
    source: event.source || 'detector',
    severity: event.severity || 'unknown',
    blocked: event.blocked !== false, // 默认blocked
    metadata: event.metadata || {}
  };
  
  const line = JSON.stringify(record) + '\n';
  fs.appendFileSync(CASE_DB_PATH, line, 'utf8');
  
  return record;
}

/**
 * 记录漏报案例（攻击成功逃逸）
 */
function logMissedCase(event) {
  const record = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    type: 'missed',
    input: event.input?.substring(0, 200),
    source: event.source || 'unknown',
    severity: 'critical',
    blocked: false,
    note: event.note || '攻击逃逸，需补充规则',
    metadata: event.metadata || {}
  };
  
  const line = JSON.stringify(record) + '\n';
  fs.appendFileSync(CASE_DB_PATH, line, 'utf8');
  
  // 触发规则更新分析
  triggerRuleUpdate(record);
  
  return record;
}

/**
 * 触发规则更新分析
 */
function triggerRuleUpdate(missedEvent) {
  // 异步分析，不阻塞主流程
  setImmediate(() => {
    analyzeAndSuggestRules(missedEvent);
  });
}

/**
 * 分析漏报并生成规则建议
 */
function analyzeAndSuggestRules(missedEvent) {
  const suggestions = [];
  const input = missedEvent.input;
  
  if (!input) return suggestions;
  
  // 1. 提取关键词模式
  const words = input.toLowerCase().split(/\s+/).filter(w => w.length > 3);
  
  // 2. 尝试生成简单规则
  // 这里使用简化的启发式方法
  const patterns = extractPatterns(input);
  
  if (patterns.length > 0) {
    const suggestion = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      source_event: missedEvent.id,
      type: 'rule_suggestion',
      patterns: patterns,
      confidence: calculateConfidence(patterns),
      status: 'pending_review'
    };
    
    // 保存到待审核队列
    saveSuggestion(suggestion);
    
    return suggestion;
  }
  
  return suggestions;
}

/**
 * 从输入中提取攻击模式
 */
function extractPatterns(input) {
  const patterns = [];
  
  // 检测SQL注入模式
  const sqlPatterns = [
    /('|"|;|--|\bor\b|\band\b|union|select|drop|insert|update|delete)/gi
  ];
  
  // 检测XSS模式
  const xssPatterns = [
    /(<script|javascript:|onerror=|onload=|onclick=)/gi,
    /<[^>]*>/g
  ];
  
  // 检测命令注入模式
  const cmdPatterns = [
    /(\||;|`|\$\(|\$\{)/g,
    /(rm|wget|curl|nc|bash|sh)/gi
  ];
  
  // 检测编码绕过
  const encodingPatterns = [
    /%[0-9a-f]{2}/gi,
    /\\x[0-9a-f]{2}/gi,
    /base64|utf-8|hex/i
  ];
  
  if (sqlPatterns.some(p => p.test(input))) {
    patterns.push({
      category: 'sql_injection',
      matched: input.match(sqlPatterns[0])?.[0] || '',
      position: input.indexOf(RegExp.lastMatch || '')
    });
  }
  
  if (xssPatterns.some(p => p.test(input))) {
    patterns.push({
      category: 'xss',
      matched: input.match(xssPatterns[0])?.[0] || '',
      position: input.indexOf(RegExp.lastMatch || '')
    });
  }
  
  if (cmdPatterns.some(p => p.test(input))) {
    patterns.push({
      category: 'command_injection',
      matched: input.match(cmdPatterns[0])?.[0] || '',
      position: input.indexOf(RegExp.lastMatch || '')
    });
  }
  
  if (encodingPatterns.some(p => p.test(input))) {
    patterns.push({
      category: 'encoding_bypass',
      matched: input.match(encodingPatterns[0])?.[0] || '',
      position: input.indexOf(RegExp.lastMatch || '')
    });
  }
  
  return patterns;
}

/**
 * 计算规则置信度
 */
function calculateConfidence(patterns) {
  if (patterns.length === 0) return 0;
  
  // 基础分
  let score = 0.5;
  
  // 匹配越多，置信度越高
  score += patterns.length * 0.1;
  
  // 特定关键词加成
  const highValueKeywords = ['password', 'admin', 'root', 'exec', 'eval', 'system'];
  for (const p of patterns) {
    if (highValueKeywords.some(k => p.category.includes(k))) {
      score += 0.1;
    }
  }
  
  return Math.min(score, 0.95);
}

/**
 * 保存规则建议到待审核队列
 */
function saveSuggestion(suggestion) {
  const queuePath = path.join(__dirname, 'rule_suggestions.json');
  let queue = [];
  
  if (fs.existsSync(queuePath)) {
    try {
      queue = JSON.parse(fs.readFileSync(queuePath, 'utf8'));
    } catch (e) {
      queue = [];
    }
  }
  
  queue.push(suggestion);
  fs.writeFileSync(queuePath, JSON.stringify(queue, null, 2), 'utf8');
}

/**
 * 获取统计信息
 */
function getStats() {
  if (!fs.existsSync(CASE_DB_PATH)) {
    return { total: 0, blocked: 0, missed: 0 };
  }
  
  const content = fs.readFileSync(CASE_DB_PATH, 'utf8');
  const lines = content.trim().split('\n').filter(l => l);
  
  let blocked = 0;
  let missed = 0;
  
  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      if (record.blocked) blocked++;
      else missed++;
    } catch (e) {
      // 跳过无效行
    }
  }
  
  return {
    total: lines.length,
    blocked,
    missed,
    blockRate: lines.length > 0 ? (blocked / lines.length * 100).toFixed(1) + '%' : 'N/A'
  };
}

/**
 * 获取待审核规则建议
 */
function getPendingSuggestions() {
  const queuePath = path.join(__dirname, 'rule_suggestions.json');
  if (!fs.existsSync(queuePath)) return [];
  try {
    return JSON.parse(fs.readFileSync(queuePath, 'utf8'));
  } catch (e) {
    return [];
  }
}

/**
 * 批准规则建议并更新规则库
 * 真正将新规则写入JSON文件
 */
function approveSuggestion(suggestionId) {
  const queuePath = path.join(__dirname, 'rule_suggestions.json');
  let queue = getPendingSuggestions();
  
  const suggestion = queue.find(s => s.id === suggestionId);
  if (!suggestion) {
    return { success: false, error: 'Suggestion not found' };
  }
  
  const updatedRules = [];
  
  // 根据类别更新对应规则文件
  // 路径映射：category -> 文件路径
  const categoryToPath = {
    'sql_injection': 'web/sql_injection.json',
    'xss': 'web/xss.json',
    'ssrf': 'web/ssrf.json',
    'csrf': 'web/csrf.json',
    'injection': 'injection.json',
    'jailbreak': 'jailbreak.json',
    'prompt_leak': 'prompt_leak.json',
    'encoding': 'encoding.json',
    'key_exposure': 'api/key_exposure.json',
    'auth': 'api/auth.json',
    'rate_limit': 'api/rate_limit.json',
    'env_leak': 'deploy/env_leak.json',
    'debug_info': 'deploy/debug_info.json',
    'deps': 'supply_chain/deps.json',
    'command_injection': 'web/sql_injection.json', // 暂用SQL注入
  };
  
  for (const pattern of suggestion.patterns) {
    const relativePath = categoryToPath[pattern.category] || `${pattern.category}.json`;
    const ruleFile = path.join(RULES_DIR, relativePath);    
    if (fs.existsSync(ruleFile)) {
      try {
        const rulesData = JSON.parse(fs.readFileSync(ruleFile, 'utf8'));
        
        // 构建新规则条目
        const newRule = {
          id: `auto_${Date.now().toString(36)}`,
          pattern: escapeRegex(pattern.matched), // 转义特殊字符
          weight: suggestion.confidence,
          severity: suggestion.confidence > 0.8 ? 'high' : 'medium',
          source: suggestion.id,
          created: new Date().toISOString(),
          description: `Auto-generated from missed case: ${suggestion.id}`
        };
        
        // 追加到patterns数组
        if (rulesData.patterns && Array.isArray(rulesData.patterns)) {
          rulesData.patterns.push(newRule);
          fs.writeFileSync(ruleFile, JSON.stringify(rulesData, null, 2), 'utf8');
          updatedRules.push({ file: ruleFile, rule: newRule.id });
          console.log(`[奇点造物-Genesisix Self-Loop] Added rule to ${ruleFile}: ${newRule.id}`);
        }
      } catch (e) {
        console.error(`[奇点造物-Genesisix Self-Loop] Failed to update ${ruleFile}: ${e.message}`);
      }
    } else {
      console.log(`[奇点造物-Genesisix Self-Loop] Rule file not found: ${ruleFile}`);
    }
  }
  
  // 从队列中移除
  queue = queue.filter(s => s.id !== suggestionId);
  fs.writeFileSync(queuePath, JSON.stringify(queue, null, 2), 'utf8');
  
  return { success: true, suggestion, updatedRules };
}

/**
 * 转义正则特殊字符
 */
function escapeRegex(str) {
  if (!str) return '';
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function generateId() {
  return 'case_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 5);
}

module.exports = {
  logCase,
  logMissedCase,
  getStats,
  getPendingSuggestions,
  approveSuggestion,
};
