#!/usr/bin/env node
/**
 * 奇点造物-Genesisix × 奇点造物-Genesisix 联动日志收集器
 * 统一收集两个系统的日志，按 JSON Lines 格式输出
 */

const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(process.env.HOME, 'Desktop/奇点造物-Genesisix——奇点造物v1.0/logs');
const UNIFIED_LOG = path.join(LOG_DIR, 'unified.jsonl');

// 确保目录存在
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

/**
 * 记录日志条目
 * @param {Object} entry - 日志对象
 */
function log(entry) {
  const line = JSON.stringify({
    ...entry,
    timestamp: new Date().toISOString(),
    source: entry.source || 'unknown'
  }) + '\n';
  
  fs.appendFileSync(UNIFIED_LOG, line, 'utf8');
  console.log('[联动日志]', line.trim());
}

/**
 * 奇点造物-Genesisix 日志记录
 * @param {string} event - 事件类型
 * @param {Object} data - 数据
 */
function logFromClawSafe(event, data) {
  log({
    source: '奇点造物-Genesisix',
    event,
    ...data
  });
}

/**
 * 奇点造物-Genesisix日志记录
 * @param {string} event - 事件类型  
 * @param {Object} data - 数据
 */
function logFromXiaomeng(event, data) {
  log({
    source: 'xiaomeng',
    event,
    ...data
  });
}

// 演示：测试日志写入
if (require.main === module) {
  logFromClawSafe('threat_blocked', {
    threats: [{ type: 'injection', severity: 'high' }],
    input_preview: 'Ignore previous instructions...'
  });
  
  logFromXiaomeng('self_healed', {
    metric: 'gateway_recovery',
    attempt: 2
  });
  
  console.log('联动日志测试完成');
  console.log('日志文件:', UNIFIED_LOG);
}

module.exports = { log, logFromClawSafe, logFromXiaomeng };
