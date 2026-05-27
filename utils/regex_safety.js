/**
 * ReDoS防护 - 正则安全执行工具
 * 提供超时保护，防止正则表达式拒绝服务攻击
 *
 * 已知限制: JavaScript正则引擎是同步的，对于灾难性回溯(catastrophic backtracking)
 * 的正则（如 /^(a+)+$/ 匹配 "aaaa...X"），Date.now() 无法抢占执行。
 * 这种情况需要使用 Worker Thread 或 RE2 引擎来实现真正的超时。
 * 当前实现适用于：正常正则的耗时监控 + 编译错误捕获。
 */

/**
 * 安全正则测试 - 带超时保护
 * @param {string} pattern - 正则表达式模式
 * @param {string} input - 待检测输入
 * @param {number} timeoutMs - 超时阈值（毫秒），默认1000ms
 * @returns {object} { matched, timeout, elapsed, error }
 */
function safeRegexTest(pattern, input, timeoutMs = 1000) {
  try {
    const regex = new RegExp(pattern, 'i');
    const start = Date.now();
    const result = regex.test(input);
    const elapsed = Date.now() - start;
    if (elapsed > timeoutMs) {
      return { matched: false, timeout: true, elapsed };
    }
    return { matched: result, timeout: false, elapsed };
  } catch (e) {
    return { matched: false, error: e.message };
  }
}

/**
 * 安全正则匹配（全局标志）- 带超时保护
 * @param {string} pattern - 正则表达式模式
 * @param {string} input - 待检测输入
 * @param {number} timeoutMs - 超时阈值（毫秒），默认1000ms
 * @returns {object} { matched, timeout, elapsed, error }
 */
function safeRegexTestGlobal(pattern, input, timeoutMs = 1000) {
  try {
    const regex = new RegExp(pattern, 'gi');
    const start = Date.now();
    const result = regex.test(input);
    const elapsed = Date.now() - start;
    if (elapsed > timeoutMs) {
      return { matched: false, timeout: true, elapsed };
    }
    return { matched: result, timeout: false, elapsed };
  } catch (e) {
    return { matched: false, error: e.message };
  }
}

module.exports = { safeRegexTest, safeRegexTestGlobal };
