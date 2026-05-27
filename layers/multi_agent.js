/**
 * Multi-Agent Security Detector / 多Agent安全检测层
 * Detects: Cross-Agent Injection, Agent Impersonation, Tool Chain Attacks, Intent Misalignment
 * 检测: 跨Agent指令注入、Agent身份冒充、工具链攻击、意图-行为对齐异常
 *
 * Sources:
 *   - ClawArmor (Alibaba-AAIG): multi-agent defense, toolchain detection, intent alignment
 *   - safe-mcp: SAFE-T1705 Cross-Agent Injection, SAFE-T1702 Shared-Memory Poisoning
 *   - slowmist-agent-security: trust hierarchy, pseudo-authority, trust grafting
 *
 * @version 2.4.0
 */

const fs = require('fs');
const path = require('path');

class MultiAgentDetector {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.rules = {};
    this.toolCallHistory = []; // Ring buffer for tool chain detection (ClawArmor style)
    this.maxHistorySize = 50;
    this._loadRules();
  }

  _loadRules() {
    const rulesDir = path.join(this.skillPath, 'rules', 'multi_agent');
    if (!fs.existsSync(rulesDir)) return;

    const ruleFiles = ['cross_agent_injection.json', 'agent_impersonation.json', 'slowmist_review.json', 'chain_attack.json', 'trust_evaluation.json'];

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
   * 检测跨Agent指令注入
   * @param {string} input - 用户输入或消息内容
   * @returns {object} { safe, threats, confidence }
   */
  detectCrossAgentInjection(input) {
    if (!input || typeof input !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    const ruleData = this.rules['cross_agent_injection'];
    if (!ruleData || !ruleData.patterns) {
      return { safe: true, threats: [], confidence: 0 };
    }

    for (const pattern of ruleData.patterns) {
      try {
        const { safeRegexTestGlobal } = require('../utils/regex_safety');
        const _result = safeRegexTestGlobal(pattern.pattern, input);
        if (_result.timeout) {
          threats.push({ type: 'multi_agent', id: pattern.id + '-REDoS', severity: 'medium', confidence: 0.5, description: '正则超时跳过: ' + pattern.id });
          maxConfidence = Math.max(maxConfidence, 0.5);
          continue;
        }
        if (_result.error) continue;
        if (_result.matched) {
          threats.push({
            type: 'cross_agent_injection',
            id: pattern.id,
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
   * 检测Agent身份冒充
   * @param {string} input - 用户输入或消息内容
   * @returns {object} { safe, threats, confidence }
   */
  detectAgentImpersonation(input) {
    if (!input || typeof input !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    const ruleData = this.rules['agent_impersonation'];
    if (!ruleData || !ruleData.patterns) {
      return { safe: true, threats: [], confidence: 0 };
    }

    for (const pattern of ruleData.patterns) {
      try {
        const { safeRegexTestGlobal } = require('../utils/regex_safety');
        const _result = safeRegexTestGlobal(pattern.pattern, input);
        if (_result.timeout) {
          threats.push({ type: 'multi_agent', id: pattern.id + '-REDoS', severity: 'medium', confidence: 0.5, description: '正则超时跳过: ' + pattern.id });
          maxConfidence = Math.max(maxConfidence, 0.5);
          continue;
        }
        if (_result.error) continue;
        if (_result.matched) {
          threats.push({
            type: 'agent_impersonation',
            id: pattern.id,
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
   * 工具链攻击检测 (ClawArmor ToolChain Detector)
   * 分析工具调用序列，检测多阶段攻击模式
   * @param {string} input - 当前输入/工具调用
   * @returns {object} { safe, threats, confidence, chainInfo }
   */
  detectToolChainAttack(input) {
    if (!input || typeof input !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    // 分类当前工具调用 (ClawArmor ToolCategory approach)
    const currentCategory = this._classifyToolCall(input);

    // 添加到历史记录
    if (currentCategory !== 'unknown') {
      this.toolCallHistory.push({
        category: currentCategory,
        input: input.substring(0, 200),
        timestamp: Date.now()
      });

      // 维持ring buffer大小
      if (this.toolCallHistory.length > this.maxHistorySize) {
        this.toolCallHistory.shift();
      }
    }

    // 定义攻击链模式 (ClawArmor AttackChain approach)
    const attackChains = [
      {
        id: 'CHAIN-001',
        name: 'Credential Theft Chain',
        stages: ['recon', 'credential_read', 'network_out'],
        description: '侦察→凭据读取→网络外泄的完整攻击链',
        riskScore: 0.95
      },
      {
        id: 'CHAIN-002',
        name: 'Data Exfiltration Chain',
        stages: ['recon', 'sensitive_read', 'encode', 'network_out'],
        description: '侦察→敏感文件读取→编码混淆→网络外泄',
        riskScore: 0.95
      },
      {
        id: 'CHAIN-003',
        name: 'Privilege Escalation Chain',
        stages: ['recon', 'credential_read', 'privilege_esc'],
        description: '侦察→凭据读取→权限提升',
        riskScore: 0.92
      },
      {
        id: 'CHAIN-004',
        name: 'Persistence Chain',
        stages: ['recon', 'credential_read', 'file_write'],
        description: '侦察→凭据读取→写入持久化文件（如crontab, .bashrc）',
        riskScore: 0.9
      },
      {
        id: 'CHAIN-005',
        name: 'RCE Chain',
        stages: ['recon', 'shell_exec'],
        description: '侦察后直接执行Shell命令',
        riskScore: 0.88
      }
    ];

    // 检查历史记录中是否匹配任何攻击链
    const recentHistory = this.toolCallHistory.slice(-10); // 最近10步

    for (const chain of attackChains) {
      let matchIndex = 0;
      const matchedStages = [];

      for (const entry of recentHistory) {
        if (matchIndex < chain.stages.length && entry.category === chain.stages[matchIndex]) {
          matchedStages.push(chain.stages[matchIndex]);
          matchIndex++;
        }
      }

      // 完全匹配攻击链
      if (matchIndex === chain.stages.length) {
        threats.push({
          type: 'tool_chain_attack',
          id: chain.id,
          name: chain.name,
          severity: 'critical',
          confidence: chain.riskScore,
          description: chain.description,
          matchedStages,
          completeness: 1.0
        });
        maxConfidence = Math.max(maxConfidence, chain.riskScore);
      }
      // 部分匹配（至少2个阶段）
      else if (matchIndex >= 2 && matchIndex === chain.stages.length - 1) {
        threats.push({
          type: 'tool_chain_attack_partial',
          id: chain.id + '-partial',
          name: chain.name + ' (Partial)',
          severity: 'high',
          confidence: chain.riskScore * 0.7,
          description: `部分匹配: ${matchedStages.join(' → ')} ... (缺少 ${chain.stages.slice(matchIndex).join(', ')})`,
          matchedStages,
          completeness: matchIndex / chain.stages.length
        });
        maxConfidence = Math.max(maxConfidence, chain.riskScore * 0.7);
      }
    }

    return {
      safe: threats.length === 0,
      threats,
      confidence: maxConfidence,
      chainInfo: {
        historySize: this.toolCallHistory.length,
        currentCategory
      }
    };
  }

  /**
   * 工具调用分类器 (ClawArmor ToolClassifier approach)
   * @param {string} input - 工具调用内容
   * @returns {string} 工具类别
   */
  _classifyToolCall(input) {
    const lower = input.toLowerCase();

    // Reconnaissance
    if (/\b(?:ls|find|locate|whoami|id|uname|hostname|ifconfig|ip\s+addr|netstat|ss\s|ps\s|top|env\b|printenv|set\b)\b/i.test(input)) {
      return 'recon';
    }

    // Credential read
    if (/\b(?:\.env(?:\b|[^.]|\.(?!example|template|sample))|\.aws\/credentials|\.ssh\/id_rsa|\.netrc|\.pgpass|\/etc\/shadow|\/etc\/passwd|secrets?\.(?:json|yml|yaml)|api[_-]?key|token|password|\.pem|\.key)\b/i.test(input)) {
      return 'credential_read';
    }

    // Sensitive file read
    if (/\b(?:\/root\/|\/home\/[^/]+\/\.git\/config|\.bash_history|\.zsh_history|\/proc\/\d+\/environ|\/etc\/sudoers)\b/i.test(input)) {
      return 'sensitive_read';
    }

    // File write
    if (/\b(?:write_file|create_file|edit_file|apply_patch|tee|>>)\b/i.test(input)) {
      return 'file_write';
    }

    // Encode
    if (/\b(?:base64|xxd|hexdump|od|openssl\s+enc|gzip|tar\sczf)\b/i.test(input)) {
      return 'encode';
    }

    // Network outbound
    if (/\b(?:curl\s+.*(?:-X\s*(?:POST|PUT|PATCH)|--data|-d\s)|wget\s+--post|nc\s+\S+\s+\d+|netcat|ncat|scp|rsync|ftp|sftp)\b/i.test(input)) {
      return 'network_out';
    }

    // Shell exec
    if (/\b(?:bash\s+-c|sh\s+-c|zsh\s+-c|\beval\s)\b/i.test(input)) {
      return 'shell_exec';
    }

    // Privilege escalation
    if (/\b(?:sudo|su\s+-|doas|pkexec|runas)\b/i.test(input)) {
      return 'privilege_esc';
    }

    return 'unknown';
  }

  /**
   * SlowMist零信任安全审查检测
   * @param {string} input - 用户输入或消息内容
   * @returns {object} { safe, threats, confidence }
   */
  detectSlowMistReview(input) {
    if (!input || typeof input !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    const ruleData = this.rules['slowmist_review'];
    if (!ruleData || !ruleData.patterns) {
      return { safe: true, threats: [], confidence: 0 };
    }

    for (const pattern of ruleData.patterns) {
      try {
        const { safeRegexTestGlobal } = require('../utils/regex_safety');
        const _result = safeRegexTestGlobal(pattern.pattern, input);
        if (_result.timeout) {
          threats.push({ type: 'multi_agent', id: pattern.id + '-REDoS', severity: 'medium', confidence: 0.5, description: '正则超时跳过: ' + pattern.id });
          maxConfidence = Math.max(maxConfidence, 0.5);
          continue;
        }
        if (_result.error) continue;
        if (_result.matched) {
          threats.push({
            type: 'slowmist_review',
            id: pattern.id,
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
   * 综合多Agent安全检测
   * @param {string} input - 用户输入或消息内容
   * @returns {object} { safe, threats, confidence, details }
   */

  /**
   * 评估Agent间信任等级 (slowmist零信任原则)
   * @param {object} context - { message, sourceAgent, targetAgent, toolCalls }
   * @returns {object} { level, score, warnings }
   */
  evaluateTrust(context) {
    const { message, sourceAgent, targetAgent, toolCalls } = context;
    let score = 100;
    const warnings = [];

    // Rule 1: External input is untrusted (slowmist principle)
    if (!sourceAgent || sourceAgent === 'user' || sourceAgent === 'external') {
      score -= 30;
      warnings.push('External/untrusted source');
    }

    // Rule 2: Cross-agent message without verification
    if (sourceAgent && targetAgent && sourceAgent !== targetAgent) {
      score -= 20;
      warnings.push('Cross-agent communication detected');
    }

    // Rule 3: Message contains instruction override patterns
    const overridePatterns = [
      /ignore.{0,20}(previous|above|all)/i,
      /forget.{0,20}(instructions|rules)/i,
      /you are now/i,
      /new instructions/i
    ];
    for (const pat of overridePatterns) {
      if (pat.test(message)) {
        score -= 25;
        warnings.push('Instruction override pattern detected');
        break;
      }
    }

    // Rule 4: Tool calls from untrusted context
    if (toolCalls && toolCalls.length > 5) {
      score -= 15;
      warnings.push('Excessive tool calls in single message');
    }

    // Rule 5: Pseudo-authority detection (slowmist)
    const authorityPatterns = [
      /system administrator/i,
      /as your creator/i,
      /authorized by/i,
      /security team/i,
      /official update/i
    ];
    for (const pat of authorityPatterns) {
      if (pat.test(message)) {
        score -= 20;
        warnings.push('Pseudo-authority claim detected');
        break;
      }
    }

    const level = score >= 80 ? 'high' : score >= 50 ? 'medium' : score >= 30 ? 'low' : 'untrusted';

    return { level, score: Math.max(0, score), warnings };
  }

  detect(input) {
    const crossAgentResult = this.detectCrossAgentInjection(input);
    const impersonationResult = this.detectAgentImpersonation(input);
    const toolChainResult = this.detectToolChainAttack(input);
    const slowmistResult = this.detectSlowMistReview(input);

    // Additional pattern-based detection for chain_attack and trust_evaluation
    const extraThreats = [];
    let extraConfidence = 0;
    for (const category of ['chain_attack', 'trust_evaluation']) {
      const ruleData = this.rules[category];
      if (!ruleData || !ruleData.patterns) continue;
      for (const pattern of ruleData.patterns) {
        try {
          const { safeRegexTestGlobal } = require('../utils/regex_safety');
          const _rgResult = safeRegexTestGlobal(pattern.pattern, input);
          if (_rgResult.timeout) {
            extraThreats.push({ type: category, id: pattern.id + '-REDoS', severity: 'medium', confidence: 0.5, description: '正则超时跳过: ' + pattern.id });
            extraConfidence = Math.max(extraConfidence, 0.5);
            continue;
          }
          if (_rgResult.error) continue;
          if (_rgResult.matched) {
            extraThreats.push({
              type: category,
              id: pattern.id,
              severity: pattern.severity,
              confidence: pattern.weight,
              description: pattern.description
            });
            extraConfidence = Math.max(extraConfidence, pattern.weight);
          }
        } catch (e) {}
      }
    }

    const allThreats = [
      ...crossAgentResult.threats,
      ...impersonationResult.threats,
      ...toolChainResult.threats,
      ...slowmistResult.threats,
      ...extraThreats
    ];
    const maxConfidence = Math.max(
      crossAgentResult.confidence,
      impersonationResult.confidence,
      toolChainResult.confidence,
      slowmistResult.confidence,
      extraConfidence
    );

    return {
      safe: allThreats.length === 0,
      threats: allThreats,
      confidence: maxConfidence,
      details: {
        cross_agent_injection: {
          safe: crossAgentResult.safe,
          threatCount: crossAgentResult.threats.length
        },
        agent_impersonation: {
          safe: impersonationResult.safe,
          threatCount: impersonationResult.threats.length
        },
        tool_chain: {
          safe: toolChainResult.safe,
          threatCount: toolChainResult.threats.length,
          historySize: toolChainResult.chainInfo?.historySize || 0
        },
        slowmist_review: {
          safe: slowmistResult.safe,
          threatCount: slowmistResult.threats.length
        },
        chain_attack: {
          safe: extraThreats.filter(t => t.type === 'chain_attack').length === 0,
          threatCount: extraThreats.filter(t => t.type === 'chain_attack').length
        },
        trust_evaluation: {
          safe: extraThreats.filter(t => t.type === 'trust_evaluation').length === 0,
          threatCount: extraThreats.filter(t => t.type === 'trust_evaluation').length
        }
      }
    };
  }

  /**
   * 重置工具调用历史
   */
  resetHistory() {
    this.toolCallHistory = [];
  }

  reload() {
    this.rules = {};
    this._loadRules();
  }
}

module.exports = MultiAgentDetector;
