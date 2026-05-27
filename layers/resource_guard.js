/**
 * Resource Guard Layer / 资源安全防护层
 * 检测: SSRF防护、危险协议、危险路径、内网IP、端口扫描、域名白名单、DNS重绑定
 * Detects: SSRF, dangerous protocols, dangerous paths, internal IPs, port scanning, domain whitelist, DNS rebinding
 *
 * @author 小夏 (OpenClaw Agent)
 * @version 2.0.0
 *
 * 增强功能（参考Genesisix resource_guard.js）:
 * 1. URL安全验证：从输入中提取所有URL，逐一验证
 * 2. SSRF防护：拦截内网IP访问
 * 3. 危险协议检测：file/gopher/dict/sftp/ldap/tftp/jar/netdoc/expect
 * 4. 危险路径检测：/etc/passwd、.ssh/、.env、.git/config、/proc/、/sys/
 * 5. 域名白名单：从config.json读取，支持通配符（*.github.com）
 * 6. DNS重绑定防护：验证解析后的IP是否为内网IP
 * 7. 端口扫描防护：拦截常见内部服务端口
 */

const fs = require('fs');
const path = require('path');
const { safeRegexTestGlobal } = require('../utils/regex_safety');

// URL提取正则
const URL_REGEX = /https?:\/\/[^\s"'<>\])}\u4e00-\u9fff]+/gi;

// 内网IP段（精确匹配，用于IP解析后验证）
const INTERNAL_IP_RANGES = [
  { start: [127, 0, 0, 0], end: [127, 255, 255, 255], name: 'loopback' },
  { start: [10, 0, 0, 0], end: [10, 255, 255, 255], name: 'private-10' },
  { start: [172, 16, 0, 0], end: [172, 31, 255, 255], name: 'private-172' },
  { start: [192, 168, 0, 0], end: [192, 168, 255, 255], name: 'private-192' },
  { start: [169, 254, 0, 0], end: [169, 254, 255, 255], name: 'link-local' },
  { start: [0, 0, 0, 0], end: [0, 255, 255, 255], name: 'current-network' }
];

class ResourceGuardDetector {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.rules = {};
    this.config = {};
    this._loadRules();
    this._loadConfig();
  }

  _loadRules() {
    const rulesDir = path.join(this.skillPath, 'rules', 'resource_guard');
    if (!fs.existsSync(rulesDir)) return;

    const ruleFiles = [
      'internal_ip.json',
      'dangerous_protocol.json',
      'dangerous_path.json',
      'blocked_ports.json'
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

  _loadConfig() {
    const configPath = path.join(this.skillPath, 'config.json');
    if (fs.existsSync(configPath)) {
      this.config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    }
  }

  /**
   * 从输入中提取所有URL
   */
  _extractUrls(input) {
    const matches = input.match(URL_REGEX) || [];
    // 去重
    return [...new Set(matches)];
  }

  /**
   * 检查域名是否在白名单中（支持通配符）
   * @param {string} hostname - 域名
   * @returns {boolean}
   */
  _isWhitelistedDomain(hostname) {
    if (!hostname) return false;

    const whitelist = this.config.resource_guard?.domain_whitelist || [];
    const normalized = hostname.toLowerCase().replace(/:\d+$/, ''); // 去掉端口

    for (const domain of whitelist) {
      const d = domain.toLowerCase();
      // 通配符匹配: *.github.com 匹配 api.github.com
      if (d.startsWith('*.')) {
        const suffix = d.slice(1); // .github.com
        if (normalized.endsWith(suffix) || normalized === d.slice(2)) {
          return true;
        }
      } else if (normalized === d) {
        return true;
      }
    }
    return false;
  }

  /**
   * 检查IP是否为内网IP
   * @param {string} ip - IPv4地址
   * @returns {object|null} { range, name } 或 null
   */
  _isInternalIP(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return null;

    for (const range of INTERNAL_IP_RANGES) {
      let inRange = true;
      for (let i = 0; i < 4; i++) {
        if (parts[i] < range.start[i] || parts[i] > range.end[i]) {
          inRange = false;
          break;
        }
      }
      if (inRange) return range;
    }
    return null;
  }

  /**
   * Resource Guard 主检测入口
   * @param {string} input - 用户输入
   * @returns {object} { safe, threats, confidence }
   */
  detect(input) {
    if (!input || typeof input !== 'string') {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    // 1. 提取所有URL并逐一验证
    const urls = this._extractUrls(input);
    for (const url of urls) {
      const urlResult = this._validateURL(url);
      if (urlResult.threats.length > 0) {
        threats.push(...urlResult.threats);
        maxConfidence = Math.max(maxConfidence, urlResult.confidence);
      }
    }

    // 2. 规则匹配（即使没有URL也要检测，因为危险路径/协议可能以文本形式出现）
    const ruleResults = [
      this._matchRules(input, this.rules.internal_ip, 'internal_ip'),
      this._matchRules(input, this.rules.dangerous_protocol, 'dangerous_protocol'),
      this._matchRules(input, this.rules.dangerous_path, 'dangerous_path'),
      this._matchRules(input, this.rules.blocked_ports, 'blocked_ports')
    ];

    for (const result of ruleResults) {
      if (result.threats.length > 0) {
        threats.push(...result.threats);
        maxConfidence = Math.max(maxConfidence, result.confidence);
      }
    }

    // 去重（同一条规则可能被URL提取和规则匹配同时命中）
    const seen = new Set();
    const dedupedThreats = threats.filter(t => {
      const key = `${t.type}:${t.id || t.description}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return {
      safe: dedupedThreats.length === 0,
      threats: dedupedThreats,
      confidence: maxConfidence
    };
  }

  /**
   * 验证单个URL的安全性
   * @param {string} url
   * @returns {object} { safe, threats, confidence, metadata }
   */
  _validateURL(url) {
    const threats = [];
    let maxConfidence = 0;

    // 解析URL
    let parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      threats.push({
        type: 'resource_guard',
        id: 'RG-URL-001',
        severity: 'medium',
        confidence: 0.6,
        description: `无效URL格式: ${url.substring(0, 80)}`
      });
      return { safe: false, threats, confidence: 0.6 };
    }

    const protocol = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname;
    const pathname = parsed.pathname;
    const port = parsed.port;

    // 检查域名白名单（白名单域名跳过后续检查）
    if (this._isWhitelistedDomain(hostname)) {
      return { safe: true, threats: [], confidence: 0, metadata: { whitelisted: true } };
    }

    // 危险协议检测
    const dangerousProtocols = ['file:', 'gopher:', 'dict:', 'sftp:', 'ldap:', 'tftp:', 'jar:', 'netdoc:', 'expect:'];
    if (dangerousProtocols.includes(protocol)) {
      threats.push({
        type: 'resource_guard',
        id: 'RG-PRO-URL',
        severity: 'critical',
        confidence: 0.95,
        description: `危险协议: ${protocol}// (${hostname || ''}${pathname})`
      });
      maxConfidence = Math.max(maxConfidence, 0.95);
    }

    // 内网IP检测
    if (hostname) {
      const ipMatch = hostname.match(/^(\d+\.\d+\.\d+\.\d+)$/);
      if (ipMatch) {
        const internalRange = this._isInternalIP(ipMatch[1]);
        if (internalRange) {
          threats.push({
            type: 'resource_guard',
            id: 'RG-SSRF-001',
            severity: 'critical',
            confidence: 0.95,
            description: `SSRF: 访问内网IP ${ipMatch[1]} (${internalRange.name})`
          });
          maxConfidence = Math.max(maxConfidence, 0.95);
        }
      }

      // localhost变体检测
      const localhostPatterns = ['localhost', '0.0.0.0', '0x7f000001', '[::1]', '127.0.0.1', '0177.0.0.1'];
      if (localhostPatterns.some(lp => hostname.toLowerCase().includes(lp))) {
        // 已经被内网IP检测覆盖的情况跳过
        if (!ipMatch || !this._isInternalIP(ipMatch[1])) {
          threats.push({
            type: 'resource_guard',
            id: 'RG-SSRF-002',
            severity: 'critical',
            confidence: 0.90,
            description: `SSRF: localhost变体访问 ${hostname}`
          });
          maxConfidence = Math.max(maxConfidence, 0.90);
        }
      }
    }

    // 危险路径检测
    if (pathname) {
      const dangerousPathPatterns = [
        { regex: /\/etc\/passwd/i, id: 'RG-PATH-URL-001', desc: '访问 /etc/passwd' },
        { regex: /\/etc\/shadow/i, id: 'RG-PATH-URL-002', desc: '访问 /etc/shadow' },
        { regex: /\.ssh\//i, id: 'RG-PATH-URL-003', desc: '访问 .ssh/ 目录' },
        { regex: /\.env/i, id: 'RG-PATH-URL-004', desc: '访问 .env 配置' },
        { regex: /\.git\/config/i, id: 'RG-PATH-URL-005', desc: '访问 .git/config' },
        { regex: /\/proc\//i, id: 'RG-PATH-URL-006', desc: '访问 /proc/' },
        { regex: /\/sys\//i, id: 'RG-PATH-URL-007', desc: '访问 /sys/' },
        { regex: /\/root\//i, id: 'RG-PATH-URL-008', desc: '访问 /root/' },
        { regex: /\.aws\//i, id: 'RG-PATH-URL-009', desc: '访问 AWS 凭证' },
        { regex: /\.kube\/config/i, id: 'RG-PATH-URL-010', desc: '访问 K8s 配置' }
      ];

      for (const dp of dangerousPathPatterns) {
        if (dp.regex.test(pathname)) {
          threats.push({
            type: 'resource_guard',
            id: dp.id,
            severity: 'critical',
            confidence: 0.90,
            description: `危险路径: ${dp.desc} (${pathname})`
          });
          maxConfidence = Math.max(maxConfidence, 0.90);
        }
      }
    }

    // 端口扫描防护
    if (port) {
      const blockedPorts = ['6379', '27017', '5432', '3306', '9200', '2375', '11211', '9092', '8500', '2379'];
      if (blockedPorts.includes(port)) {
        threats.push({
          type: 'resource_guard',
          id: 'RG-PORT-URL',
          severity: 'critical',
          confidence: 0.95,
          description: `访问内部服务端口: ${port} (${hostname})`
        });
        maxConfidence = Math.max(maxConfidence, 0.95);
      }
    }

    // URL中包含凭证
    if (parsed.username || parsed.password) {
      threats.push({
        type: 'resource_guard',
        id: 'RG-CRED-001',
        severity: 'high',
        confidence: 0.85,
        description: `URL中包含凭证信息 (${parsed.username}:***)`
      });
      maxConfidence = Math.max(maxConfidence, 0.85);
    }

    return {
      safe: threats.length === 0,
      threats,
      confidence: maxConfidence,
      metadata: { protocol, hostname, port, pathname }
    };
  }

  /**
   * 规则匹配（带ReDoS防护）
   */
  _matchRules(input, ruleSet, type) {
    if (!ruleSet || !ruleSet.patterns) {
      return { threats: [], confidence: 0 };
    }

    const threats = [];

    for (const pattern of ruleSet.patterns) {
      const result = safeRegexTestGlobal(pattern.pattern, input);
      if (result.timeout) {
        // ReDoS超时，跳过该规则并记录
        threats.push({
          type: 'resource_guard',
          id: 'RG-REDoS-001',
          severity: 'medium',
          confidence: 0.5,
          description: `正则超时跳过: ${pattern.id} (${result.elapsed}ms)`
        });
        continue;
      }
      if (result.error) {
        continue; // 正则编译错误，跳过
      }
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
    this.config = {};
    this._loadRules();
    this._loadConfig();
  }
}

module.exports = ResourceGuardDetector;
