#!/usr/bin/env node
/**
 * 奇点造物-Genesisix v1.2 — 外部资源安全过滤层
 * 
 * 新增功能：
 * 1. URL安全验证（SSRF防护）
 * 2. 外部资源访问控制
 * 3. 请求上下文隔离
 * 4. 资源类型检测
 */

const path = require('path');
const fs = require('fs');

// 内部IP段黑名单
const INTERNAL_IP_PATTERNS = [
  /^127\./,                    // localhost
  /^10\./,                    // private
  /^172\.(1[6-9]|2\d|3[01])\./, // private
  /^192\.168\./,              // private
  /^169\.254\./,              // AWS metadata
  /^0\./,                     // current network
  /^(::1|fe80:)/i,           // IPv6 localhost
];

// 危险协议
const DANGEROUS_PROTOCOLS = [
  'file://',
  'gopher://',
  'dict://',
  'sftp://',
  'ldap://',
  'tftp://',
];

// 危险路径模式
const DANGEROUS_PATHS = [
  /^\/etc\//i,
  /^\/etc\/passwd/,
  /^\/etc\/shadow/,
  /^\/root\//,
  /^\/home\/.*\/\.ssh\//,
  /^\/var\/log\//,
  /^\/proc\//,
  /^\/sys\//,
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /\.env$/i,
  /\.git\/config$/i,
];

// 安全域名白名单（可配置）
let WHITELIST = new Set([
  'google.com',
  'github.com',
  'api.openai.com',
  'api.anthropic.com',
]);

/**
 * 验证URL是否安全
 */
function validateURL(url, context = {}) {
  const threats = [];
  
  // 1. 检查危险协议
  for (const proto of DANGEROUS_PROTOCOLS) {
    if (url.toLowerCase().startsWith(proto)) {
      threats.push({
        type: 'dangerous_protocol',
        severity: 'critical',
        confidence: 0.95,
        description: `危险协议: ${proto}`
      });
    }
  }
  
  // 2. 解析URL
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    threats.push({
      type: 'invalid_url',
      severity: 'high',
      confidence: 0.8,
      description: '无效URL格式'
    });
    return { safe: threats.length === 0, threats };
  }
  
  // 3. 检查内部IP访问
  const hostname = parsed.hostname;
  if (hostname) {
    // 直接IP访问
    const ip = hostname.match(/^(\d+\.\d+\.\d+\.\d+)/);
    if (ip) {
      for (const pattern of INTERNAL_IP_PATTERNS) {
        if (pattern.test(ip[1])) {
          threats.push({
            type: 'internal_ip_access',
            severity: 'critical',
            confidence: 0.95,
            description: `访问内部IP: ${ip[1]}`
          });
        }
      }
    }
    
    // DNS重绑定检测（短TTL + 内部IP）
    // 这里简化为检测localhost变体
    if (hostname.includes('localhost') || hostname === '0') {
      threats.push({
        type: 'localhost_access',
        severity: 'high',
        confidence: 0.9,
        description: '尝试访问localhost'
      });
    }
  }
  
  // 4. 检查危险路径
  if (parsed.pathname) {
    for (const pattern of DANGEROUS_PATHS) {
      if (pattern.test(parsed.pathname)) {
        threats.push({
          type: 'dangerous_path',
          severity: 'critical',
          confidence: 0.9,
          description: `危险路径: ${parsed.pathname}`
        });
      }
    }
  }
  
  // 5. 检查凭证泄露
  if (parsed.username || parsed.password) {
    threats.push({
      type: 'url_with_credentials',
      severity: 'high',
      confidence: 0.85,
      description: 'URL中包含凭证信息'
    });
  }
  
  // 6. 检查端口
  const port = parsed.port;
  const dangerousPorts = ['22', '23', '25', '3306', '5432', '6379', '27017', '11211'];
  if (dangerousPorts.includes(port)) {
    threats.push({
      type: 'dangerous_port',
      severity: 'high',
      confidence: 0.8,
      description: `危险端口: ${port}`
    });
  }
  
  return {
    safe: threats.length === 0,
    threats,
    metadata: {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port,
      pathname: parsed.pathname,
      hash: parsed.hash
    }
  };
}

/**
 * 检查外部资源响应是否安全
 */
function validateResponse(response, context = {}) {
  const threats = [];
  
  // 1. 检查是否是内部敏感数据
  if (response.body) {
    const body = response.body.toString('utf8').substring(0, 1000);
    
    if (/root:.*:0:0:/i.test(body)) {
      threats.push({
        type: 'sensitive_file_content',
        severity: 'critical',
        confidence: 0.95,
        description: '响应包含/etc/passwd内容'
      });
    }
    
    if (/BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY/i.test(body)) {
      threats.push({
        type: 'private_key_exposed',
        severity: 'critical',
        confidence: 0.95,
        description: '响应包含私钥内容'
      });
    }
    
    if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/.test(body) && body.length > 500) {
      threats.push({
        type: 'potential_data_leak',
        severity: 'medium',
        confidence: 0.6,
        description: '响应包含大量邮箱地址'
      });
    }
  }
  
  // 2. 检查Content-Type
  const contentType = response.headers?.['content-type'] || '';
  if (contentType.includes('application/x-executable') || 
      contentType.includes('application/x-sharedlib')) {
    threats.push({
      type: 'executable_content',
      severity: 'high',
      confidence: 0.85,
      description: '响应包含可执行文件'
    });
  }
  
  return {
    safe: threats.length === 0,
    threats
  };
}

/**
 * 生成安全请求配置
 */
function secureRequestOptions(url, userOptions = {}) {
  const defaults = {
    // 默认不允许重定向到内部资源
    validateURL: true,
    maxRedirects: 3,
    timeout: 30000,
    // 默认只允许HTTP/HTTPS
    allowedProtocols: ['http:', 'https:'],
    // 检查证书
    rejectUnauthorized: true,
  };
  
  return { ...defaults, ...userOptions };
}

/**
 * 扫描资源访问请求
 */
function scanResourceAccess(request, context = {}) {
  const threats = [];
  
  // URL验证
  if (request.url) {
    const urlResult = validateURL(request.url, context);
    threats.push(...urlResult.threats);
  }
  
  // 请求头检查
  if (request.headers) {
    const headers = request.headers;
    
    // Referer泄漏检测
    if (headers.referer && headers.referer.includes('internal')) {
      threats.push({
        type: 'internal_referer_leak',
        severity: 'medium',
        confidence: 0.7,
        description: 'Referer头可能泄露内部路径'
      });
    }
    
    // Cookie泄漏检测
    if (headers.cookie) {
      threats.push({
        type: 'cookie_exposure',
        severity: 'high',
        confidence: 0.8,
        description: '请求包含Cookie，可能泄露认证信息'
      });
    }
  }
  
  return {
    safe: threats.length === 0,
    threats,
    recommendations: generateRecommendations(threats)
  };
}

function generateRecommendations(threats) {
  const recommendations = [];
  
  for (const threat of threats) {
    switch (threat.type) {
      case 'internal_ip_access':
        recommendations.push('使用白名单域名而非IP访问外部资源');
        recommendations.push('禁止访问169.254.169.254元数据端点');
        break;
      case 'dangerous_protocol':
        recommendations.push('仅允许HTTP/HTTPS协议');
        break;
      case 'localhost_access':
        recommendations.push('禁止访问localhost和127.0.0.1');
        break;
      case 'dangerous_path':
        recommendations.push('禁止访问系统敏感路径');
        break;
      case 'url_with_credentials':
        recommendations.push('使用请求头传递认证信息而非URL');
        break;
      case 'dangerous_port':
        recommendations.push('禁止访问SSH/数据库等管理端口');
        break;
    }
  }
  
  return recommendations;
}

module.exports = {
  validateURL,
  validateResponse,
  secureRequestOptions,
  scanResourceAccess,
  INTERNAL_IP_PATTERNS,
  DANGEROUS_PROTOCOLS,
  DANGEROUS_PATHS,
};
