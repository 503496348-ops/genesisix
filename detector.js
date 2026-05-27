/**
 * 奇点造物-Genesisix Security Detector / 奇点造物-Genesisix 安全检测器
 * Unified entry point / 统一入口: scan(input) -> { safe, threats, confidence }
 * 
 * @author 小夏 (OpenClaw Agent)
 * @version 2.0.0
 * 
 * Phase 4B: Integrated claude-forge hooks + fireclaw preprocessing + SchemaPin + multi-agent
 * - claude-forge: 6-layer security hook architecture (beforeScan/afterScan/beforeLayer/afterLayer/onThreat/onBypass)
 * - fireclaw: 4-stage preprocessing pipeline (structural→encoding→canary→metadata)
 * - SchemaPin: ECDSA P-256 schema signature verification in MCP layer
 * - Multi-Agent: chain attack detection + trust evaluation
 */

const path = require('path');
const LLMDetector = require('./layers/llm');
const WebDetector = require('./layers/web');
const APIDetector = require('./layers/api');
const SupplyChainDetector = require('./layers/supply_chain');
const DeployDetector = require('./layers/deploy');
const OutboundDetector = require('./layers/outbound');
const IngestDetector = require('./layers/ingest');
const MemoryDetector = require('./layers/memory');
const MCPSecurityDetector = require('./layers/mcp_security');
const Preprocessor = require('./layers/preprocess');
const MultiAgentDetector = require('./layers/multi_agent');
const { SelfLoop, integrateWithDetector } = require('./self_loop');
const IntegrityDetector = require('./layers/integrity');
const ResourceGuardDetector = require('./layers/resource_guard');
const { safeRegexTest, safeRegexTestGlobal } = require('./utils/regex_safety');

class Detector {
  constructor(skillPath = __dirname) {
    this.skillPath = skillPath;
    this.llm = new LLMDetector(skillPath);
    this.web = new WebDetector(skillPath);
    this.api = new APIDetector(skillPath);
    this.supplyChain = new SupplyChainDetector(skillPath);
    this.deploy = new DeployDetector(skillPath);
    this.outbound = new OutboundDetector(skillPath);
    this.ingest = new IngestDetector(skillPath);
    this.memory = new MemoryDetector(skillPath);
    this.mcpSecurity = new MCPSecurityDetector(skillPath);
    this.preprocessor = new Preprocessor(skillPath);
    this.multiAgent = new MultiAgentDetector(skillPath);
    this.selfLoop = new SelfLoop(skillPath);
    this.integrity = new IntegrityDetector(skillPath);
    this.resourceGuard = new ResourceGuardDetector(skillPath);
    this.config = this._loadConfig();
    this.hooks = {
      beforeScan: [],
      afterScan: [],
      beforeLayer: [],
      afterLayer: [],
      onThreat: [],
      onBypass: []
    };
    
    // Integrate self-loop hooks (must be after hooks init)
    integrateWithDetector(this, this.selfLoop);
  }

  _loadConfig() {
    const fs = require('fs');
    const configPath = path.join(this.skillPath, 'config.json');
    if (fs.existsSync(configPath)) {
      const cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      // 加载白名单
      const whitelistPath = path.join(this.skillPath, 'whitelist.json');
      if (fs.existsSync(whitelistPath)) {
        this._whitelist = JSON.parse(fs.readFileSync(whitelistPath, 'utf-8'));
      }
      return cfg;
    }
    this._whitelist = {};
    return { 
      enabled: true, 
      layers: { 
        llm: { enabled: true }, 
        web: { enabled: true },
        api: { enabled: true },
        supply_chain: { enabled: true },
        deploy: { enabled: true },
        outbound: { enabled: true },
        ingest: { enabled: true },
        memory: { enabled: true },
        mcp_security: { enabled: true },
        multi_agent: { enabled: true },
        preprocessing: { enabled: true }
      } 
    };
  }

  // ============================================================
  // Hook System (Inspired by claude-forge's 21 lifecycle events)
  // 6 hook types: beforeScan, afterScan, beforeLayer, afterLayer, onThreat, onBypass
  // ============================================================

  /**
   * Register a hook callback
   * @param {string} hookType - 'beforeScan'|'afterScan'|'beforeLayer'|'afterLayer'|'onThreat'|'onBypass'
   * @param {function} callback - Callback function
   * @returns {function} Unregister function
   */
  on(hookType, callback) {
    if (!this.hooks[hookType]) {
      throw new Error(`Unknown hook type: ${hookType}. Valid types: ${Object.keys(this.hooks).join(', ')}`);
    }
    if (typeof callback !== 'function') {
      throw new Error('Hook callback must be a function');
    }
    this.hooks[hookType].push(callback);
    
    // Return unregister function
    return () => {
      const idx = this.hooks[hookType].indexOf(callback);
      if (idx > -1) this.hooks[hookType].splice(idx, 1);
    };
  }

  /**
   * Execute all hooks of a given type
   * @param {string} hookType - Type of hook to execute
   * @param {object} context - Hook context data
   * @returns {object} Modified context (hooks can modify it)
   */
  async _executeHooks(hookType, context) {
    const hookCallbacks = this.hooks[hookType];
    if (!hookCallbacks || hookCallbacks.length === 0) return context;

    let modifiedContext = { ...context };
    for (const callback of hookCallbacks) {
      try {
        const result = await callback(modifiedContext);
        if (result && typeof result === 'object') {
          // Hooks can modify context by returning new values
          modifiedContext = { ...modifiedContext, ...result };
        }
      } catch (e) {
        // Hook errors should not break scanning
        if (hookType === 'onThreat' || hookType === 'onBypass') {
          console.error(`奇点造物-Genesisix hook error (${hookType}):`, e.message);
        }
      }
    }
    return modifiedContext;
  }

  /**
   * Register a beforeScan hook (pre-execution)
   * Called before any scanning begins. Can modify or reject input.
   * @param {function} callback - (context: {input, options}) => {input?, options?, reject?, rejectReason?}
   */
  beforeScan(callback) {
    return this.on('beforeScan', callback);
  }

  /**
   * Register an afterScan hook (post-execution)
   * Called after scanning completes. Can modify results.
   * @param {function} callback - (context: {input, result, options}) => {result?}
   */
  afterScan(callback) {
    return this.on('afterScan', callback);
  }

  /**
   * Register a beforeLayer hook
   * Called before each layer executes.
   * @param {function} callback - (context: {layer, input}) => {skip?}
   */
  beforeLayer(callback) {
    return this.on('beforeLayer', callback);
  }

  /**
   * Register an afterLayer hook
   * Called after each layer executes.
   * @param {function} callback - (context: {layer, result}) => {result?}
   */
  afterLayer(callback) {
    return this.on('afterLayer', callback);
  }

  /**
   * Register an onThreat hook
   * Called when a threat is detected.
   * @param {function} callback - (context: {threat, layer, input}) => void
   */
  onThreat(callback) {
    return this.on('onThreat', callback);
  }

  /**
   * Register an onBypass hook
   * Called when a bypass attempt is detected (canary survived).
   * @param {function} callback - (context: {canary, input}) => void
   */
  onBypass(callback) {
    return this.on('onBypass', callback);
  }

  // ============================================================
  // Core Scanning
  // ============================================================

  /**
   * Execute a single layer with hook support
   */
  async _executeLayer(layerName, detector, input, detectMethod = 'detect') {
    // beforeLayer hook
    const beforeCtx = await this._executeHooks('beforeLayer', { layer: layerName, input });
    if (beforeCtx.skip) return null;

    const result = detector[detectMethod](input);

    // afterLayer hook
    const afterCtx = await this._executeHooks('afterLayer', { layer: layerName, result });
    return afterCtx.result || result;
  }

  /**
   * 主扫描入口
   * @param {string} input - 用户输入
   * @param {object} options - 可选参数 { layer?: string, preprocess?: boolean }
   * @returns {object} { safe, threats, confidence }
   */
  async scan(input, options = {}) {
    const { layer = 'all', preprocess = true } = options;

    // beforeScan hook — can modify input or reject
    const hookCtx = await this._executeHooks('beforeScan', { input, options });
    if (hookCtx.reject) {
      return {
        safe: false,
        threats: [{ type: 'hook_rejection', id: 'HOOK-001', severity: 'high', description: hookCtx.rejectReason || 'Rejected by beforeScan hook' }],
        confidence: 0.95,
        layersScanned: ['hooks'],
        scannedAt: new Date().toISOString()
      };
    }
    input = hookCtx.input || input;

    // 检查是否启用
    if (!this.config.enabled) {
      return { safe: true, threats: [], confidence: 0 };
    }

    // 输入长度限制 — 防止上下文窗口溢出攻击 (#10)
    const maxInputLength = this.config.detection?.maxInputLength || 100000;
    if (input && typeof input === 'string' && input.length > maxInputLength) {
      const overflowResult = {
        safe: false,
        threats: [{
          type: 'context_overflow',
          id: 'CO-001',
          name: 'Context Window Overflow',
          severity: 'high',
          description: `Input length ${input.length} exceeds limit ${maxInputLength} — possible context overflow attack`,
          confidence: 0.85,
          pattern: 'input_length'
        }],
        confidence: 0.85,
        layersScanned: ['guard'],
        scannedAt: new Date().toISOString()
      };
      await this._executeHooks('afterScan', { input, result: overflowResult, options });
      return overflowResult;
    }

    // FireClaw-inspired preprocessing
    let preprocessResult = null;
    if (preprocess && this.config.layers?.preprocessing?.enabled !== false) {
      preprocessResult = this.preprocessor.preprocess(input, { source: 'scan' });
      // Check canary for bypass detection
      const canaryCheck = this.preprocessor.checkCanary(input);
      if (canaryCheck.survived) {
        await this._executeHooks('onBypass', { canary: canaryCheck.canary, input });
      }
    }

    // P1-1: 白名单检查
    const whitelistResult = this._checkWhitelist(input, options);
    if (whitelistResult.skip) {
      return {
        safe: true,
        threats: [],
        confidence: 0,
        layersScanned: ['whitelist'],
        scannedAt: new Date().toISOString(),
        whitelistMatch: whitelistResult.reason
      };
    }

    const results = [];
    const allLayers = [
      { name: 'resource_guard', detector: this.resourceGuard, configKey: 'resource_guard' },
      { name: 'llm', detector: this.llm, configKey: 'llm' },
      { name: 'web', detector: this.web, configKey: 'web' },
      { name: 'api', detector: this.api, configKey: 'api' },
      { name: 'supply_chain', detector: this.supplyChain, configKey: 'supply_chain' },
      { name: 'deploy', detector: this.deploy, configKey: 'deploy' },
      { name: 'outbound', detector: this.outbound, configKey: 'outbound' },
      { name: 'ingest', detector: this.ingest, configKey: 'ingest' },
      { name: 'memory', detector: this.memory, configKey: 'memory' },
      { name: 'multi_agent', detector: this.multiAgent, configKey: 'multi_agent' }
    ];

    for (const layerDef of allLayers) {
      if (layer !== 'all' && layer !== layerDef.name) continue;
      if (this.config.layers?.[layerDef.configKey]?.enabled === false) continue;

      const layerResult = await this._executeLayer(layerDef.name, layerDef.detector, input);
      if (layerResult) {
        results.push({ layer: layerDef.name, ...layerResult });
      }
    }

    // MCP Security 层检测（仅在明确指定时或all模式）
    if (layer === 'mcp_security' || layer === 'all') {
      if (this.config.layers?.mcp_security?.enabled !== false) {
        const mcpResult = this.mcpSecurity.detect(input);
        results.push({ layer: 'mcp_security', ...mcpResult });
      }
    }

    // 合并结果
    const merged = this._mergeResults(results);

    // P1-2: 置信度阈值分级
    this._applyThresholds(merged);

    // FireClaw canary survival check in output
    if (preprocessResult) {
      merged.preprocessing = {
        applied: true,
        stages: preprocessResult.metadata.stages,
        canaryInjected: preprocessResult.metadata.stages.some(s => s.name === 'canary_injection')
      };
    }

    // afterScan hook
    const afterCtx = await this._executeHooks('afterScan', { input, result: merged, options });

    // onThreat hook for each threat
    if (!merged.safe && merged.threats) {
      for (const threat of merged.threats) {
        await this._executeHooks('onThreat', { threat, input });
      }
    }

    return afterCtx.result || merged;
  }

  /**
   * 同步版scan（向后兼容）
   */
  scanSync(input, options = {}) {
    const { layer = 'all' } = options;

    if (!this.config.enabled) {
      return { safe: true, threats: [], confidence: 0 };
    }

    const maxInputLength = this.config.detection?.maxInputLength || 100000;
    if (input && typeof input === 'string' && input.length > maxInputLength) {
      return {
        safe: false,
        threats: [{
          type: 'context_overflow', id: 'CO-001', name: 'Context Window Overflow',
          severity: 'high', description: `Input length ${input.length} exceeds limit ${maxInputLength}`,
          confidence: 0.85, pattern: 'input_length'
        }],
        confidence: 0.85, layersScanned: ['guard'], scannedAt: new Date().toISOString()
      };
    }

    // P1-1: 白名单检查
    const whitelistResult = this._checkWhitelist(input, options);
    if (whitelistResult.skip) {
      return {
        safe: true,
        threats: [],
        confidence: 0,
        layersScanned: ['whitelist'],
        scannedAt: new Date().toISOString(),
        whitelistMatch: whitelistResult.reason
      };
    }

    const results = [];
    const allLayers = [
      { name: 'resource_guard', detector: this.resourceGuard, configKey: 'resource_guard' },
      { name: 'llm', detector: this.llm, configKey: 'llm' },
      { name: 'web', detector: this.web, configKey: 'web' },
      { name: 'api', detector: this.api, configKey: 'api' },
      { name: 'supply_chain', detector: this.supplyChain, configKey: 'supply_chain' },
      { name: 'deploy', detector: this.deploy, configKey: 'deploy' },
      { name: 'outbound', detector: this.outbound, configKey: 'outbound' },
      { name: 'ingest', detector: this.ingest, configKey: 'ingest' },
      { name: 'memory', detector: this.memory, configKey: 'memory' },
      { name: 'multi_agent', detector: this.multiAgent, configKey: 'multi_agent' }
    ];

    for (const layerDef of allLayers) {
      if (layer !== 'all' && layer !== layerDef.name) continue;
      if (this.config.layers?.[layerDef.configKey]?.enabled === false) continue;
      const result = layerDef.detector.detect(input);
      results.push({ layer: layerDef.name, ...result });
    }

    if (layer === 'mcp_security' || layer === 'all') {
      if (this.config.layers?.mcp_security?.enabled !== false) {
        const mcpResult = this.mcpSecurity.detect(input);
        results.push({ layer: 'mcp_security', ...mcpResult });
      }
    }

    const merged = this._mergeResults(results);

    // P1-2: 置信度阈值分级
    this._applyThresholds(merged);

    return merged;
  }

  /**
   * 出站扫描 - 检测URL/请求安全性
   */
  scanOutbound(url, options = {}) {
    if (!this.config.enabled) {
      return { safe: true, threats: [], confidence: 0 };
    }

    if (this.config.layers?.outbound?.enabled === false) {
      return { safe: true, threats: [], confidence: 0, layersScanned: [] };
    }

    const outboundResult = this.outbound.detect(url);

    const results = [{ layer: 'outbound', ...outboundResult }];
    if (options.includeWebSsrf !== false) {
      const webResult = this.web.detect(url);
      results.push({ layer: 'web', ...webResult });
    }

    return this._mergeResults(results);
  }

  /**
   * 输入扫描 - 检测输入内容中的隐藏威胁
   */
  scanIngest(content, options = {}) {
    if (!this.config.enabled) {
      return { safe: true, threats: [], confidence: 0 };
    }

    if (this.config.layers?.ingest?.enabled === false) {
      return { safe: true, threats: [], confidence: 0, layersScanned: [] };
    }

    const ingestResult = this.ingest.detect(content);

    const results = [{ layer: 'ingest', ...ingestResult }];
    if (options.includeLlm !== false) {
      const llmResult = this.llm.detect(content);
      results.push({ layer: 'llm', ...llmResult });
    }

    return this._mergeResults(results);
  }

  /**
   * 记忆扫描 - 检测记忆/checkpoint内容安全性
   */
  scanMemory(content, options = {}) {
    if (!this.config.enabled) {
      return { safe: true, threats: [], confidence: 0 };
    }

    if (this.config.layers?.memory?.enabled === false) {
      return { safe: true, threats: [], confidence: 0, layersScanned: [] };
    }

    const memoryResult = this.memory.detect(content);

    const results = [{ layer: 'memory', ...memoryResult }];
    if (options.includeLlm !== false) {
      const llmResult = this.llm.detect(content);
      results.push({ layer: 'llm', ...llmResult });
    }

    return this._mergeResults(results);
  }

  /**
   * MCP安全扫描 - 检测MCP工具Schema和输出的安全性
   */

  /**
   * 扫描Profile配置文件完整性
   * @param {string} content - 文件内容
   * @param {string} filePath - 文件路径 (AGENTS.md/SOUL.md等)
   * @returns {object} { safe, threats, confidence }
   */
  scanIntegrity(content, filePath = '') {
    const result = this.integrity.detect(content, filePath);
    return {
      safe: result.safe,
      threats: result.threats,
      confidence: result.confidence,
      scannedAt: new Date().toISOString()
    };
  }

  /**
   * 多轮对话越狱扫描
   * @param {Array<string|object>} messages - 最近N条消息，字符串或 {role, content} 对象
   * @param {object} options - { windowSize?, includeCurrentScan?, currentInput? }
   * @returns {object} { safe, threats, confidence, phases, phaseAnalysis }
   */
  scanMultiturn(messages, options = {}) {
    if (!this.config.enabled) {
      return { safe: true, threats: [], confidence: 0, phases: [] };
    }

    // 多轮检测属于LLM层
    if (this.config.layers?.llm?.enabled === false) {
      return { safe: true, threats: [], confidence: 0, phases: [], layersScanned: [] };
    }

    const result = this.llm.detectMultiturn(messages, options);

    // 可选：同时对当前输入做单轮检测
    if (options.includeCurrentScan && options.currentInput) {
      const singleResult = this.llm.detect(options.currentInput);
      if (!singleResult.safe && singleResult.threats.length > 0) {
        result.threats.push(...singleResult.threats);
        result.confidence = Math.min(result.confidence + singleResult.confidence * 0.2, 1.0);
        result.safe = result.safe && singleResult.safe;
      }
    }

    return {
      ...result,
      layer: 'llm',
      layersScanned: ['llm'],
      scannedAt: new Date().toISOString()
    };
  }

  scanMCP(toolSchema, toolOutput) {
    if (!this.config.enabled) {
      return { safe: true, threats: [], confidence: 0 };
    }

    if (this.config.layers?.mcp_security?.enabled === false) {
      return { safe: true, threats: [], confidence: 0, layersScanned: [] };
    }

    const mcpResult = this.mcpSecurity.detect(toolSchema, toolOutput);

    const schemaText = typeof toolSchema === 'string' ? toolSchema : JSON.stringify(toolSchema);
    const results = [{ layer: 'mcp_security', ...mcpResult }];

    if (schemaText) {
      const llmResult = this.llm.detect(schemaText);
      if (!llmResult.safe) {
        results.push({ layer: 'llm', ...llmResult });
      }
    }

    // Schema signature verification (SchemaPin-inspired)
    const schemaSig = this._verifySchemaSignature(toolSchema);
    if (schemaSig.threats.length > 0) {
      results.push({ layer: 'schema_signature', ...schemaSig });
    }

    const merged = this._mergeResults(results);

    if (mcpResult.details) {
      merged.details = mcpResult.details;
    }

    return merged;
  }

  /**
   * SchemaPin-inspired schema signature verification
   */
  _verifySchemaSignature(toolSchema) {
    const input = typeof toolSchema === 'string' ? toolSchema : JSON.stringify(toolSchema);
    const threats = [];
    let maxConfidence = 0;

    const sigRules = this.mcpSecurity.rules['schema_signature'];
    if (sigRules && sigRules.patterns) {
      for (const pattern of sigRules.patterns) {
        try {
          const regex = new RegExp(pattern.pattern, 'gi');
          if (regex.test(input)) {
            threats.push({
              type: 'schema_signature',
              pattern: pattern.id,
              severity: pattern.severity,
              confidence: pattern.weight,
              description: pattern.description
            });
            maxConfidence = Math.max(maxConfidence, pattern.weight);
          }
        } catch (e) {}
      }
    }

    // Check for unsigned schemas (SchemaPin requirement)
    if (toolSchema && typeof toolSchema === 'object') {
      if (!toolSchema.signature && !toolSchema['x-schema-signature']) {
        threats.push({
          type: 'schema_signature',
          pattern: 'SS-UNSIGNED',
          severity: 'high',
          confidence: 0.80,
          description: 'MCP tool schema has no cryptographic signature — unsigned schemas are vulnerable to rug-pull attacks'
        });
        maxConfidence = Math.max(maxConfidence, 0.80);
      }
    }

    return {
      safe: threats.length === 0,
      threats,
      confidence: maxConfidence
    };
  }

  /**
   * 多Agent安全扫描
   */
  scanMultiAgent(content, context = {}) {
    if (!this.config.enabled) {
      return { safe: true, threats: [], confidence: 0 };
    }

    const threats = [];
    let maxConfidence = 0;

    // Chain attack detection
    const chainResult = this.multiAgent.detect(content);
    if (!chainResult.safe) {
      threats.push(...chainResult.threats);
      maxConfidence = Math.max(maxConfidence, chainResult.confidence);
    }

    // Trust evaluation
    const trustResult = this.multiAgent.evaluateTrust({
      message: content,
      ...context
    });

    return {
      safe: threats.length === 0,
      threats,
      confidence: maxConfidence,
      trust: trustResult,
      scannedAt: new Date().toISOString()
    };
  }

  /**
   * 预处理扫描内容
   */
  preprocessContent(input, options = {}) {
    return this.preprocessor.preprocess(input, options);
  }

  /**
   * 扫描代码片段（支持多语言）
   */
  scanCode(code) {
    const results = [];

    if (this.config.layers?.api?.enabled) {
      const apiResult = this.api.detect(code);
      results.push({ layer: 'api', ...apiResult });
    }

    if (this.config.layers?.supply_chain?.enabled) {
      const supplyChainResult = this._detectSupplyChain(code);
      results.push({ layer: 'supply_chain', ...supplyChainResult });
    }

    if (this.config.layers?.deploy?.enabled) {
      const deployResult = this._detectDeploy(code);
      results.push({ layer: 'deploy', ...deployResult });
    }

    if (this.config.layers?.outbound?.enabled) {
      const outboundResult = this.outbound.detect(code);
      results.push({ layer: 'outbound', ...outboundResult });
    }

    return this._mergeResults(results);
  }

  /**
   * 供应链层检测
   */
  _detectSupplyChain(code) {
    const fs = require('fs');
    const supplyChainDir = path.join(this.skillPath, 'rules', 'supply_chain');
    const threats = [];

    if (!fs.existsSync(supplyChainDir)) {
      return { safe: true, threats: [], confidence: 0 };
    }

    const files = ['deps.json', 'typosquat.json', 'malicious_import.json', 'skill_integrity.json'];

    for (const file of files) {
      const rulePath = path.join(supplyChainDir, file);
      if (!fs.existsSync(rulePath)) continue;

      const ruleSet = JSON.parse(fs.readFileSync(rulePath, 'utf-8'));

      for (const pattern of ruleSet.patterns || []) {
        try {
          const regex = new RegExp(pattern.pattern, 'gi');
          if (regex.test(code)) {
            threats.push({
              type: ruleSet.category || 'supply_chain',
              id: pattern.id,
              name: pattern.description,
              severity: pattern.severity,
              description: pattern.description,
              confidence: pattern.weight,
              pattern: pattern.pattern
            });
          }
        } catch (e) {}
      }
    }

    return {
      safe: threats.length === 0,
      threats,
      confidence: threats.length > 0 ? Math.max(...threats.map(t => t.confidence)) : 0
    };
  }

  /**
   * 部署层检测
   */
  _detectDeploy(code) {
    const fs = require('fs');
    const threats = [];
    const deployDir = path.join(this.skillPath, 'rules', 'deploy');

    if (!fs.existsSync(deployDir)) {
      return { safe: true, threats: [], confidence: 0 };
    }

    const files = ['env_leak.json', 'debug_info.json', 'docker_leak.json', 'cicd_leak.json', 'source_leak.json'];
    
    for (const file of files) {
      const filePath = path.join(deployDir, file);
      if (!fs.existsSync(filePath)) continue;
      
      const ruleSet = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      
      for (const pattern of ruleSet.patterns || []) {
        try {
          const regex = new RegExp(pattern.pattern, 'gi');
          if (regex.test(code)) {
            threats.push({
              type: ruleSet.category,
              id: pattern.id,
              name: ruleSet.name,
              severity: pattern.severity,
              description: pattern.description,
              confidence: pattern.weight,
              pattern: pattern.pattern
            });
          }
        } catch (e) {}
      }
    }

    return {
      safe: threats.length === 0,
      threats,
      confidence: threats.length > 0 ? Math.max(...threats.map(t => t.confidence)) : 0
    };
  }

  /**
   * P1-1: 白名单检查
   * @param {string} input - 用户输入
   * @param {object} options - { userId?, sessionId? }
   * @returns {object} { skip: boolean, reason?: string }
   */
  _checkWhitelist(input, options = {}) {
    if (!this._whitelist) return { skip: false };

    // 检查用户ID白名单
    if (options.userId && this._whitelist.users) {
      if (this._whitelist.users.includes(options.userId)) {
        return { skip: true, reason: `whitelisted_user:${options.userId}` };
      }
    }

    // 检查会话ID白名单
    if (options.sessionId && this._whitelist.sessions) {
      if (this._whitelist.sessions.includes(options.sessionId)) {
        return { skip: true, reason: `whitelisted_session:${options.sessionId}` };
      }
    }

    // 检查关键词白名单（输入完全匹配白名单关键词时跳过）
    if (input && this._whitelist.keywords) {
      const normalizedInput = input.trim().toLowerCase();
      for (const keyword of this._whitelist.keywords) {
        if (normalizedInput === keyword.toLowerCase()) {
          return { skip: true, reason: `whitelisted_keyword:${keyword}` };
        }
      }
    }

    // 检查模式白名单（输入匹配白名单正则模式时跳过）
    if (input && this._whitelist.patterns) {
      for (const pattern of this._whitelist.patterns) {
        try {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(input.trim())) {
            return { skip: true, reason: `whitelisted_pattern:${pattern}` };
          }
        } catch (e) {
          // 正则编译错误，跳过
        }
      }
    }

    return { skip: false };
  }

  /**
   * P1-2: 置信度阈值分级
   * 根据config中的阈值设置action字段
   * @param {object} result - 合并后的扫描结果
   */
  _applyThresholds(result) {
    const detection = this.config.detection || {};
    const alertThreshold = detection.alert_threshold || 0.5;
    const blockThreshold = detection.block_threshold || 0.8;
    const confidence = result.confidence || 0;

    if (confidence < alertThreshold) {
      result.action = 'pass';       // 低风险，放行
    } else if (confidence < blockThreshold) {
      result.action = 'alert';      // 中风险，告警
    } else {
      result.action = 'block';      // 高风险，拦截
    }

    result.thresholds = {
      alert_threshold: alertThreshold,
      block_threshold: blockThreshold,
      confidence_threshold: detection.confidence_threshold || 0.7
    };
  }

  /**
   * P0-1: 资源安全扫描 - 公开API
   * @param {string} input - URL / 包含URL的内容
   * @returns {object} { safe, threats, confidence }
   */
  scanResource(input) {
    if (!this.config.enabled) {
      return { safe: true, threats: [], confidence: 0 };
    }

    if (this.config.layers?.resource_guard?.enabled === false) {
      return { safe: true, threats: [], confidence: 0, layersScanned: [] };
    }

    return {
      ...this.resourceGuard.detect(input),
      layer: 'resource_guard',
      layersScanned: ['resource_guard'],
      scannedAt: new Date().toISOString()
    };
  }

  /**
   * 合并多层检测结果
   */
  _mergeResults(results) {
    if (results.length === 0) {
      return { safe: true, threats: [], confidence: 0 };
    }

    const allThreats = [];
    let maxConfidence = 0;
    let isSafe = true;

    for (const result of results) {
      if (result.threats) {
        allThreats.push(...result.threats.map(t => ({ ...t, layer: result.layer })));
      }
      maxConfidence = Math.max(maxConfidence, result.confidence);
      if (!result.safe) {
        isSafe = false;
      }
    }

    return {
      safe: isSafe,
      threats: allThreats,
      confidence: maxConfidence,
      layersScanned: results.map(r => r.layer),
      scannedAt: new Date().toISOString()
    };
  }

  /**
   * 快速检测 - 仅 LLM 层
   */
  quickCheck(input) {
    const result = this.scanSync(input, { layer: 'llm' });
    return result.safe;
  }

  /**
   * 获取检测统计
   */
  getStats() {
    return {
      version: '2.0.0',
      rules: {
        llm: {
          injection: this.llm.rules.injection?.patterns?.length || 0,
          jailbreak: this.llm.rules.jailbreak?.patterns?.length || 0,
          prompt_leak: this.llm.rules.prompt_leak?.patterns?.length || 0,
          encoding: this.llm.rules.encoding?.patterns?.length || 0,
          multilingual_injection: this.llm.rules.multilingual_injection?.patterns?.length || 0,
          indirect_injection: this.llm.rules.indirect_injection?.patterns?.length || 0,
          rag_indirect_injection: this.llm.rules.rag_indirect_injection?.patterns?.length || 0,
          few_shot_injection: this.llm.rules.few_shot_injection?.patterns?.length || 0,
          prompt_firewall: this.llm.rules.prompt_firewall?.patterns?.length || 0
        },
        web: {
          sql_injection: this.web.rules.sql_injection?.patterns?.length || 0,
          xss: this.web.rules.xss?.patterns?.length || 0,
          csrf: this.web.rules.csrf?.patterns?.length || 0,
          ssrf: this.web.rules.ssrf?.patterns?.length || 0
        },
        api: {
          key_exposure: this.api.rules.key_exposure?.patterns?.length || 0,
          rate_limit: this.api.rules.rate_limit?.patterns?.length || 0,
          auth: this.api.rules.auth?.patterns?.length || 0
        },
        outbound: {
          url_reputation: this.outbound.rules.url_reputation?.patterns?.length || 0,
          short_link: this.outbound.rules.short_link?.patterns?.length || 0,
          internal_network: this.outbound.rules.internal_network?.patterns?.length || 0,
          protocol_check: this.outbound.rules.protocol_check?.patterns?.length || 0,
          data_exfiltration: this.outbound.rules.data_exfiltration?.patterns?.length || 0,
          pii_exfil: this.outbound.rules.pii_exfil?.patterns?.length || 0,
          dns_exfil: this.outbound.rules.dns_exfil?.patterns?.length || 0
        },
        ingest: {
          hidden_text: this.ingest.rules.hidden_text?.patterns?.length || 0,
          zero_width: this.ingest.rules.zero_width?.patterns?.length || 0,
          html_injection: this.ingest.rules.html_injection?.patterns?.length || 0,
          encoding_bypass: this.ingest.rules.encoding_bypass?.patterns?.length || 0,
          homoglyph: this.ingest.rules.homoglyph?.patterns?.length || 0,
          trojan_source: this.ingest.rules.trojan_source?.patterns?.length || 0
        },
        memory: {
          memory_injection: this.memory.rules.memory_injection?.patterns?.length || 0,
          checkpoint_tamper: this.memory.rules.checkpoint_tamper?.patterns?.length || 0
        },
        mcp_security: {
          tool_poisoning: this.mcpSecurity.rules.tool_poisoning?.patterns?.length || 0,
          schema_validation: this.mcpSecurity.rules.schema_validation?.patterns?.length || 0,
          dangerous_tools: this.mcpSecurity.rules.dangerous_tools?.patterns?.length || 0,
          tool_exfil: this.mcpSecurity.rules.tool_exfil?.patterns?.length || 0,
          mcp_audit: this.mcpSecurity.rules.mcp_audit?.patterns?.length || 0,
          safe_mcp_threats: this.mcpSecurity.rules.safe_mcp_threats?.patterns?.length || 0,
          oauth_security: this.mcpSecurity.rules.oauth_security?.patterns?.length || 0,
          schema_signature: this.mcpSecurity.rules.schema_signature?.patterns?.length || 0
        },
        multi_agent: {
          cross_agent_injection: this.multiAgent.rules.cross_agent_injection?.patterns?.length || 0,
          agent_impersonation: this.multiAgent.rules.agent_impersonation?.patterns?.length || 0,
          chain_attack: this.multiAgent.rules.chain_attack?.patterns?.length || 0,
          trust_evaluation: this.multiAgent.rules.trust_evaluation?.patterns?.length || 0
        },
        resource_guard: {
          internal_ip: this.resourceGuard.rules.internal_ip?.patterns?.length || 0,
          dangerous_protocol: this.resourceGuard.rules.dangerous_protocol?.patterns?.length || 0,
          dangerous_path: this.resourceGuard.rules.dangerous_path?.patterns?.length || 0,
          blocked_ports: this.resourceGuard.rules.blocked_ports?.patterns?.length || 0
        }
      },
      layers: {
        llm: this.config.layers?.llm?.enabled !== false,
        web: this.config.layers?.web?.enabled || false,
        api: this.config.layers?.api?.enabled || false,
        supply_chain: this.config.layers?.supply_chain?.enabled || false,
        deploy: this.config.layers?.deploy?.enabled || false,
        outbound: this.config.layers?.outbound?.enabled || false,
        ingest: this.config.layers?.ingest?.enabled || false,
        memory: this.config.layers?.memory?.enabled || false,
        mcp_security: this.config.layers?.mcp_security?.enabled || false,
        multi_agent: this.config.layers?.multi_agent?.enabled !== false,
        preprocessing: this.config.layers?.preprocessing?.enabled !== false,
        resource_guard: this.config.layers?.resource_guard?.enabled !== false
      },
      hooks: {
        beforeScan: this.hooks.beforeScan.length,
        afterScan: this.hooks.afterScan.length,
        beforeLayer: this.hooks.beforeLayer.length,
        afterLayer: this.hooks.afterLayer.length,
        onThreat: this.hooks.onThreat.length,
        onBypass: this.hooks.onBypass.length
      },
      config: this.config
    };
  }

  /**
   * 重新加载配置和规则
   */
  reload() {
    this.llm.reload();
    this.web.reload();
    this.api.reload();
    this.outbound.reload();
    this.ingest.reload();
    this.memory.reload();
    this.mcpSecurity.reload();
    this.multiAgent.reload();
    this.resourceGuard.reload();
    this.config = this._loadConfig();
  }
}

// 导出
module.exports = Detector;

// 便捷函数：直接调用 scan (sync for backward compat)
const detector = new Detector();
function scan(input, options) {
  return detector.scanSync(input, options);
}

function quickCheck(input) {
  return detector.quickCheck(input);
}

module.exports.scan = scan;
module.exports.quickCheck = quickCheck;
module.exports.Detector = Detector;
