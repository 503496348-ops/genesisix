/**
 * Preprocessing Layer / 输入预处理层
 * Inspired by FireClaw's 4-stage proxy pipeline:
 *   Stage 1: Structural sanitization (HTML/Unicode tricks)
 *   Stage 2: Encoding normalization (decode obfuscation)
 *   Stage 3: Canary token injection (bypass detection)
 *   Stage 4: Content extraction (strip non-essential)
 * 
 * @version 2.5.0
 */

class Preprocessor {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.stats = { processed: 0, sanitized: 0, canariesInjected: 0 };
  }

  /**
   * Full preprocessing pipeline (FireClaw-inspired 4-stage)
   * @param {string} input - Raw input text
   * @param {object} options - { stage?: number, injectCanary?: boolean, source?: string }
   * @returns {object} { sanitized, original, metadata }
   */
  preprocess(input, options = {}) {
    if (!input || typeof input !== 'string') {
      return { sanitized: input, original: input, metadata: { stages: [] } };
    }

    const original = input;
    let sanitized = input;
    const stages = [];
    const { injectCanary = true, source = 'unknown' } = options;

    // Stage 1: Structural Sanitization
    sanitized = this._stage1Structural(sanitized);
    stages.push({ stage: 1, name: 'structural_sanitization', applied: sanitized !== input });

    // Stage 2: Encoding Normalization
    const afterStage2 = this._stage2Encoding(sanitized);
    stages.push({ stage: 2, name: 'encoding_normalization', applied: afterStage2 !== sanitized });
    sanitized = afterStage2;

    // Stage 3: Canary Token Injection (FireClaw's bypass detection)
    if (injectCanary) {
      const canary = this._generateCanary();
      sanitized = `${sanitized}\n\n<!-- CANARY:${canary} -->`;
      stages.push({ stage: 3, name: 'canary_injection', canary, applied: true });
      this.stats.canariesInjected++;
    }

    // Stage 4: Metadata Extraction
    const metadata = this._stage4Metadata(sanitized, source);
    stages.push({ stage: 4, name: 'metadata_extraction', applied: true });

    this.stats.processed++;
    if (sanitized !== original) this.stats.sanitized++;

    return {
      sanitized,
      original,
      metadata: {
        ...metadata,
        stages,
        source,
        processedAt: new Date().toISOString(),
        lengthDelta: sanitized.length - original.length
      }
    };
  }

  /**
   * Stage 1: Structural Sanitization
   * Strips HTML tricks, hidden Unicode, encoding exploits
   */
  _stage1Structural(input) {
    let result = input;

    // Remove HTML comments (may hide instructions)
    result = result.replace(/<!--[\s\S]*?-->/g, '');

    // Remove script/style/iframe/object/embed tags
    result = result.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '[STRIPPED:script]');
    result = result.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '[STRIPPED:style]');
    result = result.replace(/<iframe[^>]*>[\s\S]*?<\/iframe>/gi, '[STRIPPED:iframe]');
    result = result.replace(/<object[^>]*>[\s\S]*?<\/object>/gi, '[STRIPPED:object]');
    result = result.replace(/<embed[^>]*>/gi, '[STRIPPED:embed]');

    // Remove zero-width characters
    result = result.replace(/[\u200B\u200C\u200D\uFEFF]/g, '');

    // Remove RTL/LTR override characters
    result = result.replace(/[\u202A-\u202E]/g, '');

    // Remove control characters (except newline, tab, carriage return)
    result = result.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, '');

    // Remove replacement characters
    result = result.replace(/\uFFFD/g, '');

    // Remove soft hyphens
    result = result.replace(/\u00AD/g, '');

    // Remove invisible separators
    result = result.replace(/[\u2063\u2064]/g, '');

    // Collapse excessive whitespace
    result = result.replace(/[ \t]{10,}/g, ' ');
    result = result.replace(/\n{5,}/g, '\n\n');

    return result;
  }

  /**
   * Stage 2: Encoding Normalization
   * Decodes obfuscation attempts
   */
  _stage2Encoding(input) {
    let result = input;

    // Decode double URL encoding
    try {
      const decoded = decodeURIComponent(result);
      if (decoded !== result) {
        result = decoded;
      }
    } catch (e) {
      // Invalid encoding, keep original
    }

    // Normalize unicode confusables (basic Latin/Cyrillic)
    const confusableMap = {
      '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
      '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
      '\u0410': 'A', '\u0415': 'E', '\u041E': 'O', '\u0420': 'P',
      '\u0421': 'C', '\u0423': 'Y', '\u0425': 'X'
    };
    for (const [cyrillic, latin] of Object.entries(confusableMap)) {
      result = result.replace(new RegExp(cyrillic, 'g'), latin);
    }

    return result;
  }

  /**
   * Stage 3: Generate canary token for bypass detection
   * (Inspired by FireClaw's CanaryTokenSystem)
   */
  _generateCanary() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let canary = 'CANARY_';
    for (let i = 0; i < 12; i++) {
      canary += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return canary;
  }

  /**
   * Check if a canary token survived processing (bypass detection)
   * @param {string} output - Processed output to check
   * @returns {object} { survived: boolean, canary?: string }
   */
  checkCanary(output) {
    const match = output.match(/CANARY_[A-Z0-9]{8,16}/);
    return {
      survived: !!match,
      canary: match ? match[0] : null
    };
  }

  /**
   * Stage 4: Metadata Extraction
   * Extracts structural metadata for analysis
   */
  _stage4Metadata(input, source) {
    return {
      inputLength: input.length,
      lineCount: (input.match(/\n/g) || []).length + 1,
      hasUrls: /https?:\/\//.test(input),
      hasBase64: /[A-Za-z0-9+/]{100,}={0,2}/.test(input),
      hasHtml: /<[a-z][\s\S]*>/i.test(input),
      hasUnicodeAnomalies: /[\u200B-\u200F\u202A-\u202E\u2063-\u2064\uFEFF]/.test(input),
      encodingEntropy: this._calculateEntropy(input)
    };
  }

  /**
   * Calculate Shannon entropy of input (high entropy = likely encoded/encrypted)
   */
  _calculateEntropy(str) {
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    const len = str.length;
    let entropy = 0;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
  }

  /**
   * Get processing statistics
   */
  getStats() {
    return { ...this.stats };
  }
}

module.exports = Preprocessor;
