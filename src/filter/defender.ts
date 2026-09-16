import { createPromptDefense, type PromptDefense } from '@stackone/defender';
import { config } from '../config.js';
import { logger } from '../logger.js';
import { randomToken } from '../util.js';
import { analyzePatterns, boundaryWrap, maxRisk, normalizeForDetection, type RiskLevel } from './patterns.js';

let defense: PromptDefense | null = null;
let tier2Warmup: Promise<void> | undefined;

function get(): PromptDefense {
  if (!defense) {
    defense = createPromptDefense({
      blockHighRisk: config.FILTER_MODE === 'strict',
      defaultRiskLevel: 'low',
      enableTier1: true,
      enableTier2: config.FILTER_TIER2,
      annotateBoundary: false,
      tier2Fields: ['content'],
      // We bound and chunk inputs ourselves; the upstream 10k-character default
      // must never silently omit the tail of a fetched document.
      tier2Config: { minTextLength: 1, maxTextLength: Number.MAX_SAFE_INTEGER },
    });
  }
  return defense;
}

/** If an explicitly enabled ML tier is unavailable, fetched content is withheld. */
export async function warmupDefender(): Promise<void> {
  if (!config.FILTER_TIER2) {
    logger.info('filter: ML tier (tier2) disabled; using regex layers only');
    return;
  }
  tier2Warmup ??= (async () => {
    try {
      await get().warmupTier2();
      if (!get().isTier2Ready()) throw new Error('ML tier did not become ready');
      logger.info('filter: ML tier (ONNX) ready');
    } catch {
      logger.error('filter: enabled ML tier unavailable; fetched content will be withheld');
      throw new Error('Enabled prompt-injection classifier unavailable');
    }
  })();
  await tier2Warmup;
}

export interface FilterOutcome {
  allowed: boolean;
  riskLevel: RiskLevel;
  detections: string[];
  tier2Score?: number;
  /** Neutralized, boundary-tagged untrusted data, or empty when withheld. */
  content: string;
}

function checkedRisk(value: string): RiskLevel {
  if (!['low', 'medium', 'high', 'critical'].includes(value)) throw new Error('Invalid classifier risk');
  return value as RiskLevel;
}

class Tier2LimitError extends Error {}
class Tier2TimeoutError extends Error {}
class Tier2BusyError extends Error {}
let tier2InFlight = 0;

function boundedInference<T>(start: () => Promise<T>): Promise<T> {
  if (tier2InFlight >= 4) throw new Tier2BusyError('ML tier concurrency limit exceeded');
  tier2InFlight++;
  let operation: Promise<T>;
  try { operation = start(); }
  catch (error) { tier2InFlight--; throw error; }
  // A timeout cannot cancel native inference. Retain the slot until the actual
  // operation settles so repeated timeout requests cannot accumulate work.
  return operation.finally(() => { tier2InFlight--; });
}

async function beforeDeadline<T>(operation: Promise<T>, deadline: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Tier2TimeoutError('ML tier time limit exceeded')),
          Math.max(0, deadline - Date.now()));
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// Byte-bounded overlapping windows avoid the upstream tokenizer silently
// truncating a very long sentence. Resource exhaustion is a failure, not license
// to scan only a prefix. Tier2 is optional; regex layers scan the full envelope.
function tier2Chunks(input: string): string[] {
  const chunks: string[] = [];
  let chunk = '';
  let bytes = 0;
  for (const char of input) {
    const size = Buffer.byteLength(char, 'utf8');
    if (bytes + size > 256) {
      chunks.push(chunk);
      if (chunks.length >= 512) throw new Tier2LimitError('ML tier input limit exceeded');
      let overlap = '';
      let overlapBytes = 0;
      for (const trailing of [...chunk].reverse()) {
        const trailingBytes = Buffer.byteLength(trailing, 'utf8');
        if (overlapBytes + trailingBytes > 64) break;
        overlap = trailing + overlap;
        overlapBytes += trailingBytes;
      }
      chunk = overlap;
      bytes = overlapBytes;
    }
    chunk += char;
    bytes += size;
  }
  if (chunk.trim()) chunks.push(chunk);
  return chunks;
}

/** Defense in depth, not a guarantee against semantic or novel prompt injection. */
export async function filterContent(rawContent: string, toolName: string, url: string): Promise<FilterOutcome> {
  const detections = new Set<string>();
  let risk: RiskLevel = 'low';
  let neutralized = '';
  let normalized = '';
  let failed = false;
  let tier2Score: number | undefined;

  try {
    const own = analyzePatterns(rawContent);
    for (const detection of own.detections) detections.add(detection);
    risk = own.risk;
    neutralized = own.neutralized;
    normalized = normalizeForDetection(rawContent);
  } catch {
    detections.add('filter_pattern_unavailable');
    failed = true;
  }

  try {
    for (const input of new Set([rawContent, normalized])) {
      const result = get().analyze(input);
      for (const match of result.matches) detections.add(`def:${match.pattern}`);
      for (const flag of result.structuralFlags) detections.add(`def:${flag.type}`);
      risk = maxRisk(risk, checkedRisk(result.suggestedRisk));
    }
  } catch {
    detections.add('filter_regex_unavailable');
    failed = true;
  }

  if (config.FILTER_TIER2 && !failed) {
    try {
      const deadline = Date.now() + 10_000;
      await beforeDeadline(warmupDefender(), deadline);
      const chunks = tier2Chunks(normalized);
      if (chunks.length > 0) {
        // Scan each batch independently so a skipped/incomplete batch cannot be
        // hidden behind a valid score obtained for a different part of the page.
        for (const content of chunks) {
          if (Date.now() >= deadline) throw new Tier2TimeoutError('ML tier time limit exceeded');
          const result = await beforeDeadline(boundedInference(() => get().defendToolResult({ content }, toolName)), deadline);
          if (result.tier2SkipReason || result.truncatedAtDepth ||
              typeof result.tier2Score !== 'number' || !Number.isFinite(result.tier2Score) ||
              result.tier2Score < 0 || result.tier2Score > 1) {
            throw new Error('Incomplete ML classifier result');
          }
          tier2Score = Math.max(tier2Score ?? 0, result.tier2Score);
          risk = maxRisk(risk, checkedRisk(result.riskLevel));
          if (!result.allowed) risk = maxRisk(risk, 'high');
          for (const detection of result.detections) detections.add(`def:${detection}`);
        }
      }
    } catch (error) {
      detections.add(error instanceof Tier2LimitError ? 'filter_tier2_input_limit' :
        error instanceof Tier2TimeoutError ? 'filter_tier2_timeout' :
        error instanceof Tier2BusyError ? 'filter_tier2_busy' : 'filter_tier2_unavailable');
      failed = true;
    }
  }

  if (failed) risk = 'critical';
  const blocked = failed || (config.FILTER_MODE === 'strict' && (risk === 'high' || risk === 'critical'));
  const detectionList = [...detections];
  if (detectionList.length > 0 || risk !== 'low') {
    // Do not log page text or URL query/fragment data (which may contain secrets).
    let origin: string | undefined;
    try { origin = new URL(url).origin; } catch { /* optional telemetry only */ }
    logger.warn({ origin, tool: toolName, risk_level: risk, detections: detectionList,
      tier2_score: tier2Score, blocked }, 'prompt-injection filter detections');
  }
  return {
    allowed: !blocked,
    riskLevel: risk,
    detections: detectionList,
    tier2Score,
    // Hidden/comment removal can join `!` and `[` from separate source spans.
    // Defuse image syntax only after reconstruction has itself been scanned.
    content: blocked ? '' : boundaryWrap(neutralized.replace(/!\[/g, '！['), randomToken(12)),
  };
}
