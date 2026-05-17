import { createPromptDefense, type PromptDefense } from '@stackone/defender';
import { config } from '../config.js';
import { logger } from '../logger.js';
import { randomToken } from '../util.js';
import { analyzePatterns, boundaryWrap, maxRisk, type RiskLevel } from './patterns.js';

let defense: PromptDefense | null = null;

function get(): PromptDefense {
  if (!defense) {
    defense = createPromptDefense({
      blockHighRisk: config.FILTER_MODE === 'strict',
      enableTier1: true,
      enableTier2: config.FILTER_TIER2,
      annotateBoundary: false, // we add our own per-call boundary markers
      tier2Fields: ['content'], // scan the field we pass in defendToolResult({ content })
    });
  }
  return defense;
}

/** Pre-load the ML tier if enabled; degrade gracefully if unavailable. */
export async function warmupDefender(): Promise<void> {
  if (!config.FILTER_TIER2) {
    logger.info('filter: ML tier (tier2) disabled; using regex layers only');
    return;
  }
  try {
    await get().warmupTier2();
    logger.info('filter: ML tier (ONNX) ready');
  } catch (err) {
    logger.warn(
      { err: err instanceof Error ? err.message : String(err) },
      'filter: ML tier unavailable; falling back to regex layers',
    );
  }
}

export interface FilterOutcome {
  allowed: boolean;
  riskLevel: RiskLevel;
  detections: string[];
  tier2Score?: number;
  /** Sanitized + per-call boundary-tagged content, safe to hand to the model. */
  content: string;
}

/**
 * Treat all fetched content as untrusted data. Three layers:
 *   1. our own deterministic pattern detector + neutralizer (always on),
 *   2. @stackone/defender's regex tier via analyze() (string input, no native deps),
 *   3. defender's ML tier (optional, FILTER_TIER2) on the content field.
 * Detections are unioned, risk is the max, content is neutralized + boundary-tagged.
 */
export async function filterContent(
  rawContent: string,
  toolName: string,
  url: string,
): Promise<FilterOutcome> {
  const own = analyzePatterns(rawContent);
  const detections = new Set<string>(own.detections);
  let risk: RiskLevel = own.risk;
  let tier2Score: number | undefined;

  // Layer 2: defender regex tier.
  try {
    const a = get().analyze(rawContent);
    for (const m of a.matches) detections.add(`def:${m.pattern}`);
    for (const f of a.structuralFlags) detections.add(`def:${f.type}`);
    risk = maxRisk(risk, a.suggestedRisk as RiskLevel);
  } catch (err) {
    logger.debug({ err }, 'filter: defender analyze failed');
  }

  // Layer 3: defender ML tier (best-effort).
  if (config.FILTER_TIER2) {
    try {
      const r = await get().defendToolResult({ content: rawContent }, toolName);
      tier2Score = r.tier2Score;
      risk = maxRisk(risk, r.riskLevel as RiskLevel);
      for (const d of r.detections) detections.add(`def:${d}`);
    } catch (err) {
      logger.debug({ err }, 'filter: defender tier2 failed');
    }
  }

  const blocked = config.FILTER_MODE === 'strict' && (risk === 'high' || risk === 'critical');
  const detectionList = [...detections];

  if (detectionList.length > 0 || risk !== 'low') {
    logger.warn(
      {
        url,
        tool: toolName,
        risk_level: risk,
        detections: detectionList,
        tier2_score: tier2Score,
        blocked,
      },
      'prompt-injection filter detections',
    );
  }

  return {
    allowed: !blocked,
    riskLevel: risk,
    detections: detectionList,
    tier2Score,
    content: boundaryWrap(own.neutralized, randomToken(12)),
  };
}
