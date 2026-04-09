/**
 * FinTrust – Risk Scorer
 * Converts threat detection results into a numeric risk score
 */

const SEVERITY_WEIGHTS = {
    low: 15,
    medium: 40,
    high: 65,
    critical: 90,
};

const RISK_LEVELS = {
    LOW: { label: 'Low', min: 0, max: 25, color: 'emerald' },
    MEDIUM: { label: 'Medium', min: 26, max: 50, color: 'amber' },
    HIGH: { label: 'High', min: 51, max: 75, color: 'red' },
    CRITICAL: { label: 'Critical', min: 76, max: 100, color: 'rose' },
};

/**
 * Calculate risk score from threat detection results
 * @param {{ detected: boolean, threats: Array, totalConfidence: number }} detectionResult
 * @returns {{ score: number, level: string, label: string, color: string, breakdown: Object }}
 */
export function calculateRiskScore(detectionResult) {
    if (!detectionResult.detected || detectionResult.threats.length === 0) {
        return {
            score: 0,
            level: 'LOW',
            label: RISK_LEVELS.LOW.label,
            color: RISK_LEVELS.LOW.color,
            breakdown: {
                baseSeverity: 0,
                patternMultiplier: 0,
                categoryMultiplier: 0,
                finalScore: 0,
            },
        };
    }

    const { threats } = detectionResult;

    // Base severity from highest threat
    const maxSeverity = threats.reduce((max, t) => {
        const weight = SEVERITY_WEIGHTS[t.severity] || 0;
        return Math.max(max, weight);
    }, 0);

    // Pattern multiplier (more matched patterns = higher risk)
    const totalPatterns = threats.reduce((sum, t) => sum + t.patternCount, 0);
    const patternMultiplier = Math.min(1 + (totalPatterns - 1) * 0.1, 1.5);

    // Category multiplier (multiple attack categories = higher risk)
    const categoryMultiplier = Math.min(1 + (threats.length - 1) * 0.15, 1.4);

    // Final score
    const rawScore = maxSeverity * patternMultiplier * categoryMultiplier;
    const score = Math.min(Math.round(rawScore), 100);

    // Determine level
    let level = 'LOW';
    for (const [key, config] of Object.entries(RISK_LEVELS)) {
        if (score >= config.min && score <= config.max) {
            level = key;
            break;
        }
    }

    return {
        score,
        level,
        label: RISK_LEVELS[level].label,
        color: RISK_LEVELS[level].color,
        breakdown: {
            baseSeverity: maxSeverity,
            patternMultiplier: Math.round(patternMultiplier * 100) / 100,
            categoryMultiplier: Math.round(categoryMultiplier * 100) / 100,
            finalScore: score,
        },
    };
}

export { RISK_LEVELS, SEVERITY_WEIGHTS };
