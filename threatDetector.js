/**
 * FinTrust – Threat Detector
 * Regex-based pattern matching for 5 attack categories
 */

const THREAT_PATTERNS = {
    instruction_override: {
        label: 'Instruction Override',
        severity: 'critical',
        weight: 0.95,
        patterns: [
            /ignore\s+(all\s+)?previous\s+(instructions?|rules?|guidelines?)/i,
            /ignore\s+(all\s+)?(security|safety)\s+(rules?|protocols?|policies?)/i,
            /disregard\s+(all\s+)?previous/i,
            /forget\s+(all\s+)?(your\s+)?(rules?|instructions?|guidelines?|training)/i,
            /override\s+(all\s+)?(your\s+)?(rules?|instructions?|safety|policies?|security)/i,
            /override\s+policies/i,
            /new\s+rules?\s*:/i,
            /you\s+are\s+now\s+(a|an)\s+/i,
            /act\s+as\s+(if|though)\s+you\s+(have\s+)?no\s+restrict/i,
            /pretend\s+(you|that)\s+(are|have)\s+no\s+(restrict|rules?|limit)/i,
            /do\s+not\s+follow\s+(your|any)\s+(rules?|guidelines?|instructions?)/i,
            /bypass\s+(your\s+)?(safety|security|rules?|restrict|verification)/i,
            /disable\s+(all\s+)?(security|safety|protection|rules?|filtering)/i,
            /turn\s+off\s+(security|safety|protection|sandbox)/i,
            /deactivate\s+(security|safety|protection)/i,
        ],
    },
    authority_escalation: {
        label: 'Authority Escalation',
        severity: 'high',
        weight: 0.85,
        patterns: [
            /i\s+am\s+(the\s+)?(admin|administrator|root|superuser|manager|ceo|owner)/i,
            /i\s+have\s+(admin|root|elevated|super)\s*(access|privileges?|rights?|permissions?)/i,
            /grant\s+(me|yourself)\s+(admin|root|elevated|full)\s*(access|privileges?|rights?|permissions?)/i,
            /escalat(e|ing)\s+(my\s+)?(privileges?|access|permissions?|role)/i,
            /authorize\s+(me|this)\s+(as|for)\s+(admin|manager|supervisor)/i,
            /my\s+clearance\s+(level|is)\s+(top\s+secret|classified|maximum)/i,
            /executive\s+override/i,
            /emergency\s+(access|override|authorization)/i,
            /administrator\s+mode/i,
            /admin(istrator)?\s+(mode|command|access|panel|privileges?)/i,
            /system\s+(admin|override|command)/i,
            /root\s+(access|privileges?|mode|permissions?)/i,
            /act\s+as\s+(an?\s+)?admin(istrator)?/i,
            /switch\s+to\s+(admin|root|privileged)\s*(mode|access)?/i,
            /enable\s+(admin|root|administrator|privileged)\s*(mode|access)?/i,
            /super\s*user\s*(mode|access|privileges?)/i,
        ],
    },
    data_exfiltration: {
        label: 'Data Exfiltration',
        severity: 'critical',
        weight: 0.90,
        patterns: [
            /show\s+(me\s+)?(the\s+)?(system\s+)?prompt/i,
            /reveal\s+(your\s+)?(system\s+)?(instructions?|prompt|config|data|credentials?)/i,
            /display\s+(your\s+)?(internal|hidden|system)\s*(config(uration)?|prompt|instructions?|rules?|data)/i,
            /what\s+(are|is)\s+your\s+(system\s+)?(instructions?|prompt|rules?|config)/i,
            /print\s+(your\s+)?(internal|system|hidden)/i,
            /output\s+(your\s+)?(system|training)\s*(data|prompt|instructions?)/i,
            /leak\s+(the\s+)?(data|information|credentials?|passwords?)/i,
            /extract\s+(customer|user|account|private)\s*(data|info|details|records?)/i,
            /dump\s+(all\s+)?(the\s+)?(database|records?|data|accounts?)/i,
            /list\s+all\s+(customer|user|account)\s*(data|info|records?)/i,
            /database\s+(connection|credentials?|password|access|config(uration)?|string|details)/i,
            /server\s+(config(uration)?|details|credentials?|architecture|info)/i,
            /internal\s+(architecture|config(uration)?|system|infrastructure|network)/i,
            /secret\s+(tokens?|keys?|credentials?|passwords?)/i,
            /api\s+(keys?|tokens?|secrets?|credentials?)/i,
            /provide\s+(the\s+)?(api|secret|access)\s*(keys?|tokens?|credentials?)/i,
            /connection\s+string/i,
            /reveal\s+(account|customer|user)\s*(data|info|details|records?|balance)/i,
        ],
    },
    financial_attack: {
        label: 'Financial Transaction Attack',
        severity: 'critical',
        weight: 0.95,
        patterns: [
            /transfer\s+(\$?\d[\d,]*\.?\d*\s*)?(money|funds|amount)/i,
            /transfer\s+money/i,
            /wire\s+(transfer|funds|money|\$)/i,
            /send\s+(\$?\d[\d,]*\.?\d*\s+)?(to|from)\s+(account|wallet)/i,
            /approve\s+(the\s+)?(transaction|transfer|payment|withdrawal)/i,
            /process\s+(this\s+)?(payment|withdrawal|transfer)/i,
            /withdraw\s+(\$?\d[\d,]*\.?\d*\s*)?(from|funds|money)/i,
            /change\s+(the\s+)?(account|beneficiary)\s*(number|details|info)/i,
            /modify\s+(the\s+)?transaction\s*(amount|recipient|details)/i,
            /create\s+(a\s+)?(new\s+)?(unauthorized|fake|fraudulent)\s*(transaction|transfer)/i,
            /divert\s+(the\s+)?(funds|payment|transfer)/i,
            /bypass\s+(the\s+)?(verification|authentication|authorization|2fa|mfa|otp)/i,
            /execute\s+(the\s+)?(transaction|transfer|payment|withdrawal)/i,
            /reveal\s+(the\s+)?(account|balance|transaction)\s*(data|details|info|history|number)/i,
            /skip\s+(the\s+)?(verification|authentication|security\s+check)/i,
            /move\s+(funds|money|\$\d)/i,
        ],
    },
    context_injection: {
        label: 'Context Injection',
        severity: 'high',
        weight: 0.80,
        patterns: [
            /\[SYSTEM\]/i,
            /\[ADMIN\]/i,
            /\[OVERRIDE\]/i,
            /\[INSTRUCTION\]/i,
            /\[PRIORITY\]/i,
            /<<<\s*(system|admin|override)/i,
            />>>\s*(end|begin)\s*(system|admin)/i,
            /new\s+system\s+(instructions?|message|prompt)/i,
            /---\s*begin\s+(system|admin|override)/i,
            /update(d)?\s+system\s+(prompt|instructions?|rules?)/i,
            /inject(ing|ed)?\s+(new\s+)?(context|instructions?|rules?)/i,
            /system:\s*(you\s+are|ignore|override|new\s+rules?)/i,
            /\[HIDDEN\s*INSTRUCTION\]/i,
            /\[CONFIDENTIAL\]/i,
            /\{\{.*system.*\}\}/i,
        ],
    },
};

/**
 * Analyze input text for potential threats
 * @param {string} input - User input text
 * @returns {{ detected: boolean, threats: Array, totalConfidence: number }}
 */
export function detectThreats(input) {
    if (!input || typeof input !== 'string') {
        return { detected: false, threats: [], totalConfidence: 0 };
    }

    const normalizedInput = input.trim();
    const threats = [];

    for (const [category, config] of Object.entries(THREAT_PATTERNS)) {
        const matchedPatterns = [];

        for (const pattern of config.patterns) {
            const match = normalizedInput.match(pattern);
            if (match) {
                matchedPatterns.push({
                    pattern: pattern.source,
                    matched: match[0],
                });
            }
        }

        if (matchedPatterns.length > 0) {
            const patternRatio = matchedPatterns.length / config.patterns.length;
            const confidence = Math.min(
                config.weight * (0.6 + patternRatio * 0.4) * 100,
                100
            );

            threats.push({
                category,
                label: config.label,
                severity: config.severity,
                confidence: Math.round(confidence),
                matchedPatterns,
                patternCount: matchedPatterns.length,
            });
        }
    }

    const totalConfidence = threats.length > 0
        ? Math.round(threats.reduce((sum, t) => sum + t.confidence, 0) / threats.length)
        : 0;

    return {
        detected: threats.length > 0,
        threats,
        totalConfidence,
    };
}

export { THREAT_PATTERNS };
