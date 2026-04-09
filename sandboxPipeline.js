/**
 * FinTrust – Sandbox Pipeline
 * Orchestrates: Input → Threat Detection → Risk Scoring → Decision → Response
 */

import { detectThreats } from './threatDetector';
import { calculateRiskScore } from './riskScorer';
import { makeDecision } from './decisionEngine';

/**
 * Run the full sandbox security pipeline on user input
 * @param {string} input - Raw user input
 * @param {boolean} sandboxEnabled - Whether sandbox protection is active
 * @returns {Object} Full analysis result
 */
export function runSandboxPipeline(input, sandboxEnabled = true) {
    const timestamp = new Date().toISOString();
    const id = `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    // Step 1: Threat Detection
    const detection = detectThreats(input);

    // Step 2: Risk Scoring
    const risk = calculateRiskScore(detection);

    // Step 3: Decision
    const decision = sandboxEnabled
        ? makeDecision(risk, detection)
        : {
            action: 'ALLOW',
            label: 'No Protection',
            response: null,
            explanation: 'Sandbox is disabled. Input processed without security checks.',
            shouldLog: false,
            color: 'red',
            icon: '❌',
        };

    // Build analysis report
    const analysis = {
        id,
        timestamp,
        input: input.substring(0, 500),
        sandboxEnabled,
        detection: {
            detected: detection.detected,
            threatCount: detection.threats.length,
            threats: detection.threats,
            totalConfidence: detection.totalConfidence,
        },
        risk: {
            score: risk.score,
            level: risk.level,
            label: risk.label,
            color: risk.color,
            breakdown: risk.breakdown,
        },
        decision: {
            action: decision.action,
            label: decision.label,
            response: decision.response,
            explanation: decision.explanation,
            shouldLog: decision.shouldLog,
            color: decision.color,
            icon: decision.icon,
            details: decision.details || null,
        },
    };

    return analysis;
}

/**
 * Run a predefined attack simulation
 * @param {string} attackPayload - The attack input
 * @returns {{ vulnerable: Object, protected: Object }}
 */
export function runAttackSimulation(attackPayload) {
    const vulnerable = runSandboxPipeline(attackPayload, false);
    const protected_ = runSandboxPipeline(attackPayload, true);

    return {
        vulnerable,
        protected: protected_,
    };
}
