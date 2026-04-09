# 🏛️ FinTrust — System Architecture

> Technical architecture document for the FinTrust AI Security Sandbox Platform.

---

## 1. High-Level Overview

FinTrust is a client-heavy React SPA with a thin serverless backend, designed to demonstrate how AI agents in banking environments can be secured against prompt injection attacks.

```
┌──────────────────────────────────────────────────────────────────┐
│                        CLIENT (React SPA)                        │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌──────┐│
│  │ AI Chat  │  │Attack Lab│  │Analytics │  │ Audit  │  │Admin ││
│  │  Page    │  │  Page    │  │  Page    │  │ Logs   │  │Panel ││
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘  └──┬───┘│
│       │              │              │             │          │    │
│       └──────────────┴──────┬───────┴─────────────┴──────────┘   │
│                             │                                    │
│                    ┌────────▼────────┐                            │
│                    │  Threat Store   │ (React Context + Reducer)  │
│                    │  (Global State) │                            │
│                    └────────┬────────┘                            │
│                             │                                    │
│        ┌────────────────────┼────────────────────┐               │
│        │                    │                    │               │
│  ┌─────▼─────┐  ┌──────────▼──────────┐  ┌─────▼──────┐        │
│  │  LLM      │  │  Security Pipeline  │  │  Supabase  │        │
│  │  Client   │  │  (4-Stage Engine)   │  │  Service   │        │
│  └─────┬─────┘  └──────────┬──────────┘  └─────┬──────┘        │
└────────┼────────────────────┼────────────────────┼───────────────┘
         │                    │                    │
         ▼                    │                    ▼
   ┌───────────┐              │           ┌──────────────┐
   │ Groq API  │              │           │   Supabase   │
   │ (LLaMA 3) │              │           │ (PostgreSQL) │
   └───────────┘              │           └──────────────┘
                              │
                    ┌─────────▼─────────┐
                    │ Vercel Serverless  │
                    │   API (Gemini)     │
                    └───────────────────┘
```

---

## 2. Security Pipeline Architecture

The core differentiator of FinTrust. Every user input is processed through a 4-stage pipeline before reaching the LLM.

### Pipeline Flow

```
         ┌─────────────┐
         │  User Input  │
         └──────┬───────┘
                │
                ▼
    ┌───────────────────────┐
    │   STAGE 1: DETECTION  │
    │   threatDetector.js   │
    │                       │
    │  • 70+ regex patterns │
    │  • 5 attack categories│
    │  • Pattern matching   │
    │  • Confidence scoring │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │   STAGE 2: SCORING    │
    │   riskScorer.js       │
    │                       │
    │  • Severity weights   │
    │  • Pattern multiplier │
    │  • Category multiplier│
    │  • Score: 0–100       │
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │   STAGE 3: DECISION   │
    │   decisionEngine.js   │
    │                       │
    │  • Threshold-based    │
    │  • ALLOW / WARN / BLOCK│
    │  • Safe response gen  │
    │  • Audit metadata     │
    └───────────┬───────────┘
                │
         ┌──────┴──────┐
         │             │
    ┌────▼────┐  ┌─────▼─────┐
    │  ALLOW  │  │   BLOCK   │
    │  /WARN  │  │           │
    └────┬────┘  └─────┬─────┘
         │             │
         ▼             ▼
    ┌─────────┐  ┌──────────────┐
    │ LLM API │  │ Safe Response │
    │ (Groq)  │  │ + Threat Card │
    └─────────┘  └──────────────┘
```

### Stage 1 — Threat Detector (`threatDetector.js`)

**Purpose:** Pattern-based scanning of user inputs for known prompt injection techniques.

| Category | Severity | Weight | Pattern Count |
|----------|----------|--------|---------------|
| Instruction Override | Critical | 0.95 | 16 |
| Authority Escalation | High | 0.85 | 16 |
| Data Exfiltration | Critical | 0.90 | 18 |
| Financial Transaction Attack | Critical | 0.95 | 16 |
| Context Injection | High | 0.80 | 15 |

**Output:** `{ detected: boolean, threats: Array, totalConfidence: number }`

Each threat includes the matched patterns, confidence score, and severity level.

### Stage 2 — Risk Scorer (`riskScorer.js`)

**Purpose:** Converts threat detection results into a normalized 0–100 risk score.

**Scoring Formula:**

```
finalScore = baseSeverity × patternMultiplier × categoryMultiplier
```

| Factor | Calculation |
|--------|-------------|
| **Base Severity** | Highest severity weight among detected threats |
| **Pattern Multiplier** | `1 + (totalPatterns - 1) × 0.1` (capped at 1.5×) |
| **Category Multiplier** | `1 + (categoryCount - 1) × 0.15` (capped at 1.4×) |

**Risk Levels:**

| Level | Score Range | Color |
|-------|-----------|-------|
| LOW | 0–25 | Emerald |
| MEDIUM | 26–50 | Amber |
| HIGH | 51–75 | Red |
| CRITICAL | 76–100 | Rose |

### Stage 3 — Decision Engine (`decisionEngine.js`)

**Purpose:** Maps risk scores to actionable security decisions.

| Risk Level | Action | Behavior |
|-----------|--------|----------|
| LOW | ✅ ALLOW | Pass input to LLM |
| MEDIUM | ⚠️ WARN | Pass to LLM with warning context |
| HIGH | 🛡️ BLOCK | Return pre-built safe response |
| CRITICAL | 🚨 BLOCK + LOG | Block, return safe response, log to Supabase |

**Safe Responses:** Pre-written, category-specific refusal messages that do not leak detection logic.

### Stage 4 — Pipeline Orchestrator (`sandboxPipeline.js`)

**Purpose:** Chains stages 1–3 into a single function call, producing a complete analysis object.

```js
const analysis = runSandboxPipeline(userInput, sandboxEnabled);
// Returns: { id, timestamp, detection, risk, decision }
```

Also provides `runAttackSimulation()` which runs the same input through both protected and vulnerable modes for side-by-side comparison.

---

## 3. Dual-Mode LLM Architecture

FinTrust supports two LLM backends and two behavioral modes.

### LLM Backends

| Backend | Model | File | Use Case |
|---------|-------|------|----------|
| **Groq** | LLaMA 3.3 70B | `llm.js` | Primary — fast inference |
| **Gemini** | Gemini 2.0 Flash | `Agent.js` | Fallback / Serverless |

### Behavioral Modes

#### Protected Mode (Sandbox ON)

```
User Message + File → Security Pipeline → [ALLOW?] → Protected System Prompt → Groq API
```

- System prompt enforces banking-domain restriction, zero-trust, and output rules
- Flagged queries receive additional safety context before reaching the LLM
- Blocked queries never reach the LLM — a safe response is returned directly

#### Vulnerable Mode (Sandbox OFF)

```
User Message → Attack Type Detection → [Match?] → Simulated Vulnerable Response
                                       [No Match] → Vulnerable System Prompt → Groq API
```

- Deliberately permissive system prompt that simulates a compromised AI
- Pre-built vulnerable simulations for 5 attack types (admin access, data leak, money transfer, system prompt reveal, instruction override)
- Demonstrates the real-world impact of prompt injection on unprotected systems

---

## 4. Data Layer

### Supabase (PostgreSQL)

All data is persisted to Supabase with Row-Level Security enabled on every table.

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    users     │     │   sessions   │     │   messages   │
│──────────────│     │──────────────│     │──────────────│
│ id (UUID/PK) │◄────│ user_id (FK) │     │ session_id   │
│ email        │     │ session_id   │     │ role         │
│ role         │     │ sandbox_on   │     │ content      │
│ display_name │     │ created_at   │     │ threat_info  │
│ created_at   │     │ ended_at     │     │ created_at   │
└──────────────┘     └──────────────┘     └──────────────┘

┌──────────────────┐     ┌──────────────┐
│   threat_logs    │     │  documents   │
│──────────────────│     │──────────────│
│ scan_id (unique) │     │ session_id   │
│ session_id       │     │ filename     │
│ input_text       │     │ file_type    │
│ threat_score     │     │ extracted_text│
│ risk_level       │     │ risk_level   │
│ decision         │     │ scan_result  │
│ patterns[]       │     │ uploaded_at  │
│ detection_details│     └──────────────┘
│ risk_breakdown   │
└──────────────────┘
```

**Indexes:** Optimized for `session_id` lookups, `created_at DESC` ordering, and `risk_level` / `decision` filtering.

### Client-Side State

Global state is managed via React Context + `useReducer` in `threatStore.jsx`:

| State | Purpose |
|-------|---------|
| `messages[]` | Current chat session messages |
| `sandboxEnabled` | Toggle for security pipeline |
| `threatLogs[]` | All threat scan results (seeded with demo data) |
| `analytics{}` | Computed aggregates (total scans, blocks, avg score) |
| `currentSession` | Active session identifier |

---

## 5. Frontend Architecture

### Routing

```
/            → Redirect to /chat
/chat        → ChatPage     (AI chat + file uploads)
/attack-lab  → AttackLabPage (Attack simulations)
/analytics   → AnalyticsPage (Charts & metrics)
/audit-logs  → AuditLogsPage (Searchable log table)
/admin       → AdminPage     (System controls)
```

### Component Hierarchy

```
App
├── ThreatStoreProvider (Global State)
├── BrowserRouter
│   └── Layout
│       ├── Sidebar (Navigation)
│       └── <Page>
│           ├── ChatPage
│           │   └── ThreatDetectionCard
│           │       └── RiskMeter
│           ├── AttackLabPage
│           ├── AnalyticsPage (Recharts)
│           ├── AuditLogsPage
│           └── AdminPage
└── Toaster (react-hot-toast)
```

### UI Design System

- **Theme:** Dark mode with slate/gray base and glassmorphism panels
- **Accents:** Emerald (safe), Amber (warn), Red/Rose (threat/critical), Cyan (info)
- **Icons:** Lucide React icon library throughout
- **Animations:** Smooth transitions on sandbox toggle, message bubbles, and threat cards

---

## 6. Deployment Architecture

```
┌─────────────┐   HTTPS    ┌──────────────────────┐
│   Browser   │──────────►│     Vercel Edge      │
│   (SPA)     │◄──────────│                      │
└──────┬──────┘           │  ┌────────────────┐  │
       │                   │  │  Static Assets │  │
       │                   │  │  (React Build) │  │
       │                   │  └────────────────┘  │
       │                   │                      │
       │   /api/chat       │  ┌────────────────┐  │
       └──────────────────►│  │  Serverless Fn │  │
                           │  │  (api/chat.js) │──│──► Gemini API
                           │  └────────────────┘  │
                           └──────────────────────┘
                                      │
          Client-side API calls       │
          ┌───────────────────────────┘
          │
   ┌──────▼──────┐      ┌──────────────┐
   │  Groq API   │      │   Supabase   │
   │  (LLaMA 3)  │      │ (PostgreSQL) │
   └─────────────┘      └──────────────┘
```

- **Static Assets:** Vite-built React SPA served from Vercel's CDN
- **API Routes:** `/api/chat` proxied to Vercel Serverless Functions
- **Client-Side Routing:** SPA fallback configured in `vercel.json`
- **Environment Variables:** API keys stored in Vercel's environment config (never bundled)

---

## 7. Security Considerations

| Aspect | Implementation |
|--------|---------------|
| **API Key Protection** | Keys in `.env`, never exposed to client bundle in production serverless path |
| **Row-Level Security** | All Supabase tables have RLS enabled |
| **Input Sanitization** | All inputs normalized and length-capped (500 chars) before logging |
| **Domain Restriction** | LLM system prompt enforces banking-only topic policy |
| **Zero-Trust Prompt** | System prompt treats all authority claims as social engineering |
| **No Client-Side Secrets** | Serverless function handles Gemini API calls server-side |

---

## 8. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Client-side security pipeline** | Enables real-time threat visualization and Attack Lab simulations without API latency |
| **Regex over ML for detection** | Deterministic, explainable results ideal for educational demonstration; zero inference cost |
| **Dual LLM backends** | Groq for fast chat, Gemini for serverless fallback — resilience through redundancy |
| **React Context over Redux** | Lightweight state management sufficient for the app's complexity |
| **Seeded demo data** | Pre-populated threat logs show the analytics dashboard immediately without requiring real attacks |
| **Simulated vulnerable responses** | Hard-coded dramatic "compromised" outputs make the security contrast visually impactful |

---

<p align="center"><em>FinTrust — Securing AI-Powered Banking, One Prompt at a Time.</em></p>
