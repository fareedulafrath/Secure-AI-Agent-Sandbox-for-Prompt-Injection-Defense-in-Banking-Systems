-- ═══════════════════════════════════════════
-- FinTrust – Supabase Database Schema
-- ═══════════════════════════════════════════

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  display_name TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id TEXT UNIQUE NOT NULL,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  sandbox_enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now(),
  ended_at TIMESTAMPTZ
);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('user', 'ai')),
  content TEXT NOT NULL,
  sandbox_enabled BOOLEAN DEFAULT true,
  threat_info JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Threat logs table
CREATE TABLE IF NOT EXISTS threat_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id TEXT UNIQUE NOT NULL,
  session_id TEXT,
  input_text TEXT NOT NULL,
  sandbox_enabled BOOLEAN DEFAULT true,
  threat_score INTEGER DEFAULT 0,
  risk_level TEXT CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  decision TEXT CHECK (decision IN ('ALLOW', 'WARN', 'BLOCK')),
  patterns TEXT[] DEFAULT '{}',
  category TEXT,
  detection_details JSONB,
  risk_breakdown JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Documents table
CREATE TABLE IF NOT EXISTS documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id TEXT,
  filename TEXT NOT NULL,
  file_type TEXT,
  file_size INTEGER,
  extracted_text TEXT,
  risk_level TEXT CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  scan_result JSONB,
  uploaded_at TIMESTAMPTZ DEFAULT now()
);

-- ═══════════════════════════════════════════
-- Indexes
-- ═══════════════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_threat_logs_created ON threat_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_logs_decision ON threat_logs(decision);
CREATE INDEX IF NOT EXISTS idx_threat_logs_risk ON threat_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_documents_session ON documents(session_id);

-- ═══════════════════════════════════════════
-- Row Level Security
-- ═══════════════════════════════════════════

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- Public read access for demo (restrict in production)
CREATE POLICY "Allow public read" ON users FOR SELECT USING (true);
CREATE POLICY "Allow public read" ON sessions FOR SELECT USING (true);
CREATE POLICY "Allow public read" ON messages FOR SELECT USING (true);
CREATE POLICY "Allow public read" ON threat_logs FOR SELECT USING (true);
CREATE POLICY "Allow public read" ON documents FOR SELECT USING (true);

-- Public insert for demo
CREATE POLICY "Allow public insert" ON messages FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public insert" ON threat_logs FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public insert" ON documents FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public insert" ON sessions FOR INSERT WITH CHECK (true);
