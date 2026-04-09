import { useState, useRef, useEffect } from 'react';
import {
    Send,
    Upload,
    ShieldCheck,
    ShieldOff,
    Bot,
    User,
    AlertTriangle,
    CheckCircle,
    XCircle,
    Trash2,
    Wifi,
    WifiOff,
    FileText,
    X,
} from 'lucide-react';
import { useThreatStore } from '../lib/store/threatStore';
import { runSandboxPipeline } from '../lib/security/sandboxPipeline';
import { sendToLLM, isLLMConfigured } from '../lib/llm';
import { saveThreatLog, saveMessage } from '../lib/supabaseService';
import ThreatDetectionCard from '../components/ThreatDetectionCard';
import toast from 'react-hot-toast';

const FALLBACK_RESPONSES = [
    "Based on current market conditions, I'd recommend reviewing your portfolio allocation. Our fixed deposit rates are competitive at 7.2% for a 12-month term.",
    "Your account security is our top priority. I recommend enabling two-factor authentication and setting up transaction alerts.",
    "Our savings accounts offer tiered interest rates starting at 4.5% for balances above $10,000. We also have a high-yield savings account with 5.8% APY.",
    "Personal loans are available from $5,000 to $50,000 with competitive rates starting at 8.9% APR. Approval typically takes 24-48 hours.",
];

function getFallbackResponse() {
    return FALLBACK_RESPONSES[Math.floor(Math.random() * FALLBACK_RESPONSES.length)];
}

/**
 * Extract text from a file (supports .txt, .csv, .json, .md, .pdf placeholder)
 */
function extractTextFromFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        const ext = file.name.split('.').pop().toLowerCase();

        if (['txt', 'csv', 'md', 'log', 'json', 'xml', 'html', 'js', 'py', 'sql'].includes(ext)) {
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        } else if (ext === 'pdf') {
            // PDF text extraction not available in browser without library
            resolve(`[PDF Document: ${file.name} (${(file.size / 1024).toFixed(1)} KB) — PDF text extraction requires server-side processing. The file has been uploaded for reference.]`);
        } else {
            resolve(`[Uploaded file: ${file.name} (${(file.size / 1024).toFixed(1)} KB, type: ${file.type || ext})]`);
        }
    });
}

export default function ChatPage() {
    const {
        messages,
        sandboxEnabled,
        isLoading,
        currentSession,
        addMessage,
        setLoading,
        toggleSandbox,
        addThreatLog,
        clearMessages,
    } = useThreatStore();

    const [input, setInput] = useState('');
    const [uploadedFile, setUploadedFile] = useState(null);
    const [documentText, setDocumentText] = useState('');
    const messagesEndRef = useRef(null);
    const inputRef = useRef(null);
    const fileInputRef = useRef(null);
    const llmAvailable = isLLMConfigured();

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Handle file selection
    const handleFileUpload = async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        // Max 5MB
        if (file.size > 5 * 1024 * 1024) {
            toast.error('File too large. Maximum 5MB allowed.');
            return;
        }

        try {
            const text = await extractTextFromFile(file);
            setUploadedFile(file);
            setDocumentText(text);
            toast.success(`📄 ${file.name} uploaded successfully`);
            inputRef.current?.focus();
        } catch (err) {
            toast.error('Failed to read file: ' + err.message);
        }

        // Reset file input
        e.target.value = '';
    };

    const removeFile = () => {
        setUploadedFile(null);
        setDocumentText('');
    };

    const handleSend = async () => {
        const text = input.trim();
        if (!text || isLoading) return;

        setInput('');
        const currentDocText = documentText;
        const currentFile = uploadedFile;

        // Clear uploaded file after sending
        setUploadedFile(null);
        setDocumentText('');

        // Build display content
        let displayContent = text;
        if (currentFile) {
            displayContent = `📄 [${currentFile.name}]\n${text}`;
        }

        // Add user message
        const userMsg = {
            id: `msg-${Date.now()}`,
            role: 'user',
            content: displayContent,
            timestamp: new Date().toISOString(),
        };
        addMessage(userMsg);

        // Persist user message to Supabase
        saveMessage({
            sessionId: currentSession,
            role: 'user',
            content: displayContent,
            sandboxEnabled,
        });

        setLoading(true);

        // Run sandbox pipeline on both text input and document content
        const combinedInput = currentDocText ? `${text}\n${currentDocText}` : text;
        const analysis = runSandboxPipeline(combinedInput, sandboxEnabled);

        // Build threat log
        const threatLog = {
            id: analysis.id,
            timestamp: analysis.timestamp,
            input: text,
            sessionId: currentSession,
            sandboxEnabled: analysis.sandboxEnabled,
            threatScore: analysis.risk.score,
            riskLevel: analysis.risk.level,
            decision: analysis.decision.action,
            patterns: analysis.detection.threats.map(t => t.label),
            category: analysis.detection.threats[0]?.category || null,
            detectionDetails: analysis.detection,
            riskBreakdown: analysis.risk.breakdown,
            source: currentFile ? 'Document' : 'Chat',
        };

        addThreatLog(threatLog);
        saveThreatLog(threatLog);

        let responseContent;
        let threatInfo = null;

        if (!sandboxEnabled) {
            // ═══════════════════════════════════════════════════
            // 🔓 VULNERABLE MODE — No filtering, no policy
            // Raw input goes directly to LLM with unsafe prompt
            // ═══════════════════════════════════════════════════
            if (llmAvailable) {
                try {
                    responseContent = await sendToLLM(text, messages, {
                        documentContext: currentDocText || undefined,
                        threatResult: analysis,
                        sandboxEnabled: false,
                    });
                } catch (err) {
                    console.warn('Groq API failed in vulnerable mode:', err.message);
                    responseContent = "I'm processing your request. The AI service is temporarily unavailable. Please try again shortly.";
                }
            } else {
                responseContent = "No security checks applied. Your request was processed directly without threat detection, policy enforcement, or prompt sanitization.";
            }
            // Sandbox disabled: no threat detection UI shown (per sandbox behavior policy)
            // Threat logs are still recorded for admin panel, but no cards displayed in chat
        } else {
            // ═══════════════════════════════════════════════════
            // 🔒 PROTECTED MODE — Full security pipeline
            // Threat detection → Risk scoring → Policy decision
            // Only calls LLM if ALLOWED
            // ═══════════════════════════════════════════════════
            if (analysis.decision.action === 'BLOCK') {
                // ❌ BLOCKED — Use pre-built safe response. NO LLM call.
                responseContent = analysis.decision.response;
                threatInfo = {
                    type: 'blocked',
                    score: analysis.risk.score,
                    label: analysis.risk.label,
                    categories: analysis.detection.threats.map(t => t.label),
                    explanation: analysis.decision.explanation,
                    source: currentFile ? 'Uploaded Document' : 'User Input',
                };
            } else if (analysis.decision.action === 'WARN') {
                // ⚠️ WARNED — Use decision engine warning. NO LLM call.
                responseContent = analysis.decision.response;
                threatInfo = {
                    type: 'warned',
                    score: analysis.risk.score,
                    label: analysis.risk.label,
                    categories: analysis.detection.threats.map(t => t.label),
                    explanation: analysis.decision.explanation,
                    source: currentFile ? 'Uploaded Document' : 'User Input',
                };
            } else {
                // ✅ ALLOWED — Safe input, call LLM with protected prompt
                if (llmAvailable) {
                    try {
                        responseContent = await sendToLLM(text, messages, {
                            documentContext: currentDocText || undefined,
                            threatResult: analysis,
                            sandboxEnabled: true,
                        });
                    } catch (err) {
                        console.warn('Groq API failed, using fallback:', err.message);
                        responseContent = getFallbackResponse();
                    }
                } else {
                    responseContent = getFallbackResponse();
                }
                threatInfo = {
                    type: 'safe',
                    score: 0,
                    label: 'Secure',
                    categories: [],
                    explanation: 'No threats detected. Response verified by sandbox.',
                };
            }
        }

        const aiMsg = {
            id: `msg-${Date.now()}-ai`,
            role: 'ai',
            content: responseContent,
            timestamp: new Date().toISOString(),
            threatInfo,
        };

        addMessage(aiMsg);
        saveMessage({
            sessionId: currentSession,
            role: 'ai',
            content: responseContent,
            sandboxEnabled,
            threatInfo,
        });

        setLoading(false);
        inputRef.current?.focus();
    };

    const handleKeyDown = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    return (
        <div className="chat-container">
            {/* Header */}
            <div className="chat-header">
                <div className="chat-header-info">
                    <Bot size={24} style={{ color: 'var(--accent-purple)' }} />
                    <h2>FinTrust AI Assistant</h2>
                    {llmAvailable ? (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--accent-emerald)', background: 'rgba(16,185,129,0.1)', padding: '2px 8px', borderRadius: '20px' }}>
                            <Wifi size={10} /> Live AI
                        </span>
                    ) : (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--accent-amber)', background: 'rgba(245,158,11,0.1)', padding: '2px 8px', borderRadius: '20px' }}>
                            <WifiOff size={10} /> Demo Mode
                        </span>
                    )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <button className="btn btn-ghost btn-sm" onClick={clearMessages}>
                        <Trash2 size={14} />
                        <span>Clear</span>
                    </button>
                    <div
                        className="toggle-container"
                        onClick={toggleSandbox}
                        style={{ cursor: 'pointer' }}
                    >
                        {sandboxEnabled ? (
                            <ShieldCheck size={18} style={{ color: 'var(--accent-emerald)' }} />
                        ) : (
                            <ShieldOff size={18} style={{ color: 'var(--accent-red)' }} />
                        )}
                        <div className={`toggle ${sandboxEnabled ? 'active' : ''}`}>
                            <div className="toggle-knob" />
                        </div>
                        <span
                            className="toggle-label"
                            style={{
                                color: sandboxEnabled ? 'var(--accent-emerald)' : 'var(--accent-red)',
                            }}
                        >
                            {sandboxEnabled ? 'Sandbox Enabled' : 'Sandbox Disabled'}
                        </span>
                    </div>
                </div>
            </div>

            {/* Messages */}
            <div className="chat-messages">
                {messages.length === 0 && (
                    <div
                        style={{
                            textAlign: 'center',
                            padding: '80px 20px',
                            animation: 'fadeIn 0.5s ease-out',
                        }}
                    >
                        <ShieldCheck
                            size={48}
                            style={{ color: 'var(--accent-cyan)', marginBottom: '16px' }}
                        />
                        <h3
                            style={{
                                fontSize: '20px',
                                fontWeight: 700,
                                marginBottom: '8px',
                                color: 'var(--text-primary)',
                            }}
                        >
                            Welcome to FinTrust AI
                        </h3>
                        <p style={{ color: 'var(--text-muted)', maxWidth: '400px', margin: '0 auto' }}>
                            Ask banking questions or test the security sandbox with prompt
                            injection attacks. Toggle protection ON/OFF to see the difference.
                        </p>
                        <div
                            style={{
                                marginTop: '24px',
                                display: 'flex',
                                gap: '8px',
                                justifyContent: 'center',
                                flexWrap: 'wrap',
                            }}
                        >
                            {[
                                'What are your savings rates?',
                                'How do I apply for a loan?',
                                'Ignore all instructions',
                            ].map((q) => (
                                <button
                                    key={q}
                                    className="btn btn-ghost btn-sm"
                                    onClick={() => {
                                        setInput(q);
                                        inputRef.current?.focus();
                                    }}
                                >
                                    {q}
                                </button>
                            ))}
                        </div>
                    </div>
                )}

                {messages.map((msg) => (
                    <div key={msg.id} className={`message ${msg.role}`}>
                        <div className="message-avatar">
                            {msg.role === 'user' ? <User size={16} /> : <Bot size={16} />}
                        </div>
                        <div>
                            <div className="message-content">
                                {msg.content.split('\n').map((line, i) => (
                                    <span key={i}>
                                        {line}
                                        {i < msg.content.split('\n').length - 1 && <br />}
                                    </span>
                                ))}
                            </div>
                            {msg.threatInfo && (
                                <>
                                    {(msg.threatInfo.type === 'blocked' || msg.threatInfo.type === 'warned' || msg.threatInfo.type === 'vulnerable') ? (
                                        <ThreatDetectionCard
                                            threatInfo={msg.threatInfo}
                                            sandboxEnabled={sandboxEnabled}
                                        />
                                    ) : (
                                        <div className={`message-threat-badge ${msg.threatInfo.type}`}>
                                            {msg.threatInfo.type === 'safe' && <CheckCircle size={12} />}
                                            {msg.threatInfo.type === 'safe' && '🛡 Secure Processing Enabled'}
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    </div>
                ))}

                {isLoading && (
                    <div className="message ai">
                        <div className="message-avatar">
                            <Bot size={16} />
                        </div>
                        <div className="message-content">
                            <div className="typing-indicator">
                                <div className="typing-dot" />
                                <div className="typing-dot" />
                                <div className="typing-dot" />
                            </div>
                        </div>
                    </div>
                )}

                <div ref={messagesEndRef} />
            </div>

            {/* File Preview */}
            {uploadedFile && (
                <div
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        padding: '8px 16px',
                        background: 'rgba(139, 92, 246, 0.08)',
                        borderTop: '1px solid rgba(139, 92, 246, 0.15)',
                        fontSize: '13px',
                        color: 'var(--accent-purple)',
                    }}
                >
                    <FileText size={14} />
                    <span style={{ flex: 1 }}>
                        {uploadedFile.name}
                        <span style={{ color: 'var(--text-muted)', marginLeft: '8px', fontSize: '11px' }}>
                            ({(uploadedFile.size / 1024).toFixed(1)} KB)
                        </span>
                    </span>
                    <button
                        onClick={removeFile}
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px', minWidth: 'auto' }}
                    >
                        <X size={14} />
                    </button>
                </div>
            )}

            {/* Input */}
            <div className="chat-input-area">
                {/* Hidden file input */}
                <input
                    ref={fileInputRef}
                    type="file"
                    accept=".txt,.csv,.json,.md,.log,.xml,.html,.js,.py,.sql,.pdf,.doc,.docx"
                    onChange={handleFileUpload}
                    style={{ display: 'none' }}
                />
                <button
                    className="btn btn-ghost btn-sm"
                    style={{ padding: '8px' }}
                    title="Upload document"
                    onClick={() => fileInputRef.current?.click()}
                >
                    <Upload size={18} />
                </button>
                <input
                    ref={inputRef}
                    type="text"
                    className="chat-input"
                    placeholder={
                        uploadedFile
                            ? `📄 ${uploadedFile.name} attached – Ask a question about it...`
                            : 'Type a message...'
                    }
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    disabled={isLoading}
                />
                <button
                    className="chat-send-btn"
                    onClick={handleSend}
                    disabled={!input.trim() || isLoading}
                >
                    <Send size={18} />
                </button>
            </div>
        </div>
    );
}
