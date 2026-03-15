const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

// ============================================================
// CONFIGURATION
// ============================================================
const CONFIG = {
  // Scoring thresholds
  SCORE_THRESHOLD: {
    SUSPICIOUS: 0.3,  // Score above this = suspicious
    LIKELY_AI: 0.5,   // Score above this = likely AI
    CONFIRMED_AI: 0.8 // Score above this = confirmed AI
  },
  
  // Rate limiting
  RATE_LIMIT: {
    WINDOW_MS: 60000, // 1 minute
    MAX_REQUESTS: 10
  },
  
  // Behavioral analysis
  BEHAVIORAL: {
    MIN_REQUEST_INTERVAL_MS: 500,
    BURST_THRESHOLD: 5 // requests in quick succession
  },
  
  // Proof of Work
  POW: {
    DIFFICULTY: 20,
    PREFIX: 'pow:'
  },
  
  // Known browser JA3 fingerprints (simplified list)
  BROWSER_JA3_PATTERNS: [
    '772e0e0928c9e8d8e4c0f3c7d8e4f3c7',
    // Add actual browser fingerprints here
  ]
};

// In-memory store for rate limiting (use Redis in production)
const requestHistory = new Map();
const challengeStore = new Map();

// ============================================================
// 1. HEADER-BASED DETECTION
// ============================================================
const AI_PATTERNS = [
  // Perplexity
  'perplexitybot', 'perplexity-user', 'perplexity',
  // Claude
  'claude-web', 'claude-browser', 'claude-bot', 'claude',
  // ChatGPT
  'chatgpt-user', 'chatgpt-atlas', 'chatgpt', 'gptbot',
  // Anthropic
  'anthropic-ai', 'anthropic',
  // Google
  'google-extended', 'googleai-bot', 'googlebot',
  // OpenAI
  'openai', 'openai-search-preview',
  // Common AI patterns
  'ai-bot', 'ai-crawler', 'ai-agent', 'gemini',
  // Other AI agents
  'meta-external-agent', 'meta-agent', 'duckduckbot',
  'bingbot', 'bingpreview', 'yandexbot'
];

function detectFromHeaders(req) {
  const score = { method: 'header', value: 0, details: [] };
  
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const aiAgent = req.headers['ai-agent'] || req.headers['sec-ai-agent'];
  
  // Check User-Agent for AI patterns
  if (userAgent) {
    for (const pattern of AI_PATTERNS) {
      // More specific patterns first to avoid partial matches
      if (userAgent.includes(pattern)) {
        score.value += 0.5;
        score.details.push({ type: 'user-agent', pattern, match: userAgent });
        break;
      }
    }
  }
  
  // Custom AI-Agent header (high confidence if present)
  if (aiAgent) {
    score.value += 0.5;
    score.details.push({ type: 'ai-agent-header', value: aiAgent });
  }
  
  // Check for ABSENT browser headers (AI agents often don't send these)
  // Only triggers if there's a user-agent but missing browser headers
  const browserHeaders = ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'accept-language'];
  const missingHeaders = browserHeaders.filter(h => !req.headers[h]);
  
  if (userAgent && missingHeaders.length >= 3) {
    score.value += 0.2;
    score.details.push({ type: 'missing-browser-headers', missing: missingHeaders });
  }
  
  // Check for unusual accept header
  const accept = req.headers['accept'] || '';
  if (accept && !accept.includes('text/html') && !accept.includes('application/json') && !accept.includes('*/*')) {
    score.value += 0.1;
    score.details.push({ type: 'unusual-accept', value: accept });
  }
  
  return score;
}

// ============================================================
// 2. CRYPTOGRAPHIC VERIFICATION
// ============================================================
const SIGNATURE_PUBLIC_KEYS = new Map(); // In production, load from trusted sources

function verifySignature(req) {
  const score = { method: 'signature', value: 0, details: [] };
  
  const signature = req.headers['signature'];
  const keyId = req.headers['key-id'];
  
  if (!signature || !keyId) {
    // No signature = neutral (not penalized, but no bonus)
    score.details.push({ type: 'no-signature', note: 'Optional verification' });
    return score;
  }
  
  // In production: verify HTTP Message Signature using http-message-signatures
  // For now, we simulate the check
  const isValid = verifyHttpSignature(req, signature, keyId);
  
  if (isValid) {
    score.value += 0.3;
    score.details.push({ type: 'valid-signature', keyId });
  } else {
    score.value += 0.5; // Invalid signature = suspicious
    score.details.push({ type: 'invalid-signature', keyId });
  }
  
  return score;
}

function verifyHttpSignature(req, signature, keyId) {
  // Placeholder: implement actual HTTP Message Signature verification
  // https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures
  const publicKey = SIGNATURE_PUBLIC_KEYS.get(keyId);
  if (!publicKey) return false;
  
  // Verify the signature against request components
  return crypto.verify(
    null,
    Buffer.from(JSON.stringify({ method: req.method, path: req.path })),
    publicKey,
    Buffer.from(signature, 'base64')
  );
}

// ============================================================
// 3. BEHAVIORAL ANALYSIS
// ============================================================
function analyzeBehavior(req) {
  const score = { method: 'behavioral', value: 0, details: [] };
  
  const clientIp = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  const now = Date.now();
  
  // Initialize history for this IP
  if (!requestHistory.has(clientIp)) {
    requestHistory.set(clientIp, { requests: [], lastRequest: null });
  }
  
  const history = requestHistory.get(clientIp);
  
  // Check request timing (burst detection)
  if (history.lastRequest) {
    const interval = now - history.lastRequest;
    
    if (interval < CONFIG.BEHAVIORAL.MIN_REQUEST_INTERVAL_MS) {
      score.value += 0.3;
      score.details.push({ type: 'rapid-requests', intervalMs: interval });
    }
  }
  
  // Update history
  history.requests.push(now);
  history.lastRequest = now;
  
  // Keep only recent requests (last minute)
  const cutoff = now - CONFIG.RATE_LIMIT.WINDOW_MS;
  history.requests = history.requests.filter(t => t > cutoff);
  
  // Check rate limiting
  if (history.requests.length > CONFIG.RATE_LIMIT.MAX_REQUESTS) {
    score.value += 0.4;
    score.details.push({ type: 'rate-limit-exceeded', count: history.requests.length });
  }
  
  // Check for consistent timing (bots often have very regular intervals)
  if (history.requests.length >= 5) {
    const intervals = [];
    for (let i = 1; i < history.requests.length; i++) {
      intervals.push(history.requests[i] - history.requests[i-1]);
    }
    
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    
    // Very low variance = likely bot
    if (stdDev < 50 && avgInterval > 0) {
      score.value += 0.3;
      score.details.push({ type: 'regular-timing', stdDev, avgInterval });
    }
  }
  
  // Cleanup old entries periodically
  if (requestHistory.size > 10000) {
    const oldest = Math.min(...requestHistory.values().map(h => Math.min(...h.requests)));
    if (now - oldest > 3600000) requestHistory.clear();
  }
  
  return score;
}

// ============================================================
// 4. PROOF-OF-WORK CHALLENGE
// ============================================================
function generateChallenge() {
  const nonce = crypto.randomBytes(16).toString('hex');
  const difficulty = CONFIG.POW.DIFFICULTY;
  const challenge = `${CONFIG.POW.PREFIX}difficulty=${difficulty},nonce=${nonce}`;
  
  // Store challenge with expiry (5 minutes)
  const expiry = Date.now() + 300000;
  challengeStore.set(nonce, { difficulty, expiry, solved: false });
  
  return { challenge, nonce, difficulty };
}

function verifyChallenge(req, res, next) {
  const proof = req.headers['x-proof-of-work'] || req.headers['x-pow-solution'];
  
  if (!proof) {
    // Generate and send challenge
    const { challenge } = generateChallenge();
    res.set('X-Challenge', challenge);
    res.set('X-Challenge-Required', 'true');
    return res.status(402).json({ 
      error: 'Proof of work required',
      challenge,
      message: 'Include valid X-PoW-Solution header to proceed'
    });
  }
  
  // Verify the solution
  const [type, solution] = proof.split(':');
  
  if (type === 'pow') {
    const [nonce, result] = solution.split('=');
    const stored = challengeStore.get(nonce);
    
    if (!stored || stored.expiry < Date.now()) {
      return res.status(401).json({ error: 'Challenge expired' });
    }
    
    // Verify PoW (simplified - in production use proper hash verification)
    const hash = crypto.createHash('sha256');
    hash.update(nonce + result);
    const hashResult = hash.digest('hex');
    
    // Check if hash starts with required zeros
    const requiredZeros = Math.floor(stored.difficulty / 4);
    const startsWithZeros = hashResult.startsWith('0'.repeat(requiredZeros));
    
    if (startsWithZeros) {
      stored.solved = true;
      req.challengeSolved = true;
      return next();
    }
  }
  
  return res.status(401).json({ error: 'Invalid proof of work' });
}

// ============================================================
// 5. TLS FINGERPRINTING (JA3)
// ============================================================
function analyzeTLS(req) {
  const score = { method: 'tls', value: 0, details: [] };
  
  // In production, use 'node-ja3' or 'tls-client-hello' to get actual JA3
  // For now, we analyze available connection info
  
  const protocol = req.headers['x-forwarded-proto'] || 'http';
  const httpVersion = req.httpVersion;
  
  // Check HTTP version (AI agents often use HTTP/1.1 only)
  if (httpVersion === '1.1') {
    // This is common for both browsers and AI, so low weight
    score.details.push({ type: 'http-version', value: httpVersion });
  }
  
  // Check for proxy/load balancer headers (common for AI APIs)
  const forwarded = req.headers['forwarded'];
  const via = req.headers['via'];
  
  if (forwarded || via) {
    score.value += 0.1;
    score.details.push({ type: 'proxy-headers', forwarded, via });
  }
  
  // Connection header analysis
  const connection = req.headers['connection'] || '';
  if (connection.toLowerCase() === 'close') {
    score.value += 0.1;
    score.details.push({ type: 'connection-close', note: 'Non-persistent connection' });
  }
  
  return score;
}

// ============================================================
// 6. UNIFIED DETECTION MIDDLEWARE
// ============================================================
function detectAgenticAI(req, res, next) {
  const detection = {
    scores: [],
    totalScore: 0,
    isAI: false,
    confidence: 'unknown',
    details: {}
  };
  
  // Run all detection methods
  const headerScore = detectFromHeaders(req);
  const signatureScore = verifySignature(req);
  const behavioralScore = analyzeBehavior(req);
  const tlsScore = analyzeTLS(req);
  
  detection.scores = [headerScore, signatureScore, behavioralScore, tlsScore];
  detection.details = {
    headers: headerScore.details,
    signature: signatureScore.details,
    behavioral: behavioralScore.details,
    tls: tlsScore.details
  };
  
  // Calculate total score
  detection.totalScore = detection.scores.reduce((sum, s) => sum + s.value, 0);
  
  // Determine confidence level
  if (detection.totalScore >= CONFIG.SCORE_THRESHOLD.CONFIRMED_AI) {
    detection.confidence = 'confirmed';
    detection.isAI = true;
  } else if (detection.totalScore >= CONFIG.SCORE_THRESHOLD.LIKELY_AI) {
    detection.confidence = 'likely';
    detection.isAI = true;
  } else if (detection.totalScore >= CONFIG.SCORE_THRESHOLD.SUSPICIOUS) {
    detection.confidence = 'suspicious';
    detection.isAI = false; // Not confirmed, but suspicious
  } else {
    detection.confidence = 'normal';
    detection.isAI = false;
  }
  
  // Attach to request
  req.aiDetection = detection;
  req.isAgenticAI = detection.isAI;
  req.aiConfidence = detection.confidence;
  req.aiScore = detection.totalScore;
  
  next();
}

// ============================================================
// MAIN MIDDLEWARE CHAIN
// ============================================================

// Option A: Detection only (no challenge)
app.use(detectAgenticAI);

// Option B: With PoW challenge (uncomment to enable)
// app.use('/api/', verifyChallenge);

// ============================================================
// API ROUTES
// ============================================================

app.get('/api/data', (req, res) => {
  const detection = req.aiDetection;
  
  if (detection.isAI) {
    return res.json({ 
      agentDetected: true, 
      confidence: detection.confidence,
      score: detection.totalScore,
      data: 'AI-optimized response',
      details: detection.details
    });
  }
  
  // Suspicious but not confirmed AI - still serve but log
  if (detection.confidence === 'suspicious') {
    console.log(`[SUSPICIOUS] Potential AI agent detected:`, detection.details);
  }
  
  res.json({ 
    agentDetected: false, 
    confidence: detection.confidence,
    score: detection.totalScore,
    data: 'Human response' 
  });
});

// Endpoint to check detection status
app.get('/api/detection/status', (req, res) => {
  res.json({
    detected: req.isAgenticAI,
    confidence: req.aiConfidence,
    score: req.aiScore,
    details: req.aiDetection.details
  });
});

// Health check (bypass detection for monitoring)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

// ============================================================
// ERROR HANDLING
// ============================================================
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// ============================================================
// EXPORTS FOR TESTING
// ============================================================
module.exports = { 
  app, 
  detectFromHeaders, 
  verifySignature, 
  analyzeBehavior, 
  analyzeTLS,
  detectAgenticAI,
  generateChallenge,
  verifyChallenge,
  CONFIG,
  AI_PATTERNS,
  requestHistory
};
