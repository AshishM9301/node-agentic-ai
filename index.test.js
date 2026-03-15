const request = require('supertest');

// Import the new detection functions
const { 
  detectFromHeaders, 
  analyzeBehavior, 
  analyzeTLS,
  detectAgenticAI,
  generateChallenge,
  CONFIG,
  requestHistory
} = require('./index');

// Create a test app using the new middleware
function createApp() {
  const express = require('express');
  const app = express();
  app.use(express.json());
  app.use(detectAgenticAI);
  
  app.get('/api/data', (req, res) => {
    if (req.isAgenticAI) {
      return res.json({ 
        agentDetected: true, 
        confidence: req.aiConfidence,
        score: req.aiScore,
        data: 'AI-optimized response', 
        details: req.aiDetection.details 
      });
    }
    res.json({ 
      agentDetected: false, 
      confidence: req.aiConfidence,
      score: req.aiScore,
      data: 'Human response' 
    });
  });
  
  return app;
}

describe('Agentic AI Detection - Header Based', () => {
  let app;
  
  beforeEach(() => {
    app = createApp();
  });

  describe('detectFromHeaders function', () => {
    test('should detect PerplexityBot', () => {
      const mockReq = {
        headers: { 'user-agent': 'PerplexityBot/1.0' },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      expect(score.value).toBeGreaterThan(0);
      expect(score.details.some(d => d.type === 'user-agent')).toBe(true);
    });

    test('should detect Claude', () => {
      const mockReq = {
        headers: { 'user-agent': 'ClaudeBot/1.0' },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      expect(score.value).toBeGreaterThan(0);
    });

    test('should detect Claude-Web', () => {
      const mockReq = {
        headers: { 'user-agent': 'claude-web/1.0' },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      expect(score.value).toBeGreaterThan(0);
    });

    test('should detect ChatGPT-User', () => {
      const mockReq = {
        headers: { 'user-agent': 'ChatGPT-User/1.0' },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      expect(score.value).toBeGreaterThan(0);
    });

    test('should detect ChatGPT-Atlas', () => {
      const mockReq = {
        headers: { 'user-agent': 'ChatGPT-Atlas/1.0' },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      expect(score.value).toBeGreaterThan(0);
    });

    test('should detect GPTBot', () => {
      const mockReq = {
        headers: { 'user-agent': 'GPTBot/1.0' },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      expect(score.value).toBeGreaterThan(0);
    });

    test('should detect Anthropic-AI', () => {
      const mockReq = {
        headers: { 'user-agent': 'Anthropic-AI/1.0' },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      expect(score.value).toBeGreaterThan(0);
    });

    test('should detect via AI-Agent header', () => {
      const mockReq = {
        headers: { 'ai-agent': 'my-ai-agent' },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      // ai-agent header gives 0.5, and 'ai-agent' is not a user-agent pattern anymore
      expect(score.value).toBe(0.5);
    });

    test('should detect via Sec-AI-Agent header', () => {
      const mockReq = {
        headers: { 'sec-ai-agent': 'custom-agent' },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      // sec-ai-agent is treated as ai-agent, so should get 0.5
      expect(score.value).toBe(0.5);
    });

    test('should not detect for regular browser user-agent', () => {
      const mockReq = {
        headers: { 
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'sec-ch-ua': '"Chromium";v="120"',
          'accept-language': 'en-US,en;q=0.9'
        },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      expect(score.value).toBe(0);
    });

    test('should detect missing browser headers', () => {
      const mockReq = {
        headers: { 
          'user-agent': 'PerplexityBot/1.0'
          // Missing sec-ch-ua, accept-language, etc.
        },
        ip: '127.0.0.1'
      };
      const score = detectFromHeaders(mockReq);
      expect(score.details.some(d => d.type === 'missing-browser-headers')).toBe(true);
    });
  });

  describe('API endpoint detection', () => {
    beforeEach(() => {
      requestHistory.clear();
    });
    
    test('should detect PerplexityBot via API', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'PerplexityBot/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
      expect(res.body.confidence).toBeDefined();
    });

    test('should detect Claude via API', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'ClaudeBot/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should detect AI-Agent header via API', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('ai-agent', 'my-ai-agent');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should return Human for regular browser', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(false);
      expect(res.body.data).toBe('Human response');
    });

    test('should return Human when no headers provided', async () => {
      const res = await request(app)
        .get('/api/data');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(false);
    });

    test('should handle case insensitivity', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'CLAUDE-BOT/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should return AI-optimized response for AI agents', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'ClaudeBot/1.0');
      
      expect(res.body.data).toBe('AI-optimized response');
    });

    test('should return human response for humans', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'Mozilla/5.0');
      
      expect(res.body.data).toBe('Human response');
    });
  });

  describe('Behavioral Analysis', () => {
    test('analyzeBehavior should track request history', () => {
      const mockReq = { ip: 'test-behavior-' + Date.now() }; // Unique IP per test
      
      const score1 = analyzeBehavior(mockReq);
      const score2 = analyzeBehavior(mockReq);
      
      // Second request in quick succession should detect rapid-requests
      expect(score2.details.some(d => d.type === 'rapid-requests')).toBeTruthy();
    });
  });

  describe('TLS Analysis', () => {
    test('analyzeTLS should return score object', () => {
      const mockReq = {
        headers: { 'x-forwarded-proto': 'https' },
        httpVersion: '1.1'
      };
      
      const score = analyzeTLS(mockReq);
      expect(score.method).toBe('tls');
      expect(score.details).toBeDefined();
    });
  });

  describe('Proof of Work Challenge', () => {
    test('generateChallenge should create valid challenge', () => {
      const challenge = generateChallenge();
      
      expect(challenge.challenge).toContain('pow:');
      expect(challenge.nonce).toBeDefined();
      expect(challenge.difficulty).toBe(CONFIG.POW.DIFFICULTY);
    });
  });

  describe('Configuration', () => {
    test('CONFIG should have required thresholds', () => {
      expect(CONFIG.SCORE_THRESHOLD.SUSPICIOUS).toBeLessThan(CONFIG.SCORE_THRESHOLD.LIKELY_AI);
      expect(CONFIG.SCORE_THRESHOLD.LIKELY_AI).toBeLessThan(CONFIG.SCORE_THRESHOLD.CONFIRMED_AI);
    });

    test('CONFIG should have rate limit settings', () => {
      expect(CONFIG.RATE_LIMIT.WINDOW_MS).toBeGreaterThan(0);
      expect(CONFIG.RATE_LIMIT.MAX_REQUESTS).toBeGreaterThan(0);
    });
  });
});
