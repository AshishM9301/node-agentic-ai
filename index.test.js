const request = require('supertest');
const express = require('express');

function isAgenticAI(req, res, next) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const aiAgent = req.headers['ai-agent'];
  
    const aiPatterns = [
      'perplexitybot', 'perplexity-user',
      'claude', 'claude-web', 'claude-browser',
      'chatgpt-user', 'chatgpt-atlas',
      'gptbot', 'anthropic-ai'
    ];
  
    const isAI = aiPatterns.some(pattern => userAgent.includes(pattern)) || aiAgent;
  
    req.isAgenticAI = !!isAI;
    req.aiDetails = isAI ? { userAgent, aiAgent } : null;
  
    next();
}
  
function createApp() {
  const app = express();
  app.use(express.json());
  app.use(isAgenticAI);
  
  app.get('/api/data', (req, res) => {
    if (req.isAgenticAI) {
      return res.json({ agentDetected: true, data: 'AI-optimized response', details: req.aiDetails });
    }
    res.json({ agentDetected: false, data: 'Human response' });
  });
  
  return app;
}

describe('Agentic AI Detection Middleware', () => {
  let app;

  beforeEach(() => {
    app = createApp();
  });

  describe('User-Agent based detection', () => {
    test('should detect PerplexityBot', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'PerplexityBot/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
      expect(res.body.details.userAgent).toContain('perplexitybot');
    });

    test('should detect perplexity-user', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'perplexity-user/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should detect Claude', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'ClaudeBot/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should detect Claude-Web', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'claude-web/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should detect Claude-Browser', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'claude-browser/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should detect ChatGPT-User', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'ChatGPT-User/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should detect ChatGPT-Atlas', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'ChatGPT-Atlas/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should detect GPTBot', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'GPTBot/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });

    test('should detect Anthropic-AI', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'Anthropic-AI/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });
  });

  describe('AI-Agent header detection', () => {
    test('should detect AI agent via ai-agent header', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('ai-agent', 'my-ai-agent');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
      expect(res.body.details.aiAgent).toBe('my-ai-agent');
    });

    test('should detect AI agent without user-agent header', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('ai-agent', 'custom-agent');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });
  });

  describe('Human detection', () => {
    test('should not detect AI for regular browser user-agent', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(false);
      expect(res.body.data).toBe('Human response');
    });

    test('should not detect AI when no headers provided', async () => {
      const res = await request(app)
        .get('/api/data');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(false);
    });

    test('should not detect AI for empty ai-agent header', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('ai-agent', '');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(false);
    });

    test('should not detect AI for non-matching user-agents', async () => {
      const userAgents = [
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
        'curl/7.68.0',
        'Python-urllib/3.9',
        'Wget/1.21'
      ];
      
      for (const ua of userAgents) {
        const res = await request(app)
          .get('/api/data')
          .set('User-Agent', ua);
        
        expect(res.status).toBe(200);
        expect(res.body.agentDetected).toBe(false);
      }
    });
  });

  describe('Case insensitivity', () => {
    test('should detect AI regardless of case in user-agent', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'CLAUDE-BOT/1.0');
      
      expect(res.status).toBe(200);
      expect(res.body.agentDetected).toBe(true);
    });
  });

  describe('Response content', () => {
    test('should return AI-optimized response for AI agents', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'ClaudeBot/1.0');
      
      expect(res.body.data).toBe('AI-optimized response');
    });

    test('should return human response for human users', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'Mozilla/5.0');
      
      expect(res.body.data).toBe('Human response');
    });

    test('should include details object for AI agents', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('User-Agent', 'PerplexityBot/1.0')
        .set('ai-agent', 'test-agent');
      
      expect(res.body.details).toBeDefined();
      expect(res.body.details.userAgent).toBeDefined();
      expect(res.body.details.aiAgent).toBe('test-agent');
    });
  });
});
