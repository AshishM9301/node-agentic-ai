const express = require('express');
const app = express();
app.use(express.json());

function isAgenticAI(req, res, next) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const aiAgent = req.headers['ai-agent']; // Proposed standard[web:2]
  
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
  
  app.use(isAgenticAI);

  
  app.get('/api/data', (req, res) => {
    if (req.isAgenticAI) {
      return res.json({ agentDetected: true, data: 'AI-optimized response', details: req.aiDetails });
    }
    res.json({ agentDetected: false, data: 'Human response' });
  });
  

app.listen(3000, () => console.log('Server on port 3000'));
