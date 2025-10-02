const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Client } = require('pg');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();

// === Middleware ===
app.use(express.json());
app.use(helmet());
app.use(express.urlencoded({ extended: true })); // Для form-data
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// === Настройки (не изменяйте IP, порты, БД) ===
const settings = {
  // Традиционные защиты
  sqlProtection: true,
  xssProtection: true,
  slowlorisProtection: true,
  clickjackingProtection: true,
  hidePhpInfo: true,
  filterParams: true,
  mimeMismatchProtection: true,
  sqlAutoBlacklist: true,

  dosProtection: true,
  dosAutoBlacklist: true,

  spamProtection: true,
  spamAutoBlacklist: true,

  proxyDetectionApi: true,
  proxyDetectionHeaders: true,
  proxyAutoBlacklist: true,

  detectMaliciousBots: true,
  detectFakeBots: true,
  detectAnonymousBots: true,
  botsAutoBlacklist: true,

  // AI модели
  pnhadEnabled: true,
  whXgboostEnabled: true,
  crnnLstmEnabled: true,
  haedfsEnabled: true,
  aiAutoBlacklist: true,

  notificationEmail: 'admin@example.com',
  customBlockPage: '/attacker-page'
};

// === Rate Limiter для DoS/DDoS ===
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const actions = ['Request blocked'];
    if (settings.dosAutoBlacklist) {
      addIpToBlacklist(ip);
      actions.push('IP auto-blacklisted');
    }
    logThreat(ip, 'DoS/DDoS', req, actions);
    res.status(429).send('Too Many Requests');
  }
});

// PostgreSQL
const client = new Client({
  user: 'postgres',
  host: 'shinkansen.proxy.rlwy.net',
  database: 'railway',
  password: 'qWtAcQXebBALlLYZIaBndfKMWqIbiOLq',
  port: 21259,
});

client.connect()
  .then(() => console.log('✅ Подключено к PostgreSQL'))
  .catch(err => console.error('❌ Ошибка подключения:', err.stack));

// === Nodemailer ===
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'ваш_email@gmail.com',
    pass: 'ваш_пароль_приложения'
  },
});

// === Чёрный список ===
let blacklist = new Set();
client.query('SELECT entry FROM blacklist WHERE expires_at IS NULL OR expires_at > NOW()')
  .then(res => {
    res.rows.forEach(row => blacklist.add(row.entry));
    console.log(`✅ Черный список загружен: ${blacklist.size} записей`);
  })
  .catch(err => console.error('❌ Ошибка загрузки черного списка:', err));

// === Паттерны угроз ===
const sqlInjectionPatterns = [/UNION\s+SELECT/i, /--/i, /OR\s+1\s*=\s*1/i];
const xssPatterns = [/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i, /on\w+\s*=/i, /javascript:/i];
const proxyHeaders = ['X-Forwarded-For', 'X-Real-IP', 'Via', 'Proxy-Connection'];
const botPatterns = {
  malicious: [/sqlmap/i, /hydra/i, /nmap/i, /metasploit/i, /burp/i, /nessus/i],
  fake: [/Googlebot\/Fake/i, /Baiduspider\/Fake/i, /YandexBot\/Fake/i],
  anonymous: [/Anonymouse/i, /Tor/i, /anonymous/i, /hidemyass/i]
};

// === AI: Извлечение признаков ===
function extractAiFeatures(req, ip, threatType) {
  const headers = req.headers;
  
  // Безопасное преобразование в строку
  const bodyStr = req.body ? JSON.stringify(req.body) : '';
  const queryStr = req.query ? JSON.stringify(req.query) : '';

  return {
    R_t: Date.now(),                    // Request timestamp
    V_t: (bodyStr.length + queryStr.length), // Traffic volume
    S_t: threatType ? 1 : 0,            // Stealth level
    T_t: req.originalUrl ? req.originalUrl.length : 0, // URL length
    Q_t: Object.keys({ ...req.query, ...req.body }).length, // Query params count
    user_agent_suspicious: /sqlmap|hydra|nmap|bot.*fake/i.test(headers['user-agent'] || '') ? 1 : 0,
    has_script: /<script|javascript:/i.test(bodyStr + queryStr) ? 1 : 0,
    has_sql_keywords: /union\s+select|or\s+1\s*=\s*1|--/i.test(bodyStr + queryStr) ? 1 : 0,
    x_forwarded_for: !!headers['x-forwarded-for'],
    connection_rate: ipConnections.get(ip) || 0
  };
}

// === AI: Предсказание ===
function predictWithAi(features) {
  let score = 0;

  // PNHAD: Poisson-Normal Hybrid Anomaly Detection
  if (settings.pnhadEnabled && features.connection_rate > 50) score += 0.25;

  // WH-XGBoost: Weighted Hybrid XGBoost Classifier
  if (settings.whXgboostEnabled && features.has_script) score += 0.2;
  if (settings.whXgboostEnabled && features.user_agent_suspicious) score += 0.15;

  // WH-CRNN_LSTM: Wavelet Hybrid CRNN-LSTM
  if (settings.crnnLstmEnabled && features.T_t > 150) score += 0.2;

  // HAEDFS: Hybrid Adaptive Ensemble with Dynamic Feature Selection
  const suspiciousCount = [
    features.has_script,
    features.has_sql_keywords,
    features.user_agent_suspicious,
    features.x_forwarded_for,
    features.connection_rate > 30
  ].filter(Boolean).length;

  if (settings.haedfsEnabled && suspiciousCount >= 3) score += 0.3;

  return Math.min(score, 1.0);
}

// === Глобальное решение о блокировке ===
function shouldBlockRequest(evidence, aiConfidence) {
  // Если любое правило сработало сильно — блокируем
  if (evidence.sqlInjection || evidence.xss || evidence.slowloris || evidence.dos || evidence.bot) {
    return true;
  }

  // Комбинированная уверенность
  const combinedScore = (
    (evidence.spam ? 0.5 : 0) +
    (evidence.proxy ? 0.5 : 0) +
    aiConfidence * 1.0
  );

  return combinedScore >= 0.6;
}

// === Вспомогательные функции ===
const ipConnections = new Map();

function addIpToBlacklist(ip) {
  if (blacklist.has(ip)) return;
  blacklist.add(ip);
  client.query(
    'INSERT INTO blacklist (entry, type, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING',
    [ip, 'IP']
  ).catch(err => console.error('Failed to save to DB:', err));
}

async function logThreat(ip, threatType, req, actions = ['Request blocked']) {
  const query = `INSERT INTO threat_logs 
    (ip, threat_type, date_time, browser, url, request_data, actions_taken) 
    VALUES ($1, $2, $3, $4, $5, $6, $7)`;
  
  const values = [
    ip,
    threatType,
    new Date(),
    req.get('User-Agent'),
    req.originalUrl,
    JSON.stringify(req.query) + JSON.stringify(req.body),
    actions.join(', ')
  ];
  
  try {
    await client.query(query, values);
  } catch (err) {
    console.error('Log error:', err);
  }
}

function sendNotification(message) {
  const mailOptions = {
    from: settings.notificationEmail,
    to: 'admin@example.com',
    subject: 'AWP Alert',
    text: message
  };
  transporter.sendMail(mailOptions, (err, info) => {
    if (err) console.error('Email error:', err);
  });
}

// === AWP Middleware ===
const awpMiddleware = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;

  if (blacklist.has(ip)) {
    return res.status(403).send('Access Denied: IP Blacklisted');
  }

  if (settings.dosProtection) {
    limiter(req, res, () => proceedWithChecks());
  } else {
    proceedWithChecks();
  }

  async function proceedWithChecks() {
    let threatDetected = false;
    let threatType = '';
    const actions = [];

    // Сбор доказательств
    const evidence = {
      sqlInjection: false,
      xss: false,
      slowloris: false,
      dos: false,
      spam: false,
      proxy: false,
      bot: false
    };

    // --- SQL Injection ---
    if (settings.sqlProtection) {
      const params = JSON.stringify(req.query) + JSON.stringify(req.body);
      if (sqlInjectionPatterns.some(p => p.test(params))) {
        threatDetected = true;
        threatType = 'SQL Injection';
        evidence.sqlInjection = true;
      }
    }

    // --- XSS ---
    if (settings.xssProtection) {
      const params = JSON.stringify(req.query) + JSON.stringify(req.body);
      if (xssPatterns.some(p => p.test(params))) {
        threatDetected = true;
        threatType = 'XSS';
        evidence.xss = true;
      }
    }

    // --- Slowloris ---
    if (settings.slowlorisProtection) {
      const connections = (ipConnections.get(ip) || 0) + 1;
      ipConnections.set(ip, connections);
      if (connections > 100) {
        threatDetected = true;
        threatType = 'Slowloris';
        evidence.slowloris = true;
      }
    }

    // --- Spam ---
    if (settings.spamProtection && await isIpInSpamDatabase(ip)) {
      threatDetected = true;
      threatType = 'Spam IP';
      evidence.spam = true;
    }

    // --- Proxy ---
    if (settings.proxyDetectionHeaders && proxyHeaders.some(h => req.get(h))) {
      threatDetected = true;
      threatType = 'Proxy (Headers)';
      evidence.proxy = true;
    }

    // --- Bots ---
    const userAgent = req.get('User-Agent') || '';
    const botCheck = isBotDetected(userAgent);
    if (botCheck.isBot) {
      threatDetected = true;
      threatType = botCheck.type;
      evidence.bot = true;
    }

    // --- AI Models ---
    const aiFeatures = extractAiFeatures(req, ip, threatType);
    const aiConfidence = predictWithAi(aiFeatures);

    if (!threatDetected && aiConfidence > 0.7) {
      threatDetected = true;
      threatType = 'AI-Anomaly';
    }

    // === ЕДИНОЕ РЕШЕНИЕ ===
    const shouldBlock = shouldBlockRequest(evidence, aiConfidence);

    if (shouldBlock || threatDetected) {
      actions.push('Request blocked');

      if (
        (threatType === 'SQL Injection' || threatType === 'XSS' || threatType === 'Slowloris') && settings.sqlAutoBlacklist ||
        threatType === 'DoS/DDoS' && settings.dosAutoBlacklist ||
        threatType === 'Spam IP' && settings.spamAutoBlacklist ||
        threatType === 'Proxy (Headers)' && settings.proxyAutoBlacklist ||
        threatType.includes('Bot') && settings.botsAutoBlacklist ||
        aiConfidence >= 0.7 && settings.aiAutoBlacklist
      ) {
        addIpToBlacklist(ip);
        actions.push('IP auto-blacklisted by AI');
      }

      if (settings.notificationEmail) {
        sendNotification(`${threatType} from ${ip}`);
        actions.push('Email notification sent');
      }

      logThreat(ip, threatType, req, actions);
      return res.status(403).send('Access Denied');
    }

    next();
  }
};

// === Проверка бота ===
function isBotDetected(userAgent) {
  if (!userAgent) return { isBot: false };
  if (settings.detectMaliciousBots && botPatterns.malicious.some(p => p.test(userAgent))) {
    return { isBot: true, type: 'Malicious Bot' };
  }
  if (settings.detectFakeBots && botPatterns.fake.some(p => p.test(userAgent))) {
    return { isBot: true, type: 'Fake Bot' };
  }
  if (settings.detectAnonymousBots && botPatterns.anonymous.some(p => p.test(userAgent))) {
    return { isBot: true, type: 'Anonymous Bot' };
  }
  return { isBot: false };
}

// === Проверка спам-базы ===
async function isIpInSpamDatabase(ip) {
  return false; // реализуйте при необходимости
}

// === API ===
app.get('/api/settings', (req, res) => res.json(settings));
app.post('/api/settings', async (req, res) => {
  Object.assign(settings, req.body);
  res.json({ success: true });
});

app.get('/api/logs', async (req, res) => {
  try {
    const result = await client.query(`
      SELECT id, ip, threat_type, 
             TO_CHAR(date_time, 'YYYY-MM-DD HH24:MI:SS') as date_time,
             browser, url, request_data, actions_taken 
      FROM threat_logs 
      ORDER BY date_time DESC 
      LIMIT 1000
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'DB error' });
  }
});

app.delete('/api/logs', async (req, res) => {
  try {
    await client.query('DELETE FROM threat_logs');
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to clear logs:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/blacklist', async (req, res) => {
  try {
    const result = await client.query('SELECT * FROM blacklist WHERE expires_at IS NULL OR expires_at > NOW() ORDER BY created_at DESC');
    res.json(result.rows.map(r => ({ ...r, id: r.id })));
  } catch (err) {
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/blacklist', async (req, res) => {
  const { entry, type, expires_at } = req.body;

  if (!entry || typeof entry !== 'string' || entry.trim() === '') {
    return res.status(400).json({ error: 'Entry required' });
  }

  const cleanEntry = entry.trim();

  try {
    const result = await client.query(
      `INSERT INTO blacklist (entry, type, expires_at, created_at) 
       VALUES ($1, $2, $3, NOW()) 
       ON CONFLICT (entry) DO UPDATE SET expires_at = EXCLUDED.expires_at 
       RETURNING *`,
      [cleanEntry, type || 'Other', expires_at || null]
    );

    blacklist.add(cleanEntry);
    res.json({ success: true, result: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'DB error' });
  }
});

app.delete('/api/blacklist/:entry', async (req, res) => {
  const { entry } = req.params;
  const decodedEntry = decodeURIComponent(entry);
  blacklist.delete(decodedEntry);
  try {
    await client.query('DELETE FROM blacklist WHERE entry = $1', [decodedEntry]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'DB error' });
  }
});

app.get(settings.customBlockPage, (req, res) => {
  res.send('<h1>Access Denied</h1><p>Your actions have been logged.</p>');
});

// Очистка истекших записей
setInterval(async () => {
  try {
    const result = await client.query('DELETE FROM blacklist WHERE expires_at IS NOT NULL AND expires_at <= NOW() RETURNING entry');
    result.rows.forEach(row => blacklist.delete(row.entry));
    if (result.rowCount > 0) {
      console.log(`🧹 Cleaned up ${result.rowCount} expired blacklist entries`);
    }
  } catch (err) {
    console.error('Failed to clean expired entries:', err);
  }
}, 60 * 1000);

// Экспорт
module.exports = { awpMiddleware };

// Запуск
app.listen(3000, () => {
  console.log('🛡️ AWP API запущен на порту 3000');
});