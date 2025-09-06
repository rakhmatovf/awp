const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Client } = require('pg');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();

// Middleware
app.use(helmet());
app.use(express.json());
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Настройки (с модульными autoBlacklist)
const settings = {
  // SQL/XSS
  sqlProtection: true,
  xssProtection: true,
  slowlorisProtection: true,
  clickjackingProtection: true,
  hidePhpInfo: true,
  filterParams: true,
  mimeMismatchProtection: true,
  sqlAutoBlacklist: true,
  
  // DoS/DDoS
  dosProtection: true,
  dosAutoBlacklist: true,
  
  // Spam
  spamProtection: true,
  spamAutoBlacklist: true,
  spamDatabaseUrls: [],
  
  // Proxy
  proxyDetectionApi: true,
  proxyDetectionHeaders: true,
  proxyDetectionPortScan: false,
  proxyAutoBlacklist: true,
  
  // Bots
  detectMaliciousBots: true,
  detectFakeBots: true,
  detectAnonymousBots: true,
  botsAutoBlacklist: true,
  
  // Общие
  notificationEmail: 'admin@example.com',
  customBlockPage: '/attacker-page'
};

// Rate limiter
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
    if (settings.notificationEmail) {
      sendNotification(`DoS/DDoS attack from ${ip}`);
      actions.push('Email notification sent');
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

// Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'ваш_email@gmail.com',
    pass: 'ваш_пароль_приложения'
  },
});

// Черный список
let blacklist = new Set();
client.query('SELECT * FROM blacklist WHERE expires_at IS NULL OR expires_at > NOW() ORDER BY created_at DESC')
  .then(res => {
    res.rows.forEach(row => {
      blacklist.add(row.entry);
      console.log('✅ Добавлено в Set:', row.entry);
    });
    console.log(`✅ Черный список загружен: ${blacklist.size} записей`);
  })
  .catch(err => {
    console.error('❌ Ошибка загрузки черного списка:', err);
  });

// Паттерны
const sqlInjectionPatterns = [/UNION\s+SELECT/i, /--/i, /OR\s+1\s*=\s*1/i];
const xssPatterns = [/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i, /on\w+\s*=/i, /javascript:/i];
const proxyHeaders = ['X-Forwarded-For', 'X-Real-IP', 'Via', 'Proxy-Connection'];
const botPatterns = {
  malicious: [/sqlmap/i, /hydra/i, /nmap/i, /metasploit/i, /burp/i, /nessus/i],
  fake: [/Googlebot\/Fake/i, /Baiduspider\/Fake/i, /YandexBot\/Fake/i],
  anonymous: [/Anonymouse/i, /Tor/i, /anonymous/i, /hidemyass/i]
};

// Проверка IP по спам-базам
async function isIpInSpamDatabase(ip) {
  if (!settings.spamProtection || settings.spamDatabaseUrls.length === 0) return false;
  for (const url of settings.spamDatabaseUrls) {
    try {
      const response = await fetch(url);
      const text = await response.text();
      if (text.split('\n').map(line => line.trim()).includes(ip)) {
        return true;
      }
    } catch (err) {
      console.error(`Failed to fetch spam DB: ${url}`, err);
    }
  }
  return false;
}

// Проверка бота по User-Agent
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

// Добавление в черный список
function addIpToBlacklist(ip) {
  if (blacklist.has(ip)) return;
  blacklist.add(ip);
  client.query(
    'INSERT INTO blacklist (entry, type, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING',
    [ip, 'IP']
  ).catch(err => console.error('Failed to save to DB:', err));
}

// Логирование с действиями
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

// Отправка уведомлений
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

// AWP Middleware
const awpMiddleware = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;

  if (blacklist.has(ip)) {
    return res.status(403).send('Access Denied: IP Blacklisted');
  }

  if (settings.dosProtection) {
    limiter(req, res, () => {
      proceedWithChecks();
    });
  } else {
    proceedWithChecks();
  }

  async function proceedWithChecks() {
    let threatDetected = false;
    let threatType = '';

    // SQL Injection
    if (settings.sqlProtection) {
      const params = JSON.stringify(req.query) + JSON.stringify(req.body);
      if (sqlInjectionPatterns.some(p => p.test(params))) {
        threatDetected = true;
        threatType = 'SQL Injection';
      }
    }

    // XSS
    if (settings.xssProtection) {
      const params = JSON.stringify(req.query) + JSON.stringify(req.body);
      if (xssPatterns.some(p => p.test(params))) {
        threatDetected = true;
        threatType = 'XSS';
      }
    }

    // Slowloris
    if (settings.slowlorisProtection) {
      const connections = (ipConnections.get(ip) || 0) + 1;
      ipConnections.set(ip, connections);
      if (connections > 100) {
        threatDetected = true;
        threatType = 'Slowloris';
      }
    }

    // Spam
    if (settings.spamProtection && await isIpInSpamDatabase(ip)) {
      threatDetected = true;
      threatType = 'Spam IP';
    }

    // Proxy
    if (settings.proxyDetectionHeaders && proxyHeaders.some(h => req.get(h))) {
      threatDetected = true;
      threatType = 'Proxy (Headers)';
    }

    // Bots
    const userAgent = req.get('User-Agent') || '';
    const botCheck = isBotDetected(userAgent);
    if (botCheck.isBot) {
      threatDetected = true;
      threatType = botCheck.type;
    }

    // Защита
    if (settings.clickjackingProtection) {
      res.setHeader('X-Frame-Options', 'DENY');
    }
    if (settings.hidePhpInfo) {
      res.removeHeader('X-Powered-By');
    }
    if (settings.mimeMismatchProtection) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
    }
    if (settings.filterParams) {
      const dangerous = ['cmd', 'exec', 'system'];
      const found = dangerous.some(d => Object.keys({ ...req.query, ...req.body }).some(k => k.includes(d)));
      if (found) {
        threatDetected = true;
        threatType = 'Malicious Param';
      }
    }

    if (threatDetected) {
      const actions = ['Request blocked'];

      if (
        (threatType === 'SQL Injection' || threatType === 'XSS' || threatType === 'Slowloris') && settings.sqlAutoBlacklist ||
        threatType === 'DoS/DDoS' && settings.dosAutoBlacklist ||
        threatType === 'Spam IP' && settings.spamAutoBlacklist ||
        threatType === 'Proxy (Headers)' && settings.proxyAutoBlacklist ||
        threatType.includes('Bot') && settings.botsAutoBlacklist
      ) {
        addIpToBlacklist(ip);
        actions.push('IP auto-blacklisted');
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

// Вспомогательные
const ipConnections = new Map();

// API
app.get('/api/settings', (req, res) => res.json(settings));
app.post('/api/settings', (req, res) => {
  const {
    sqlProtection, xssProtection, slowlorisProtection, clickjackingProtection,
    hidePhpInfo, filterParams, mimeMismatchProtection, sqlAutoBlacklist,
    dosProtection, dosAutoBlacklist,
    spamProtection, spamAutoBlacklist,
    proxyDetectionApi, proxyDetectionHeaders, proxyDetectionPortScan, proxyAutoBlacklist,
    detectMaliciousBots, detectFakeBots, detectAnonymousBots, botsAutoBlacklist,
    notificationEmail, customBlockPage, spamDatabaseUrls
  } = req.body;

  // SQL/XSS
  settings.sqlProtection = sqlProtection ?? settings.sqlProtection;
  settings.xssProtection = xssProtection ?? settings.xssProtection;
  settings.slowlorisProtection = slowlorisProtection ?? settings.slowlorisProtection;
  settings.clickjackingProtection = clickjackingProtection ?? settings.clickjackingProtection;
  settings.hidePhpInfo = hidePhpInfo ?? settings.hidePhpInfo;
  settings.filterParams = filterParams ?? settings.filterParams;
  settings.mimeMismatchProtection = mimeMismatchProtection ?? settings.mimeMismatchProtection;
  settings.sqlAutoBlacklist = sqlAutoBlacklist ?? settings.sqlAutoBlacklist;

  // DoS/DDoS
  settings.dosProtection = dosProtection ?? settings.dosProtection;
  settings.dosAutoBlacklist = dosAutoBlacklist ?? settings.dosAutoBlacklist;

  // Spam
  settings.spamProtection = spamProtection ?? settings.spamProtection;
  settings.spamAutoBlacklist = spamAutoBlacklist ?? settings.spamAutoBlacklist;
  settings.spamDatabaseUrls = Array.isArray(spamDatabaseUrls) ? spamDatabaseUrls : settings.spamDatabaseUrls;

  // Proxy
  settings.proxyDetectionApi = proxyDetectionApi ?? settings.proxyDetectionApi;
  settings.proxyDetectionHeaders = proxyDetectionHeaders ?? settings.proxyDetectionHeaders;
  settings.proxyDetectionPortScan = proxyDetectionPortScan ?? settings.proxyDetectionPortScan;
  settings.proxyAutoBlacklist = proxyAutoBlacklist ?? settings.proxyAutoBlacklist;

  // Bots
  settings.detectMaliciousBots = detectMaliciousBots ?? settings.detectMaliciousBots;
  settings.detectFakeBots = detectFakeBots ?? settings.detectFakeBots;
  settings.detectAnonymousBots = detectAnonymousBots ?? settings.detectAnonymousBots;
  settings.botsAutoBlacklist = botsAutoBlacklist ?? settings.botsAutoBlacklist;

  // Общие
  if (notificationEmail && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(notificationEmail)) {
    settings.notificationEmail = notificationEmail;
  }
  if (customBlockPage) settings.customBlockPage = customBlockPage;

  res.json({ success: true });
});

app.get('/api/logs', async (req, res) => {
  try {
    const result = await client.query(`
      SELECT id, ip, threat_type, date_time, browser, url, request_data, actions_taken 
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
  console.log('📥 [POST /api/blacklist] Получен запрос:', req.body);

  const { entry, type, expires_at } = req.body;

  if (!entry || typeof entry !== 'string' || entry.trim() === '') {
    console.log('❌ Ошибка: поле entry отсутствует или некорректно');
    return res.status(400).json({ 
      error: 'Entry required', 
      details: 'Поле "entry" обязательно и должно быть строкой' 
    });
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

    console.log('✅ Успешно добавлено в базу:', result.rows[0]);

    blacklist.add(cleanEntry);
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('❌ Ошибка при добавлении в базу данных:', err);
    res.status(500).json({ 
      error: 'DB error', 
      details: err.message,
      code: err.code
    });
  }
});

app.delete('/api/blacklist', async (req, res) => {
  try {
    await client.query('DELETE FROM blacklist');
    blacklist.clear();
    res.json({ success: true });
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
}, 60 * 1000); // Каждую минуту

// Экспорт
module.exports = { awpMiddleware };

// Запуск
app.listen(3000, () => {
  console.log('🛡️ AWP API запущен на порту 3000');
});