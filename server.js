
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Redis } = require('@upstash/redis');

const app = express();

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, "public")));

/* ---------- CONFIGURATION ---------- */

const API_KEY = process.env.OPENAI_API_KEY;
const MODEL = process.env.MODEL || 'gpt-6-luna';

const COUNTERS = (
  process.env.COUNTERS ||
  "Two Good,Uttardakshin,Tandoor,Woker,Combo,Chef's Library,Tripet"
).split(',').map(s => s.trim()).filter(Boolean);

const COUNTER_PASS = process.env.COUNTER_PASS || 'Bms@2026';
const ADMIN_USER = process.env.APP_USER || 'admin';
const ADMIN_PASS = process.env.APP_PASS;

const IMG_DIR = path.join(__dirname, 'public', 'images');

/* ---------- HELPERS ---------- */

const sha = value =>
  crypto.createHash('sha256').update(value).digest('hex');

const norm = value =>
  String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');

function hash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' +
    crypto.scryptSync(String(password), salt, 32).toString('hex');
}

function verify(password, stored) {
  try {
    if (!stored || typeof stored !== 'string') return false;

    const [salt, hex] = stored.split(':');
    if (!salt || !hex) return false;

    const actual = crypto.scryptSync(String(password), salt, 32);
    const expected = Buffer.from(hex, 'hex');

    return actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

const h = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(error => {
    console.error('Server error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

/* ---------- STORAGE: UPSTASH REDIS ---------- */

const REDIS_URL =
  process.env.KV_REST_API_URL ||
  process.env.UPSTASH_REDIS_REST_URL;

const REDIS_TOKEN =
  process.env.KV_REST_API_TOKEN ||
  process.env.UPSTASH_REDIS_REST_TOKEN;

let db;

if (REDIS_URL && REDIS_TOKEN) {
  const redis = new Redis({
    url: REDIS_URL,
    token: REDIS_TOKEN
  });

  db = {
    get: key => redis.get(key),

    set: (key, value, seconds) =>
      seconds
        ? redis.set(key, value, { ex: seconds })
        : redis.set(key, value),

    del: key => redis.del(key)
  };

  console.log('Upstash Redis storage enabled.');
} else {
  // Local testing only. Memory is cleared when the server restarts.
  console.warn(
    'Redis environment variables missing. Using temporary memory storage.'
  );

  const memory = new Map();

  db = {
    async get(key) {
      const entry = memory.get(key);

      if (!entry) return null;

      if (entry.expires && entry.expires <= Date.now()) {
        memory.delete(key);
        return null;
      }

      return JSON.parse(entry.value);
    },

    async set(key, value, seconds) {
      memory.set(key, {
        value: JSON.stringify(value),
        expires: seconds ? Date.now() + seconds * 1000 : 0
      });
    },

    async del(key) {
      memory.delete(key);
    }
  };
}

/* ---------- USERS ---------- */

let seeding;

async function ensureUsers() {
  if (!seeding) {
    seeding = (async () => {
      const data = (await db.get('users')) || { users: [] };
      let changed = false;

      if (!Array.isArray(data.users)) {
        data.users = [];
        changed = true;
      }

      function addUser(username, password, name, counters) {
        if (!data.users.some(
          user => norm(user.username) === norm(username)
        )) {
          data.users.push({
            username,
            password: hash(password),
            name,
            email: '',
            counters
          });

          changed = true;
        }
      }

      // Create admin only when APP_PASS is configured.
      if (ADMIN_PASS) {
        addUser(ADMIN_USER, ADMIN_PASS, 'Admin', 'all');
      }

      // Each counter gets its own login.
      COUNTERS.forEach(counter => {
        addUser(norm(counter), COUNTER_PASS, counter, [counter]);
      });

      if (changed) {
        await db.set('users', data);
      }
    })().catch(error => {
      seeding = null;
      throw error;
    });
  }

  return seeding;
}

async function getUsers() {
  await ensureUsers();
  return (await db.get('users')) || { users: [] };
}

function canUse(user, counter) {
  return user.counters === 'all' ||
    (Array.isArray(user.counters) &&
      user.counters.includes(counter));
}

/* ---------- AUTHENTICATION ---------- */

const auth = h(async (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ')
    ? header.slice(7).trim()
    : '';

  if (!token) {
    return res.status(401).json({
      error: 'Please login again'
    });
  }

  const sessionKey = 'sess:' + sha(token);
  const session = await db.get(sessionKey);

  if (!session) {
    return res.status(401).json({
      error: 'Please login again'
    });
  }

  // Invalidate sessions after the user's password is reset.
  const version = (await db.get('ver:' + session.username)) || 0;

  if (String(version) !== String(session.ver || 0)) {
    await db.del(sessionKey);

    return res.status(401).json({
      error: 'Please login again'
    });
  }

  req.session = session;
  req.sessKey = sessionKey;

  next();
});

/* ---------- PASSWORD RESET EMAIL ---------- */

async function sendCode(user, code) {
  if (process.env.SMTP_HOST && user.email) {
    try {
      const nodemailer = require('nodemailer');

      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: Number(process.env.SMTP_PORT || 587) === 465,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });

      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: 'Cafeteria Display - Password Reset Code',
        text: `Your password reset code is ${code}. It is valid for 10 minutes.`
      });

      return;
    } catch (error) {
      console.error('Email failed:', error.message);
    }
  }

  // For local testing, check the server terminal.
  console.log(
    `PASSWORD RESET CODE for ${user.username}: ${code} (valid for 10 minutes)`
  );
}

/* ---------- COUNTERS ---------- */

app.get('/api/counters', (req, res) => {
  res.json({ counters: COUNTERS });
});

/* ---------- LOGIN ---------- */

app.post('/api/login', h(async (req, res) => {
  const { username, password, counter, remember } = req.body || {};

  const data = await getUsers();

  const user = data.users.find(
    item => norm(item.username) === norm(username)
  );

  if (!user || !password || !verify(password, user.password)) {
    return res.status(401).json({
      error: 'Invalid username or password'
    });
  }

  if (!COUNTERS.includes(counter)) {
    return res.status(400).json({
      error: 'Please select a counter'
    });
  }

  if (!canUse(user, counter)) {
    return res.status(403).json({
      error: `This login does not have access to ${counter}`
    });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const version = (await db.get('ver:' + user.username)) || 0;

  const session = {
    username: user.username,
    name: user.name || user.username,
    counter,
    ver: version
  };

  // Remembered sessions last 90 days; others last 12 hours.
  const sessionSeconds = remember ? 90 * 86400 : 12 * 3600;

  await db.set(
    'sess:' + sha(token),
    session,
    sessionSeconds
  );

  res.json({
    token,
    name: session.name,
    counter
  });
}));

/* ---------- LOGOUT ---------- */

app.post('/api/logout', auth, h(async (req, res) => {
  await db.del(req.sessKey);
  res.json({ ok: true });
}));

/* ---------- FORGOT PASSWORD ---------- */

app.post('/api/forgot', h(async (req, res) => {
  const username = (req.body || {}).username;
  const data = await getUsers();

  const user = data.users.find(
    item => norm(item.username) === norm(username)
  );

  if (user) {
    const code = String(crypto.randomInt(100000, 1000000));

    await db.set(
      'reset:' + user.username,
      {
        code,
        attempts: 0,
        expires: Date.now() + 10 * 60 * 1000
      },
      600
    );

    await sendCode(user, code);
  }

  res.json({
    message: 'If the username is correct, a 6-digit reset code has been sent. It is valid for 10 minutes.'
  });
}));

/* ---------- RESET PASSWORD ---------- */

app.post('/api/reset', h(async (req, res) => {
  const { username, code, newPassword } = req.body || {};

  if (!newPassword || String(newPassword).length < 6) {
    return res.status(400).json({
      error: 'New password must be at least 6 characters'
    });
  }

  const data = await getUsers();

  const user = data.users.find(
    item => norm(item.username) === norm(username)
  );

  const key = user ? 'reset:' + user.username : '';
  const reset = user ? await db.get(key) : null;

  if (!user || !reset || Date.now() > reset.expires) {
    return res.status(400).json({
      error: 'Invalid or expired code. Please request a new one.'
    });
  }

  reset.attempts++;

  if (reset.attempts > 5) {
    await db.del(key);

    return res.status(429).json({
      error: 'Too many incorrect attempts. Request a new code.'
    });
  }

  if (String(code || '').trim() !== reset.code) {
    await db.set(key, reset, 600);

    return res.status(400).json({
      error: 'Wrong reset code'
    });
  }

  user.password = hash(String(newPassword));

  await db.set('users', data);
  await db.del(key);

  // Log out all previous sessions for this user.
  await db.set('ver:' + user.username, Date.now());

  res.json({
    message: 'Password updated. Please login with your new password.'
  });
}));

/* ---------- BACKGROUND IMAGES ---------- */

app.get('/api/bg-images', (req, res) => {
  let files = [];

  try {
    files = require('fs').readdirSync(IMG_DIR).filter(
      file => /\.(jpe?g|png|webp)$/i.test(file)
    );
  } catch {
    // Images folder may not exist yet.
  }

  res.json({
    images: files.map(
      file => '/images/' + encodeURIComponent(file)
    )
  });
});

/* ---------- GET SAVED MENU ---------- */

app.get('/api/menu', auth, h(async (req, res) => {
  const menu = await db.get('menu:' + req.session.counter);

  res.json(menu || { items: [] });
}));

/* ---------- OPENAI NUTRITION ANALYSIS ---------- */

app.post('/api/analyze', auth, h(async (req, res) => {
  const dishes = Array.isArray(req.body?.dishes)
    ? req.body.dishes
        .map(dish => String(dish).trim().slice(0, 60))
        .filter(Boolean)
        .slice(0, 8)
    : [];

  if (!dishes.length) {
    return res.status(400).json({
      error: 'No dishes provided'
    });
  }

  if (!API_KEY) {
    return res.status(500).json({
      error: 'OPENAI_API_KEY is not configured in the environment.'
    });
  }

  const prompt = `
You are a nutrition assistant for a cafeteria Smart Food Menu display.

Estimate nutrition values for one typical serving of each dish.
Dishes: ${JSON.stringify(dishes)}

Return a JSON object containing an "items" array.
Include one object per dish, in the same order.

Each item must contain:
{
  "available": true,
  "name": "Properly capitalized dish name",
  "type": "veg, non-veg, or vegan",
  "serving_size": "e.g. 200 g",
  "calories": 250,
  "protein_g": 10,
  "carbs_g": 30,
  "fat_g": 8,
  "fibre_g": 4,
  "vitamins": ["A", "B1", "C"],
  "minerals": ["Iron", "Calcium", "Potassium"],
  "allergens": ["Milk (Dairy)"]
}

For a dish you cannot confidently identify, return {"available":false,"name":"Original dish name"} instead of guessing nutrition.

Rules:
- Include one item per input dish, in the same order.
- Set available to true only when you can identify the dish and estimate its nutrition reliably.
- Set available to false for unknown, invalid, or ambiguous dish names; do not invent nutrition values.
- Nutrition figures are estimates for a typical serving.
- Use numeric values for calories, protein_g, carbs_g, fat_g, and fibre_g.
- Use vegan only if the dish normally contains no dairy, egg, honey, or meat.
- Use veg for vegetarian dishes, including those with dairy or eggs.
- Use non-veg for dishes containing meat or seafood.
- Include at most 6 vitamins and 5 minerals.
- If there is no common allergen to report, use ["None known"].
- Mention when allergens depend on the recipe.
- Return valid JSON only.
`;

  try {
    const response = await fetch(
      'https://api.openai.com/v1/responses',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${API_KEY}`
        },
        body: JSON.stringify({
          model: MODEL,
          instructions:
            'Follow the nutrition instructions and return a valid JSON object with an items array.',
          input: prompt,
          max_output_tokens: 3000,
          text: {
            format: {
              type: 'json_object'
            }
          },
          store: false
        }),
        signal: AbortSignal.timeout(60000)
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error('OpenAI API error:', data);

      return res.status(502).json({
        error: data.error?.message || 'OpenAI API request failed'
      });
    }

    const outputText = (data.output || [])
      .filter(item => item.type === 'message')
      .flatMap(item => item.content || [])
      .filter(item => item.type === 'output_text')
      .map(item => item.text || '')
      .join('')
      .trim();

    if (!outputText) {
      console.error('OpenAI returned no text:', JSON.stringify(data));

      return res.status(502).json({
        error: 'The AI returned an empty response. Please try again.'
      });
    }

    let result;

    try {
      result = JSON.parse(outputText);
    } catch {
      return res.status(502).json({
        error: 'The AI returned unreadable JSON. Please try again.'
      });
    }

    if (!result || !Array.isArray(result.items)) {
      return res.status(502).json({
        error: 'The AI response is missing the items array.'
      });
    }

    const items = dishes.map((dish, index) => {
      const item = result.items[index];

      return item?.available === true
        ? { ...item, name: item.name || dish, available: true }
        : { name: dish, available: false };
    });

    // Save this menu separately for the logged-in counter.
    await db.set('menu:' + req.session.counter, {
      items,
      updatedAt: new Date().toISOString(),
      by: req.session.name
    });

    res.json({ items });

  } catch (error) {
    console.error('Nutrition analysis error:', error);

    if (
      error.name === 'TimeoutError' ||
      error.name === 'AbortError'
    ) {
      return res.status(504).json({
        error: 'The AI request timed out. Please try again.'
      });
    }

    res.status(500).json({
      error: 'Could not get AI response: ' + error.message
    });
  }
}));

/* ---------- HEALTH CHECK ---------- */

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    message: 'Cafeteria Display server is running',
    model: MODEL,
    counters: COUNTERS
  });
});

/* ---------- VERCEL AND LOCAL START ---------- */

// Vercel imports this app.
module.exports = app;

// Local testing: npm start
if (require.main === module) {
  const PORT = process.env.PORT || 3000;

  app.listen(PORT, () => {
    console.log(`Running on http://localhost:${PORT}`);
    console.log('Model:', MODEL);
    console.log('Counters:', COUNTERS.join(', '));
  });
}
