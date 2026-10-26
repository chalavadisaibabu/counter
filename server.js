
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ==================================================
// CONFIGURATION
// ==================================================

const PORT = Number(process.env.PORT || 3000);
const USER_DEFAULT = process.env.APP_USER || 'admin';
const PASS_DEFAULT = process.env.APP_PASS || 'admin123';

const API_KEY = (process.env.OPENAI_API_KEY || '').trim();
const MODEL = (process.env.OPENAI_MODEL || 'gpt-4.1-mini').trim();

const USERS_FILE = path.join(__dirname, 'users.json');
const IMG_DIR = path.join(__dirname, 'public', 'images');

const tokens = new Set();
let user;
let resetState = null;

// Successful nutrition results are cached for 6 hours.
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const nutritionCache = new Map();

// ==================================================
// CACHE HELPERS
// ==================================================

function cacheKeyForDishes(dishes) {
  return dishes
    .map(d => d.toLowerCase().replace(/\s+/g, ' ').trim())
    .join('|');
}

function getCachedAnalysis(dishes) {
  const key = cacheKeyForDishes(dishes);
  const entry = nutritionCache.get(key);

  if (!entry) return null;

  if (Date.now() - entry.savedAt > CACHE_TTL_MS) {
    nutritionCache.delete(key);
    return null;
  }

  return entry.items;
}

function saveCachedAnalysis(dishes, items) {
  if (nutritionCache.size >= 200) {
    const oldestKey = nutritionCache.keys().next().value;
    if (oldestKey) nutritionCache.delete(oldestKey);
  }

  nutritionCache.set(cacheKeyForDishes(dishes), {
    savedAt: Date.now(),
    items
  });
}

// ==================================================
// PASSWORD HELPERS
// ==================================================

function hash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = crypto
    .scryptSync(password, salt, 32)
    .toString('hex');

  return `${salt}:${passwordHash}`;
}

function verify(password, stored) {
  try {
    if (typeof stored !== 'string') return false;

    const parts = stored.split(':');
    if (parts.length !== 2) return false;

    const [salt, savedHash] = parts;

    if (!salt || !/^[a-f0-9]{64}$/i.test(savedHash)) {
      return false;
    }

    const calculatedHash = crypto.scryptSync(password, salt, 32);
    const expectedHash = Buffer.from(savedHash, 'hex');

    return calculatedHash.length === expectedHash.length &&
      crypto.timingSafeEqual(calculatedHash, expectedHash);
  } catch (_) {
    return false;
  }
}

// ==================================================
// USER STORAGE
// ==================================================

function saveUser() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(user, null, 2));
}

function loadUser() {
  if (fs.existsSync(USERS_FILE)) {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  }

  const initialUser = {
    username: USER_DEFAULT,
    password: hash(PASS_DEFAULT),
    email: process.env.ADMIN_EMAIL || ''
  };

  fs.writeFileSync(USERS_FILE, JSON.stringify(initialUser, null, 2));
  return initialUser;
}

try {
  user = loadUser();
} catch (error) {
  console.error('Could not load users.json:', error.message);
  process.exit(1);
}

// ==================================================
// PASSWORD RESET EMAIL
// ==================================================

async function sendCode(code) {
  if (
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS &&
    user.email
  ) {
    try {
      const nodemailer = require('nodemailer');
      const port = Number(process.env.SMTP_PORT || 587);

      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port,
        secure: port === 465,
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

      console.log('Password reset email sent.');
      return;
    } catch (error) {
      console.error('Password reset email failed:', error.message);
    }
  }

  // Development fallback only. Configure SMTP for production.
  console.log('PASSWORD RESET CODE:', code, '(valid for 10 minutes)');
}

// ==================================================
// LOGIN
// ==================================================

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};

  if (
    typeof username === 'string' &&
    typeof password === 'string' &&
    username === user.username &&
    verify(password, user.password)
  ) {
    const token = crypto.randomBytes(32).toString('hex');
    tokens.add(token);
    return res.json({ token });
  }

  return res.status(401).json({
    error: 'Invalid username or password'
  });
});

// ==================================================
// FORGOT PASSWORD
// ==================================================

app.post('/api/forgot', async (req, res) => {
  const { username } = req.body || {};

  if (typeof username === 'string' && username === user.username) {
    const code = String(crypto.randomInt(100000, 1000000));

    resetState = {
      code,
      expires: Date.now() + 10 * 60 * 1000,
      attempts: 0
    };

    await sendCode(code);
  }

  return res.json({
    message: 'If the username is correct, a reset code has been sent. It is valid for 10 minutes.'
  });
});

// ==================================================
// RESET PASSWORD
// ==================================================

app.post('/api/reset', (req, res) => {
  const { username, code, newPassword } = req.body || {};

  if (typeof newPassword !== 'string' || newPassword.length < 6) {
    return res.status(400).json({
      error: 'New password must be at least 6 characters'
    });
  }

  if (
    !resetState ||
    username !== user.username ||
    Date.now() > resetState.expires
  ) {
    resetState = null;
    return res.status(400).json({
      error: 'Invalid or expired code. Please request a new one.'
    });
  }

  resetState.attempts += 1;

  if (resetState.attempts > 5) {
    resetState = null;
    return res.status(429).json({
      error: 'Too many wrong attempts. Please request a new code.'
    });
  }

  if (typeof code !== 'string' || code.trim() !== resetState.code) {
    return res.status(400).json({ error: 'Wrong reset code' });
  }

  try {
    user.password = hash(newPassword);
    saveUser();

    resetState = null;
    tokens.clear();

    return res.json({
      message: 'Password updated. Please log in with your new password.'
    });
  } catch (error) {
    console.error('Password save failed:', error.message);
    return res.status(500).json({
      error: 'Could not save the new password.'
    });
  }
});

// ==================================================
// BACKGROUND FOOD IMAGES
// ==================================================

app.get('/api/bg-images', (req, res) => {
  try {
    const files = fs.readdirSync(IMG_DIR)
      .filter(file => /\.(jpe?g|png|webp)$/i.test(file));

    return res.json({
      images: files.map(file => '/images/' + encodeURIComponent(file))
    });
  } catch (_) {
    return res.json({ images: [] });
  }
});

// ==================================================
// OPENAI REQUEST HELPER
// ==================================================

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function requestOpenAI(endpoint, options) {
  const maxAttempts = 2;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let response;

    try {
      response = await fetch(endpoint, {
        ...options,
        signal: AbortSignal.timeout(60000)
      });
    } catch (error) {
      console.error(
        `OpenAI network attempt ${attempt}/${maxAttempts} failed:`,
        error.message
      );

      if (attempt < maxAttempts) {
        await wait(1500);
        continue;
      }

      throw error;
    }

    // Do not retry quota, authentication, or invalid-model errors.
    if (
      response.ok ||
      ![500, 502, 503, 504].includes(response.status) ||
      attempt === maxAttempts
    ) {
      return response;
    }

    console.warn(
      `OpenAI returned HTTP ${response.status}; retrying once after 2 seconds.`
    );

    await wait(2000);
  }

  throw new Error('OpenAI request failed.');
}

function extractOpenAIText(data) {
  if (typeof data.output_text === 'string' && data.output_text.trim()) {
    return data.output_text.trim();
  }

  const parts = [];

  for (const item of data.output || []) {
    if (item.type !== 'message') continue;

    for (const content of item.content || []) {
      if (
        content.type === 'output_text' &&
        typeof content.text === 'string'
      ) {
        parts.push(content.text);
      }
    }
  }

  return parts.join('\n').trim();
}

// ==================================================
// OPENAI NUTRITION ANALYSIS
// ==================================================

app.post('/api/analyze', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();

  if (!token || !tokens.has(token)) {
    return res.status(401).json({ error: 'Please login again' });
  }

  const inputDishes = Array.isArray(req.body?.dishes)
    ? req.body.dishes
    : [];

  const dishes = inputDishes
    .filter(dish => typeof dish === 'string')
    .map(dish => dish.trim().slice(0, 60))
    .filter(Boolean)
    .slice(0, 12);

  if (dishes.length === 0) {
    return res.status(400).json({
      error: 'Please provide at least one dish.'
    });
  }

  // Avoid paying for the same successful analysis repeatedly.
  const cachedItems = getCachedAnalysis(dishes);

  if (cachedItems) {
    console.log('Nutrition cache hit:', dishes.join(', '));
    return res.json({ items: cachedItems, cached: true });
  }

  if (!API_KEY) {
    console.error('OPENAI_API_KEY is missing from .env');

    return res.status(500).json({
      error: 'OPENAI_API_KEY is missing from the server environment.'
    });
  }

  const prompt = `
You are a nutrition assistant for a cafeteria smart food menu.

Analyze these dishes:
${JSON.stringify(dishes)}

Estimate nutrition for one typical serving of each dish.

Return ONLY a valid JSON array with exactly one object per dish,
in the same order as the input.

Each object must contain:
{
  "name": "dish name",
  "type": "veg",
  "serving_size": "200 g",
  "calories": 250,
  "protein_g": 10,
  "carbs_g": 30,
  "fat_g": 8,
  "fibre_g": 4,
  "vitamins": ["A", "B1", "C"],
  "minerals": ["Iron", "Calcium", "Potassium"],
  "allergens": ["Unknown - recipe dependent"]
}

Rules:
- type must be exactly "veg", "non-veg", or "vegan".
- Vegan means no meat, fish, dairy, eggs, or honey.
- Vegetarian food may contain dairy or eggs.
- Nutrition values must be numbers.
- serving_size must be a short string.
- Include no more than 6 vitamins and 5 minerals.
- Mention common allergens when known.
- If ingredients are uncertain, use ["Unknown - recipe dependent"].
- Values are estimates and vary with recipe and portion size.
- Do not claim food treats or prevents diseases.
- Return JSON only, without Markdown fences or extra text.
`;

  try {
    console.log(
      `Analysing ${dishes.length} dish(es) using OpenAI model ${MODEL}.`
    );

    const response = await requestOpenAI(
      'https://api.openai.com/v1/responses',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${API_KEY}`
        },
        body: JSON.stringify({
          model: MODEL,
          instructions: 'Return only a valid JSON array. Do not include Markdown fences.',
          input: prompt,
          max_output_tokens: 2500,
          store: false
        })
      }
    );

    const responseText = await response.text();

    let data;

    try {
      data = responseText ? JSON.parse(responseText) : {};
    } catch (_) {
      console.error('OpenAI returned an unreadable response.');

      return res.status(502).json({
        error: 'OpenAI returned an unreadable response. Please try again.'
      });
    }

    if (!response.ok) {
      const apiMessage =
        data?.error?.message ||
        `OpenAI API returned HTTP ${response.status}`;

      console.error('OpenAI API error:', response.status, apiMessage);

      if (response.status === 429) {
        return res.status(429).json({
          error: 'OpenAI API quota or rate limit reached. Check your API billing and usage limits.'
        });
      }

      if (response.status === 401 || response.status === 403) {
        return res.status(502).json({
          error: 'OpenAI rejected the API key or access. Check OPENAI_API_KEY and project permissions.'
        });
      }

      if (response.status === 404) {
        return res.status(502).json({
          error: `OpenAI model "${MODEL}" was not found or is unavailable. Check OPENAI_MODEL.`
        });
      }

      if ([500, 502, 503, 504].includes(response.status)) {
        return res.status(503).json({
          error: 'OpenAI is temporarily unavailable. Please try again later.'
        });
      }

      return res.status(502).json({ error: apiMessage });
    }

    const generatedText = extractOpenAIText(data);

    if (!generatedText) {
      console.error('OpenAI returned no text.');

      return res.status(502).json({
        error: 'OpenAI returned an empty response. Please try again.'
      });
    }

    const cleanedText = generatedText
      .replace(/^```(?:json)?\s*/i, '')
      .replace(/\s*```$/, '')
      .trim();

    let items;

    try {
      items = JSON.parse(cleanedText);
    } catch (_) {
      console.error('OpenAI returned invalid JSON:', cleanedText.slice(0, 300));

      return res.status(502).json({
        error: 'OpenAI returned an invalid response. Please try again.'
      });
    }

    if (!Array.isArray(items)) {
      return res.status(502).json({
        error: 'OpenAI returned an unexpected response format.'
      });
    }

    saveCachedAnalysis(dishes, items);

    return res.json({ items, cached: false });
  } catch (error) {
    console.error('OpenAI connection error:', error.message);

    const isTimeout = error && (
      error.name === 'TimeoutError' ||
      error.name === 'AbortError' ||
      /timed out|timeout/i.test(error.message || '')
    );

    return res.status(502).json({
      error: isTimeout
        ? 'OpenAI took too long to respond. Check your internet connection and try again.'
        : 'Could not connect to OpenAI. Check the VS Code terminal for details.'
    });
  }
});

// ==================================================
// HEALTH CHECK
// ==================================================

app.get('/api/health', (req, res) => {
  return res.json({ status: 'ok' });
});

// ==================================================
// START SERVER
// ==================================================

app.listen(PORT, () => {
  console.log(`Cafeteria application running on port ${PORT}`);
  console.log(`OpenAI model configured: ${MODEL}`);

  if (!API_KEY) {
    console.warn('WARNING: OPENAI_API_KEY is missing from .env');
  }
});
