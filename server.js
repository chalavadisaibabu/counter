
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const dns = require('dns');

// Prefer IPv4 on networks where IPv6 connectivity is unreliable.
try {
  dns.setDefaultResultOrder('ipv4first');
} catch (_) {}

const app = express();

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ==================================================
// CONFIGURATION
// ==================================================

const PORT = Number(process.env.PORT || 3000);
const USER_DEFAULT = process.env.APP_USER || 'admin';
const PASS_DEFAULT = process.env.APP_PASS || 'admin123';

const API_KEY = (process.env.GEMINI_API_KEY || '').trim();
const MODEL = (process.env.GEMINI_MODEL || 'gemini-3.8-flash').trim();

const USERS_FILE = path.join(__dirname, 'users.json');
const IMG_DIR = path.join(__dirname, 'public', 'images');

const tokens = new Set();

let user;
let resetState = null;

// Cache successful results for six hours while the server runs.
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const nutritionCache = new Map();

function makeCacheKey(dishes) {
  return dishes
    .map(dish => dish.toLowerCase().replace(/\s+/g, ' ').trim())
    .join('|');
}

function getCachedAnalysis(dishes) {
  const key = makeCacheKey(dishes);
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

  nutritionCache.set(makeCacheKey(dishes), {
    savedAt: Date.now(),
    items
  });
}

// ==================================================
// PASSWORD HELPERS
// ==================================================

function hash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = crypto.scryptSync(password, salt, 32).toString('hex');

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

    return (
      calculatedHash.length === expectedHash.length &&
      crypto.timingSafeEqual(calculatedHash, expectedHash)
    );
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
      const smtpPort = Number(process.env.SMTP_PORT || 587);

      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });

      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: 'Cafeteria Display - Password Reset Code',
        text:
          `Your password reset code is ${code}. ` +
          'It is valid for 10 minutes. If you did not request this, ignore this email.'
      });

      console.log('Password reset email sent.');
      return;
    } catch (error) {
      console.error('Password reset email failed:', error.message);
    }
  }

  // Local-development fallback. Configure SMTP for production.
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
    message:
      'If the username is correct, a reset code has been sent. It is valid for 10 minutes.'
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
    return res.status(400).json({
      error: 'Wrong reset code'
    });
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
    const files = fs.readdirSync(IMG_DIR).filter(file =>
      /\.(jpe?g|png|webp)$/i.test(file)
    );

    return res.json({
      images: files.map(file => '/images/' + encodeURIComponent(file))
    });
  } catch (_) {
    return res.json({ images: [] });
  }
});

// ==================================================
// GEMINI CONNECTION HELPERS
// ==================================================

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function describeNetworkError(error) {
  const cause = error && error.cause;

  if (!cause) {
    return error ? error.message : 'Unknown network error';
  }

  const details = [
    cause.code ? `code=${cause.code}` : '',
    cause.message ? `cause=${cause.message}` : ''
  ].filter(Boolean).join(', ');

  return `${error.message}${details ? ` (${details})` : ''}`;
}

async function requestGemini(endpoint, options) {
  const retryableStatuses = new Set([429, 500, 502, 503, 504]);
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
        `Gemini network attempt ${attempt}/${maxAttempts} failed:`,
        describeNetworkError(error)
      );

      if (attempt < maxAttempts) {
        await wait(700);
        continue;
      }

      throw new Error(
        `Gemini network failure: ${describeNetworkError(error)}`
      );
    }

    if (
      response.ok ||
      !retryableStatuses.has(response.status) ||
      attempt === maxAttempts
    ) {
      return response;
    }

    console.warn(
      `Gemini returned HTTP ${response.status}. Retrying once.`
    );

    await wait(700);
  }

  throw new Error('Gemini request failed.');
}

// ==================================================
// GEMINI AI NUTRITION ANALYSIS
// ==================================================

app.post('/api/analyze', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();

  if (!token || !tokens.has(token)) {
    return res.status(401).json({
      error: 'Please login again'
    });
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

  // Fast response for a previously analysed list.
  const cachedItems = getCachedAnalysis(dishes);

  if (cachedItems) {
    console.log('Nutrition cache hit:', dishes.join(', '));
    return res.json({
      items: cachedItems,
      cached: true
    });
  }

  if (!API_KEY) {
    console.error('GEMINI_API_KEY is missing from .env.');

    return res.status(500).json({
      error: 'GEMINI_API_KEY is missing from the server environment.'
    });
  }

  const prompt = `
You are a nutrition assistant for a cafeteria menu.
Estimate nutrition for one typical serving of each dish:
${JSON.stringify(dishes)}

Return ONLY a valid JSON array with one object per dish, in the same order.
Each object must contain:
"name", "type", "serving_size", "calories", "protein_g",
"carbs_g", "fat_g", "fibre_g", "vitamins", "minerals", "allergens".

Rules:
- type must be exactly "veg", "non-veg", or "vegan".
- Vegan means no meat, fish, dairy, eggs, or honey.
- Veg may contain dairy or eggs. Non-veg contains meat or fish.
- Nutrition values must be numbers.
- serving_size must be a short string.
- Include at most 6 vitamins and 5 minerals.
- Mention common allergens when known.
- If uncertain, use ["Unknown - recipe dependent"].
- Values are estimates and vary by recipe and portion size.
- Do not claim food treats or prevents diseases.
- Return JSON only, without Markdown fences or extra text.
`;

  const endpoint =
    'https://generativelanguage.googleapis.com/v1beta/models/' +
    `${encodeURIComponent(MODEL)}:generateContent`;

  const requestOptions = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': API_KEY
    },
    body: JSON.stringify({
      contents: [{
        role: 'user',
        parts: [{ text: prompt }]
      }],
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: 0.2,
        maxOutputTokens: 2500
      }
    })
  };

  try {
    console.log(
      `Analysing ${dishes.length} dish(es) using Gemini model ${MODEL}.`
    );

    const response = await requestGemini(endpoint, requestOptions);
    const responseText = await response.text();

    let data;

    try {
      data = responseText ? JSON.parse(responseText) : {};
    } catch (_) {
      console.error(
        'Gemini returned an unreadable response:',
        responseText.slice(0, 500)
      );

      return res.status(502).json({
        error: 'Gemini returned an unreadable response. Please try again.'
      });
    }

    if (!response.ok) {
      const apiMessage = data?.error?.message ||
        `Gemini API returned HTTP ${response.status}`;

      console.error('Gemini API error:', response.status, apiMessage);

      if (response.status === 429) {
        return res.status(429).json({
          error: 'Gemini quota or rate limit reached. Wait before trying again.'
        });
      }

      if ([500, 502, 503, 504].includes(response.status)) {
        return res.status(503).json({
          error: 'Gemini is temporarily busy. Please try again shortly.'
        });
      }

      if ([401, 403].includes(response.status)) {
        return res.status(502).json({
          error: 'Gemini rejected the API key or access. Check your .env settings.'
        });
      }

      if (response.status === 404) {
        return res.status(502).json({
          error: `Gemini model "${MODEL}" was not found or is unavailable. Check GEMINI_MODEL.`
        });
      }

      return res.status(502).json({
        error: apiMessage
      });
    }

    const generatedText = (
      data.candidates?.[0]?.content?.parts || []
    )
      .map(part => part.text || '')
      .join('')
      .trim();

    if (!generatedText) {
      console.error(
        'Gemini returned no text. Finish reason:',
        data.candidates?.[0]?.finishReason || 'unknown'
      );

      return res.status(502).json({
        error: 'Gemini returned an empty response. Please try again.'
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
      console.error(
        'Gemini returned invalid JSON:',
        cleanedText.slice(0, 500)
      );

      return res.status(502).json({
        error: 'Gemini returned an invalid response. Please try again.'
      });
    }

    if (!Array.isArray(items)) {
      return res.status(502).json({
        error: 'Gemini returned an unexpected response format.'
      });
    }

    saveCachedAnalysis(dishes, items);

    return res.json({
      items,
      cached: false
    });

  } catch (error) {
    console.error(
      'Gemini connection error:',
      describeNetworkError(error)
    );

    const isTimeout =
      error.name === 'TimeoutError' ||
      error.name === 'AbortError' ||
      /timeout|timed out/i.test(error.message || '');

    return res.status(502).json({
      error: isTimeout
        ? 'Gemini took too long to respond. Check your internet connection and try again.'
        : 'Could not connect to Gemini. Check the VS Code terminal for the detailed network error.'
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
  console.log(`Gemini model configured: ${MODEL}`);

  if (!API_KEY) {
    console.warn('WARNING: GEMINI_API_KEY is missing from .env.');
  }
});
