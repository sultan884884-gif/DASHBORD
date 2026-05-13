const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const axios = require('axios');
const fs = require('fs-extra');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'data.json');

// ══════════════════════════════════════════
// قاعدة البيانات (JSON)
// ══════════════════════════════════════════
async function loadDB() {
  try {
    return await fs.readJson(DB_PATH);
  } catch {
    const defaultDB = {
      panelChannel: '', logChannel: '', supportRole: '',
      adminRole: '', ticketCategory: '', allowUserClose: false,
      ticketCounter: 0, categories: [], openTickets: {}
    };
    await fs.writeJson(DB_PATH, defaultDB);
    return defaultDB;
  }
}

async function saveDB(data) {
  await fs.writeJson(DB_PATH, data, { spaces: 2 });
}

// ══════════════════════════════════════════
// Discord OAuth
// ══════════════════════════════════════════
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL || `http://localhost:${PORT}/auth/callback`,
  scope: ['identify', 'guilds']
}, (accessToken, refreshToken, profile, done) => {
  profile.accessToken = accessToken;
  return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'ticket-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

// ══════════════════════════════════════════
// Auth Routes
// ══════════════════════════════════════════
app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/callback', passport.authenticate('discord', {
  failureRedirect: '/'
}), (req, res) => res.redirect('/dashboard'));

app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.get('/api/me', (req, res) => {
  if (!req.isAuthenticated()) return res.json({ auth: false });
  res.json({ auth: true, user: { id: req.user.id, username: req.user.username, avatar: req.user.avatar } });
});

// ══════════════════════════════════════════
// Middleware - تحقق من الصلاحية
// ══════════════════════════════════════════
async function requireAdmin(req, res, next) {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'غير مسجل' });
  const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(s => s.trim());
  if (!ADMIN_IDS.includes(req.user.id)) return res.status(403).json({ error: 'ما عندك صلاحية' });
  next();
}

// ══════════════════════════════════════════
// API - الإعدادات
// ══════════════════════════════════════════
app.get('/api/settings', requireAdmin, async (req, res) => {
  const db = await loadDB();
  res.json(db);
});

app.post('/api/settings', requireAdmin, async (req, res) => {
  const db = await loadDB();
  const fields = ['panelChannel','logChannel','supportRole','adminRole','ticketCategory','allowUserClose'];
  for (const f of fields) {
    if (req.body[f] !== undefined) db[f] = req.body[f];
  }
  await saveDB(db);
  res.json({ success: true });
});

// ══════════════════════════════════════════
// API - الأقسام
// ══════════════════════════════════════════
app.get('/api/categories', requireAdmin, async (req, res) => {
  const db = await loadDB();
  res.json(db.categories);
});

app.post('/api/categories', requireAdmin, async (req, res) => {
  const db = await loadDB();
  const { name, emoji } = req.body;
  if (!name) return res.status(400).json({ error: 'الاسم مطلوب' });
  if (db.categories.find(c => c.name === name))
    return res.status(400).json({ error: 'القسم موجود' });
  db.categories.push({ id: Date.now().toString(), name, emoji: emoji || '🎫' });
  await saveDB(db);
  res.json({ success: true });
});

app.delete('/api/categories/:id', requireAdmin, async (req, res) => {
  const db = await loadDB();
  db.categories = db.categories.filter(c => c.id !== req.params.id);
  await saveDB(db);
  res.json({ success: true });
});

app.put('/api/categories/:id', requireAdmin, async (req, res) => {
  const db = await loadDB();
  const cat = db.categories.find(c => c.id === req.params.id);
  if (!cat) return res.status(404).json({ error: 'القسم غير موجود' });
  if (req.body.name) cat.name = req.body.name;
  if (req.body.emoji) cat.emoji = req.body.emoji;
  await saveDB(db);
  res.json({ success: true });
});

// ══════════════════════════════════════════
// API - التيكتات
// ══════════════════════════════════════════
app.get('/api/tickets', requireAdmin, async (req, res) => {
  const db = await loadDB();
  res.json(db.openTickets);
});

// ══════════════════════════════════════════
// API - معلومات السيرفر (قنوات ورتب)
// ══════════════════════════════════════════
app.get('/api/guild/:guildId/channels', requireAdmin, async (req, res) => {
  try {
    const r = await axios.get(`https://discord.com/api/v10/guilds/${req.params.guildId}/channels`, {
      headers: { Authorization: `Bot ${process.env.TICKET_TOKEN}` }
    });
    res.json(r.data);
  } catch { res.json([]); }
});

app.get('/api/guild/:guildId/roles', requireAdmin, async (req, res) => {
  try {
    const r = await axios.get(`https://discord.com/api/v10/guilds/${req.params.guildId}/roles`, {
      headers: { Authorization: `Bot ${process.env.TICKET_TOKEN}` }
    });
    res.json(r.data);
  } catch { res.json([]); }
});

// ══════════════════════════════════════════
// Pages
// ══════════════════════════════════════════
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(PORT, () => console.log(`Dashboard running on port ${PORT}`));
// استدعاء إرسال اللوحة عبر ملف مشترك
app.post('/api/send-panel', requireAdmin, async (req, res) => {
  try {
    const db = await loadDB();
    if (!db.panelChannel) return res.json({ error: 'قناة اللوحة غير محددة' });
    if (!db.categories || db.categories.length === 0) return res.json({ error: 'أضف أقسام أولاً' });
    await fs.writeJson(path.join(__dirname, 'send-panel-trigger.json'), { trigger: true, time: Date.now() });
    res.json({ success: true });
  } catch (e) {
    res.json({ error: e.message });
  }
});
