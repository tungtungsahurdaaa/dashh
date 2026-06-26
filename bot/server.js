require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const {
  Client,
  GatewayIntentBits,
  Partials,
  PermissionsBitField,
  GuildMember,
} = require('discord.js');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const TOKEN = process.env.DISCORD_TOKEN;
const GUILD_ID = process.env.GUILD_ID;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'NexusVangaurdStaff';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'N3xus@Vang@urd_';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-secret-change-me';
const PORT = process.env.PORT || 3000;

const allowedOrigin = process.env.DASHBOARD_ORIGIN || '*';

if (!TOKEN || !GUILD_ID) {
  console.error('Missing DISCORD_TOKEN or GUILD_ID in environment. Set them in Render env vars (or .env locally).');
}

// ---------------------------------------------------------------------------
// Discord client
// ---------------------------------------------------------------------------
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildPresences,
    GatewayIntentBits.GuildVoiceStates,
  ],
  partials: [Partials.GuildMember, Partials.User],
});

client.once('ready', () => {
  console.log(`[DISCORD] Logged in as ${client.user.tag}`);
});
client.on('error', (e) => console.error('[DISCORD ERROR]', e.message));

// Don't crash the process if the token is missing yet — let the API report it.
client.login(TOKEN).catch((e) => console.error('[DISCORD LOGIN FAILED]', e.message));

// Helper: wait until the guild is cached
async function getGuild() {
  if (!client.isReady()) throw new Error('Bot is not ready yet. Wait a few seconds and retry.');
  const guild = client.guilds.cache.get(GUILD_ID) || (await client.guilds.fetch(GUILD_ID));
  if (!guild) throw new Error('Guild not found. Check GUILD_ID and that the bot was invited to the server.');
  // Make sure members are fetched (works for small/medium servers; large servers need GUILD_MEMBERS intent + privileged)
  try {
    await guild.members.fetch({ withPresences: true });
  } catch (_) {
    await guild.members.fetch();
  }
  return guild;
}

// ---------------------------------------------------------------------------
// Auth (stateless HMAC token, no external deps)
// ---------------------------------------------------------------------------
function makeToken(username) {
  const expiresAt = Date.now() + 1000 * 60 * 60 * 8; // 8 hours
  const payload = `${username}.${expiresAt}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [username, expiresAt, sig] = parts;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(`${username}.${expiresAt}`).digest('hex');
  // constant-time compare
  if (sig.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  const exp = Number(expiresAt);
  if (!exp || Date.now() > exp) return false;
  return username;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;
  const user = verifyToken(token);
  if (!user) return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  req.adminUser = user;
  next();
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use(
  cors({
    origin: allowedOrigin === '*' ? true : allowedOrigin.split(',').map((s) => s.trim()),
  })
);

// Health check (no auth) — useful for Render + dashboard connection test
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    botReady: client.isReady(),
    botUser: client.isReady() ? client.user.tag : null,
    time: new Date().toISOString(),
  });
});

// Root status page so visiting the Render URL directly isn't a "Cannot GET /" error.
app.get('/', (req, res) => {
  const ready = client.isReady();
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>NVG Bot API</title>
<style>body{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#070913;color:#fff;margin:0;padding:40px;line-height:1.6}
.box{max-width:560px;margin:auto;background:rgba(10,13,28,.6);border:1px solid rgba(88,101,242,.15);border-radius:8px;padding:30px}
h1{color:#5865F2;font-family:Orbitron,sans-serif;letter-spacing:1px;margin-top:0}
code{background:rgba(7,9,19,.8);padding:2px 6px;border-radius:4px;color:#f1c40f}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:8px}
.ok{background:#2ecc71}.bad{background:#e74c3c}
a{color:#5865F2}</style></head>
<body><div class="box">
<h1>Nexus Vanguard — Bot API</h1>
<p><span class="dot ${ready ? 'ok' : 'bad'}"></span> Bot: <strong>${ready ? 'online' : 'starting…'}</strong></p>
<p>Bot user: <code>${ready ? client.user.tag : '—'}</code></p>
<p>This is the backend for the NVG dashboard. It is running correctly.</p>
<p>Endpoints:</p>
<ul>
<li><code>GET /api/health</code></li>
<li><code>POST /api/login</code></li>
<li><code>GET /api/stats</code> · <code>/api/members</code> · <code>/api/voice</code></li>
<li><code>POST /api/moderate</code> · <code>/api/voice-control</code></li>
</ul>
<p>The dashboard itself lives on GitHub Pages and talks to this API.</p>
</div></body></html>`);
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    return res.json({ token: makeToken(username), username });
  }
  return res.status(401).json({ error: 'Invalid credentials.' });
});

// Verify a saved token (used by dashboard on load)
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ username: req.adminUser });
});

// Live stats
app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const guild = await getGuild();
    let online = 0,
      offline = 0,
      dnd = 0,
      idle = 0;
    let voiceCount = 0;
    for (const m of guild.members.cache.values()) {
      if (m.user.bot) continue;
      const s = m.presence?.status;
      if (s === 'online') online++;
      else if (s === 'idle') idle++;
      else if (s === 'dnd') dnd++;
      else offline++;
    }
    for (const vc of guild.channels.cache.values()) {
      if (vc.isVoiceBased?.() && vc.members && vc.members.size > 0) {
        voiceCount += vc.members.size;
      }
    }
    res.json({
      online,
      offline,
      idle,
      dnd,
      total: guild.memberCount,
      voice: voiceCount,
    });
  } catch (e) {
    console.error('[/api/stats]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// All members (with status + voice info) — for the member list / dropdown
app.get('/api/members', authMiddleware, async (req, res) => {
  try {
    const guild = await getGuild();
    const list = [];
    for (const m of guild.members.cache.values()) {
      if (m.user.bot) continue;
      const vs = m.voice;
      list.push({
        id: m.id,
        username: m.user.username,
        displayName: m.displayName,
        avatar: m.user.displayAvatarURL({ size: 64 }),
        status: m.presence?.status || 'offline',
        activities: (m.presence?.activities || []).map((a) => ({ type: a.type, name: a.name })),
        inVoice: !!(vs && vs.channelId),
        voiceChannelId: vs?.channelId || null,
        voiceChannelName: vs?.channel?.name || null,
        serverMute: !!vs?.serverMute,
        serverDeaf: !!vs?.serverDeaf,
        selfMute: !!vs?.selfMute,
        selfDeaf: !!vs?.selfDeaf,
      });
    }
    list.sort((a, b) => {
      const rank = (s) => (s === 'online' ? 0 : s === 'idle' ? 1 : s === 'dnd' ? 2 : 3);
      if (rank(a.status) !== rank(b.status)) return rank(a.status) - rank(b.status);
      if (a.inVoice !== b.inVoice) return a.inVoice ? -1 : 1;
      return a.username.localeCompare(b.username);
    });
    res.json({ members: list });
  } catch (e) {
    console.error('[/api/members]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Voice channels + who is in them
app.get('/api/voice', authMiddleware, async (req, res) => {
  try {
    const guild = await getGuild();
    const channels = [];
    for (const vc of guild.channels.cache.values()) {
      if (!vc.isVoiceBased?.()) continue;
      const members = [];
      if (vc.members) {
        for (const m of vc.members.values()) {
          members.push({
            id: m.id,
            username: m.user.username,
            displayName: m.displayName,
            avatar: m.user.displayAvatarURL({ size: 64 }),
            serverMute: !!m.voice?.serverMute,
            serverDeaf: !!m.voice?.serverDeaf,
            selfMute: !!m.voice?.selfMute,
            selfDeaf: !!m.voice?.selfDeaf,
          });
        }
      }
      if (members.length > 0) {
        channels.push({
          id: vc.id,
          name: vc.name,
          memberCount: members.length,
          members,
        });
      }
    }
    channels.sort((a, b) => a.name.localeCompare(b.name));
    res.json({ channels, totalInVoice: channels.reduce((s, c) => s + c.memberCount, 0) });
  } catch (e) {
    console.error('[/api/voice]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Moderation: ban / kick / timeout (text-mute)
// body: { userId, action: 'ban'|'kick'|'timeout', durationMinutes?, reason? }
// ---------------------------------------------------------------------------
app.post('/api/moderate', authMiddleware, async (req, res) => {
  const { userId, action, durationMinutes, reason } = req.body || {};
  if (!userId || !action) return res.status(400).json({ error: 'userId and action are required.' });

  try {
    const guild = await getGuild();
    let member;
    try {
      member = await guild.members.fetch(userId);
    } catch (_) {
      // For ban we can still target a user id even if not cached, but kick/timeout need a member.
      member = null;
    }

    const auditReason = `[NVG Dashboard] by ${req.adminUser}${reason ? ` — ${reason}` : ''}`;

    switch (action) {
      case 'ban': {
        const days = Math.min(7, Math.max(0, Number(req.body.deleteMessageDays) || 0));
        await guild.bans.create(userId, { deleteMessageSeconds: days * 86400, reason: auditReason });
        return res.json({ ok: true, action: 'ban', userId });
      }
      case 'kick': {
        if (!member) return res.status(400).json({ error: 'User is not currently in the server; cannot kick.' });
        await member.kick(auditReason);
        return res.json({ ok: true, action: 'kick', userId });
      }
      case 'timeout':
      case 'mute': {
        // text mute = Discord timeout. durationMinutes required; 0 unmutes.
        if (!member) return res.status(400).json({ error: 'User is not currently in the server; cannot timeout.' });
        const mins = Number(durationMinutes) || 0;
        if (mins <= 0) {
          await member.timeout(null, auditReason + ' (cleared)');
        } else {
          const until = new Date(Date.now() + mins * 60 * 1000);
          await member.timeout(until, auditReason);
        }
        return res.json({ ok: true, action: 'timeout', userId, until: mins > 0 ? new Date(Date.now() + mins * 60 * 1000).toISOString() : null });
      }
      case 'untimeout':
      case 'unmute': {
        if (!member) return res.status(400).json({ error: 'User is not currently in the server.' });
        await member.timeout(null, auditReason);
        return res.json({ ok: true, action: 'untimeout', userId });
      }
      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  } catch (e) {
    console.error('[/api/moderate]', e.message);
    // discord.js puts a code on permission errors
    if (e.code === 50013) return res.status(403).json({ error: 'Bot lacks permission to do that on this user (role hierarchy or missing perms).' });
    return res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Voice control: mute / unmute / deafen / undeafen / disconnect
// body: { userId, action: 'mute'|'unmute'|'deafen'|'undeafen'|'disconnect' }
// ---------------------------------------------------------------------------
app.post('/api/voice-control', authMiddleware, async (req, res) => {
  const { userId, action } = req.body || {};
  if (!userId || !action) return res.status(400).json({ error: 'userId and action are required.' });

  try {
    const guild = await getGuild();
    let member;
    try {
      member = await guild.members.fetch(userId);
    } catch (_) {
      member = null;
    }
    if (!member) return res.status(400).json({ error: 'User is not currently in the server.' });
    if (!member.voice?.channelId) {
      return res.status(400).json({ error: 'User is not connected to a voice channel.' });
    }

    const auditReason = `[NVG Dashboard] by ${req.adminUser}`;

    switch (action) {
      case 'mute':
        await member.voice.setMute(true, auditReason);
        return res.json({ ok: true, action: 'mute', userId });
      case 'unmute':
        await member.voice.setMute(false, auditReason);
        return res.json({ ok: true, action: 'unmute', userId });
      case 'deafen':
        await member.voice.setDeaf(true, auditReason);
        return res.json({ ok: true, action: 'deafen', userId });
      case 'undeafen':
        await member.voice.setDeaf(false, auditReason);
        return res.json({ ok: true, action: 'undeafen', userId });
      case 'disconnect':
        await member.voice.disconnect(auditReason);
        return res.json({ ok: true, action: 'disconnect', userId });
      default:
        return res.status(400).json({ error: `Unknown voice action: ${action}` });
    }
  } catch (e) {
    console.error('[/api/voice-control]', e.message);
    if (e.code === 50013) return res.status(403).json({ error: 'Bot lacks permission (needs Mute Members / Deafen Members / Move Members).' });
    return res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`[API] NVG dashboard backend listening on :${PORT}`);
  console.log(`[API] CORS origin: ${allowedOrigin}`);
});
