const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-production";
const MAX_FAILED = 5;
const BAN_MS = 5 * 60 * 1000;
const OTP_TTL_MS = 10 * 60 * 1000;

const db = new Database(process.env.DB_FILE || "app.db");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  two_step_enabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  purpose TEXT NOT NULL,            -- 'enable_2fa' | 'login'
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id),
  receiver_id INTEGER NOT NULL REFERENCES users(id),
  content TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL REFERENCES messages(id),
  requester_id INTEGER NOT NULL REFERENCES users(id),   -- the receiver
  status TEXT NOT NULL DEFAULT 'pending',               -- pending | accepted | rejected
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS conversations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL UNIQUE REFERENCES messages(id),
  user1_id INTEGER NOT NULL REFERENCES users(id),   -- original sender
  user2_id INTEGER NOT NULL REFERENCES users(id),   -- original receiver
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS conversation_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id INTEGER NOT NULL REFERENCES conversations(id),
  sender_id INTEGER NOT NULL REFERENCES users(id),
  content TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`);

const now = () => Date.now();
const hash = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const genOtp = () => String(crypto.randomInt(0, 1000000)).padStart(6, "0");
const signTokens = (user) => ({
  accessToken: jwt.sign({ sub: user.id, type: "access" }, JWT_SECRET, { expiresIn: "15m" }),
  refreshToken: jwt.sign({ sub: user.id, type: "refresh" }, JWT_SECRET, { expiresIn: "7d" }),
});

const transporter = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: +(process.env.SMTP_PORT || 587),
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

async function sendOtpEmail(email, code, purpose) {
  const subject = purpose === "login" ? "Your login verification code" : "Enable 2-step verification";
  const text = `Your verification code is ${code}. It expires in 10 minutes.`;
  if (transporter) {
    await transporter.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: email, subject, text });
  } else {
    console.log(`[DEV EMAIL] to=${email} | ${subject} | code=${code}`); 
  }
}

async function issueOtp(user, purpose) {
  db.prepare("UPDATE otps SET used=1 WHERE user_id=? AND purpose=? AND used=0").run(user.id, purpose);
  const code = genOtp();
  db.prepare("INSERT INTO otps (user_id,purpose,code_hash,expires_at) VALUES (?,?,?,?)")
    .run(user.id, purpose, hash(code), now() + OTP_TTL_MS);
  await sendOtpEmail(user.email, code, purpose);
}

function checkOtp(userId, purpose, code) {
  const row = db.prepare(
    "SELECT * FROM otps WHERE user_id=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1"
  ).get(userId, purpose);
  if (!row || row.expires_at < now() || row.code_hash !== hash(code)) return false;
  db.prepare("UPDATE otps SET used=1 WHERE id=?").run(row.id);
  return true;
}

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const p = jwt.verify(token, JWT_SECRET);
    if (p.type !== "access") throw new Error();
    const user = db.prepare("SELECT * FROM users WHERE id=?").get(p.sub);
    if (!user) throw new Error();
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

const app = express();
app.use(express.json());

app.post("/auth/register", wrap(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({ error: "name, email and password (min 6 chars) are required" });
  try {
    const r = db.prepare("INSERT INTO users (name,email,password_hash) VALUES (?,?,?)")
      .run(name, email.toLowerCase(), await bcrypt.hash(password, 10));
    res.status(201).json({ id: r.lastInsertRowid, name, email: email.toLowerCase() });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error: "Email already registered" });
    throw e;
  }
}));

app.post("/auth/login", wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password are required" });
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  if (user.locked_until > now()) {
    const retryAfter = Math.ceil((user.locked_until - now()) / 1000);
    res.set("Retry-After", String(retryAfter));
    return res.status(429).json({ error: "Account temporarily banned. Try again later.", retryAfterSeconds: retryAfter });
  }

  if (!(await bcrypt.compare(password, user.password_hash))) {
    const attempts = user.failed_attempts + 1;
    if (attempts >= MAX_FAILED) {
      db.prepare("UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?").run(now() + BAN_MS, user.id);
      res.set("Retry-After", String(BAN_MS / 1000));
      return res.status(429).json({ error: "Too many failed attempts. Account banned for 5 minutes.", retryAfterSeconds: BAN_MS / 1000 });
    }
    db.prepare("UPDATE users SET failed_attempts=? WHERE id=?").run(attempts, user.id);
    return res.status(401).json({ error: "Invalid credentials", attemptsLeft: MAX_FAILED - attempts });
  }

  db.prepare("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?").run(user.id);

  if (user.two_step_enabled) {
    await issueOtp(user, "login");
    return res.json({ twoStepRequired: true, message: "Verification code sent to your email. Call /auth/login/confirm." });
  }
  res.json(signTokens(user));
}));

app.post("/auth/login/confirm", wrap(async (req, res) => {
  const { email, otp } = req.body || {};
  if (!email || !otp) return res.status(400).json({ error: "email and otp are required" });
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email.toLowerCase());
  if (!user || !user.two_step_enabled || !checkOtp(user.id, "login", otp))
    return res.status(401).json({ error: "Invalid or expired code" });
  res.json(signTokens(user));
}));

app.post("/auth/2fa/enable", auth, wrap(async (req, res) => {
  if (req.user.two_step_enabled) return res.status(400).json({ error: "2-step verification already enabled" });
  await issueOtp(req.user, "enable_2fa");
  res.json({ message: "OTP sent to your email. Send it to /auth/2fa/verify." });
}));

app.post("/auth/2fa/verify", auth, wrap(async (req, res) => {
  const { otp } = req.body || {};
  if (!otp || !checkOtp(req.user.id, "enable_2fa", otp))
    return res.status(401).json({ error: "Invalid or expired code" });
  db.prepare("UPDATE users SET two_step_enabled=1 WHERE id=?").run(req.user.id);
  res.json({ message: "2-step verification enabled" });
}));

app.post("/messages", auth, (req, res) => {
  const { receiverId, content } = req.body || {};
  if (!receiverId || !content) return res.status(400).json({ error: "receiverId and content are required" });
  if (receiverId === req.user.id) return res.status(400).json({ error: "You cannot message yourself" });
  if (!db.prepare("SELECT 1 FROM users WHERE id=?").get(receiverId))
    return res.status(404).json({ error: "Receiver not found" });
  const r = db.prepare("INSERT INTO messages (sender_id,receiver_id,content,created_at) VALUES (?,?,?,?)")
    .run(req.user.id, receiverId, content, now());
  res.status(201).json({ id: r.lastInsertRowid, receiverId, content });
});

app.get("/messages/received", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT m.id, m.content, m.created_at,
      (SELECT status FROM identity_requests r WHERE r.message_id=m.id ORDER BY r.id DESC LIMIT 1) AS requestStatus,
      (SELECT id FROM conversations c WHERE c.message_id=m.id) AS conversationId,
      CASE WHEN EXISTS (SELECT 1 FROM identity_requests r WHERE r.message_id=m.id AND r.status='accepted')
           THEN u.id END AS senderId,
      CASE WHEN EXISTS (SELECT 1 FROM identity_requests r WHERE r.message_id=m.id AND r.status='accepted')
           THEN u.name END AS senderName
    FROM messages m JOIN users u ON u.id=m.sender_id
    WHERE m.receiver_id=? ORDER BY m.id DESC`).all(req.user.id);
  res.json(rows);
});

app.post("/messages/:id/request-identity", auth, (req, res) => {
  const msg = db.prepare("SELECT * FROM messages WHERE id=?").get(req.params.id);
  if (!msg || msg.receiver_id !== req.user.id) return res.status(404).json({ error: "Message not found" });
  const existing = db.prepare(
    "SELECT * FROM identity_requests WHERE message_id=? AND status IN ('pending','accepted')").get(msg.id);
  if (existing) return res.status(409).json({ error: `A request already exists (${existing.status})` });
  const r = db.prepare("INSERT INTO identity_requests (message_id,requester_id,status,created_at) VALUES (?,?,'pending',?)")
    .run(msg.id, req.user.id, now());
  res.status(201).json({ id: r.lastInsertRowid, messageId: msg.id, status: "pending" });
});

app.get("/requests", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT r.id, r.message_id AS messageId, m.content AS messageContent, r.status, r.created_at
    FROM identity_requests r JOIN messages m ON m.id=r.message_id
    WHERE m.sender_id=? ORDER BY r.id DESC`).all(req.user.id);
  res.json(rows);
});

app.patch("/requests/:id", auth, (req, res) => {
  const action = (req.body || {}).action;
  if (!["accept", "reject"].includes(action)) return res.status(400).json({ error: "action must be 'accept' or 'reject'" });
  const reqRow = db.prepare(`
    SELECT r.*, m.sender_id, m.receiver_id FROM identity_requests r
    JOIN messages m ON m.id=r.message_id WHERE r.id=?`).get(req.params.id);
  if (!reqRow || reqRow.sender_id !== req.user.id) return res.status(404).json({ error: "Request not found" });
  if (reqRow.status !== "pending") return res.status(409).json({ error: `Request already ${reqRow.status}` });

  if (action === "reject") {
    db.prepare("UPDATE identity_requests SET status='rejected' WHERE id=?").run(reqRow.id);
    return res.json({ id: reqRow.id, status: "rejected" });
  }
  const tx = db.transaction(() => {
    db.prepare("UPDATE identity_requests SET status='accepted' WHERE id=?").run(reqRow.id);
    const c = db.prepare("INSERT INTO conversations (message_id,user1_id,user2_id,created_at) VALUES (?,?,?,?)")
      .run(reqRow.message_id, reqRow.sender_id, reqRow.receiver_id, now());
    return c.lastInsertRowid;
  });
  const conversationId = tx();
  res.json({ id: reqRow.id, status: "accepted", conversationId });
});

function getConversation(req, res) {
  const c = db.prepare("SELECT * FROM conversations WHERE id=?").get(req.params.id);
  if (!c || (c.user1_id !== req.user.id && c.user2_id !== req.user.id)) {
    res.status(404).json({ error: "Conversation not found" });
    return null;
  }
  return c;
}

app.post("/conversations/:id/messages", auth, (req, res) => {
  const c = getConversation(req, res); if (!c) return;
  const { content } = req.body || {};
  if (!content) return res.status(400).json({ error: "content is required" });
  const r = db.prepare("INSERT INTO conversation_messages (conversation_id,sender_id,content,created_at) VALUES (?,?,?,?)")
    .run(c.id, req.user.id, content, now());
  res.status(201).json({ id: r.lastInsertRowid, conversationId: c.id, content });
});

app.get("/conversations/:id/messages", auth, (req, res) => {
  const c = getConversation(req, res); if (!c) return;
  const rows = db.prepare(
    "SELECT id, sender_id AS senderId, content, created_at FROM conversation_messages WHERE conversation_id=? ORDER BY id")
    .all(c.id);
  res.json({ conversationId: c.id, originalMessageId: c.message_id, messages: rows });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

module.exports = { app, db };
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`API running on http://localhost:${port}`));
}
