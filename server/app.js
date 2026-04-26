const fs = require("fs");
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt"); // ✅ for password verification
const { DEFAULT_DB_FILE, openDatabase } = require("../db");

function sendPublicFile(response, fileName) {
  response.sendFile(path.join(__dirname, "..", "public", fileName));
}

// Better session ID (not predictable)
function createSessionId() {
  return require("crypto").randomBytes(32).toString("hex");
}

async function createApp() {
  if (!fs.existsSync(DEFAULT_DB_FILE)) {
    throw new Error(
      `Database file not found at ${DEFAULT_DB_FILE}. Run "npm run init-db" first.`
    );
  }

  const db = openDatabase(DEFAULT_DB_FILE);
  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());

  app.use("/css", express.static(path.join(__dirname, "..", "public", "css")));
  app.use("/js", express.static(path.join(__dirname, "..", "public", "js")));

  // -------------------------------
  // Session middleware
  // -------------------------------
  app.use(async (request, response, next) => {
    const sessionId = request.cookies.sid;

    if (!sessionId) {
      request.currentUser = null;
      return next();
    }

    const row = await db.get(
      `
        SELECT
          sessions.id AS session_id,
          users.id AS id,
          users.username,
          users.role,
          users.display_name
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.id = ?
      `,
      [sessionId]
    );

    request.currentUser = row
      ? {
          sessionId: row.session_id,
          id: row.id,
          username: row.username,
          role: row.role,
          displayName: row.display_name
        }
      : null;

    next();
  });

  function requireAuth(request, response, next) {
    if (!request.currentUser) {
      return response.status(401).json({ error: "Authentication required." });
    }
    next();
  }

  function requireAdmin(request, response, next) {
    if (!request.currentUser || request.currentUser.role !== "admin") {
      return response.status(403).json({ error: "Forbidden." });
    }
    next();
  }

  // -------------------------------
  // Pages
  // -------------------------------
  app.get("/", (_req, res) => sendPublicFile(res, "index.html"));
  app.get("/login", (_req, res) => sendPublicFile(res, "login.html"));
  app.get("/notes", (_req, res) => sendPublicFile(res, "notes.html"));
  app.get("/settings", (_req, res) => sendPublicFile(res, "settings.html"));
  app.get("/admin", (_req, res) => sendPublicFile(res, "admin.html"));

  app.get("/api/me", (req, res) => {
    res.json({ user: req.currentUser });
  });

  // -------------------------------
  // LOGIN (fixed: SQL injection + auth)
  // -------------------------------
  app.post("/api/login", async (req, res) => {
    const username = String(req.body.username || "");
    const password = String(req.body.password || "");

    const user = await db.get(
      "SELECT id, username, password, role, display_name FROM users WHERE username = ?",
      [username]
    );

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    const sessionId = createSessionId();

    await db.run(
      "INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)",
      [sessionId, user.id, new Date().toISOString()]
    );

    res.cookie("sid", sessionId, {
      httpOnly: true, // ✅ prevents JS access (XSS mitigation)
      sameSite: "Strict" // ✅ helps prevent CSRF
    });

    res.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        displayName: user.display_name
      }
    });
  });

  // -------------------------------
  // LOGOUT
  // -------------------------------
  app.post("/api/logout", async (req, res) => {
    if (req.cookies.sid) {
      await db.run("DELETE FROM sessions WHERE id = ?", [req.cookies.sid]);
    }

    res.clearCookie("sid");
    res.json({ ok: true });
  });

  // -------------------------------
  // NOTES (fixed: injection + auth + logic abuse)
  // -------------------------------
  app.get("/api/notes", requireAuth, async (req, res) => {
    const search = String(req.query.search || "");

    const notes = await db.all(
      `
      SELECT
        notes.id,
        notes.owner_id AS ownerId,
        users.username AS ownerUsername,
        notes.title,
        notes.body,
        notes.pinned,
        notes.created_at AS createdAt
      FROM notes
      JOIN users ON users.id = notes.owner_id
      WHERE notes.owner_id = ?
        AND (notes.title LIKE ? OR notes.body LIKE ?)
      ORDER BY notes.pinned DESC, notes.id DESC
    `,
      [
        req.currentUser.id,
        `%${search}%`,
        `%${search}%`
      ]
    );

    res.json({ notes });
  });

  app.post("/api/notes", requireAuth, async (req, res) => {
    const title = String(req.body.title || "");
    const body = String(req.body.body || "");
    const pinned = req.body.pinned ? 1 : 0;

    const result = await db.run(
      "INSERT INTO notes (owner_id, title, body, pinned, created_at) VALUES (?, ?, ?, ?, ?)",
      [req.currentUser.id, title, body, pinned, new Date().toISOString()]
    );

    res.status(201).json({ ok: true, noteId: result.lastID });
  });

  // -------------------------------
  // SETTINGS (fixed: auth + logic abuse)
  // -------------------------------
  app.get("/api/settings", requireAuth, async (req, res) => {
    const settings = await db.get(
      `
        SELECT
          users.id AS userId,
          users.username,
          users.role,
          users.display_name AS displayName,
          settings.status_message AS statusMessage,
          settings.theme,
          settings.email_opt_in AS emailOptIn
        FROM settings
        JOIN users ON users.id = settings.user_id
        WHERE settings.user_id = ?
      `,
      [req.currentUser.id]
    );

    res.json({ settings });
  });

  app.post("/api/settings", requireAuth, async (req, res) => {
    const displayName = String(req.body.displayName || "");
    const statusMessage = String(req.body.statusMessage || "");
    const theme = String(req.body.theme || "classic");
    const emailOptIn = req.body.emailOptIn ? 1 : 0;

    await db.run("UPDATE users SET display_name = ? WHERE id = ?", [
      displayName,
      req.currentUser.id
    ]);

    await db.run(
      "UPDATE settings SET status_message = ?, theme = ?, email_opt_in = ? WHERE user_id = ?",
      [statusMessage, theme, emailOptIn, req.currentUser.id]
    );

    res.json({ ok: true });
  });

  // FIXED: CSRF-prone GET → now POST
  app.post("/api/settings/toggle-email", requireAuth, async (req, res) => {
    const enabled = req.body.enabled === "1" ? 1 : 0;

    await db.run("UPDATE settings SET email_opt_in = ? WHERE user_id = ?", [
      enabled,
      req.currentUser.id
    ]);

    res.json({ ok: true, emailOptIn: enabled });
  });

  // -------------------------------
  // ADMIN (fixed: authorization)
  // -------------------------------
  app.get("/api/admin/users", requireAuth, requireAdmin, async (_req, res) => {
    const users = await db.all(`
      SELECT
        users.id,
        users.username,
        users.role,
        users.display_name AS displayName,
        COUNT(notes.id) AS noteCount
      FROM users
      LEFT JOIN notes ON notes.owner_id = users.id
      GROUP BY users.id
      ORDER BY users.id
    `);

    res.json({ users });
  });

  return app;
}

module.exports = {
  createApp
};