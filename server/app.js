const fs = require("fs");
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const { DEFAULT_DB_FILE, openDatabase } = require("../db");
 
function sendPublicFile(response, fileName) {
  response.sendFile(path.join(__dirname, "..", "public", fileName));
}
 
function createSessionId() {
  return `SESSION-${Math.random().toString(36).slice(2, 10)}-${Date.now()}`;
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
 
  app.use(async (request, response, next) => {
    const sessionId = request.cookies.sid;
 
    if (!sessionId) {
      request.currentUser = null;
      next();
      return;
    }
 
    const row = await db.get(
      `
        SELECT
          sessions.id AS session_id,
          users.id AS id,
          users.username AS username,
          users.role AS role,
          users.display_name AS display_name
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
      response.status(401).json({ error: "Authentication required." });
      return;
    }
 
    next();
  }
 
  // FIX (Authorization): dedicated middleware for admin-only routes
  function requireAdmin(request, response, next) {
    if (!request.currentUser || request.currentUser.role !== "admin") {
      response.status(403).json({ error: "Forbidden." });
      return;
    }
 
    next();
  }
 
  app.get("/", (_request, response) => sendPublicFile(response, "index.html"));
  app.get("/login", (_request, response) => sendPublicFile(response, "login.html"));
  app.get("/notes", (_request, response) => sendPublicFile(response, "notes.html"));
  app.get("/settings", (_request, response) => sendPublicFile(response, "settings.html"));
  app.get("/admin", (_request, response) => sendPublicFile(response, "admin.html"));
 
  app.get("/api/me", (request, response) => {
    response.json({ user: request.currentUser });
  });
 
  app.post("/api/login", async (request, response) => {
    const username = String(request.body.username || "");
    const password = String(request.body.password || "");
 
    // FIX (SQL Injection): use a parameterized query instead of string interpolation
    const user = await db.get(
      `SELECT id, username, role, display_name
       FROM users
       WHERE username = ? AND password = ?`,
      [username, password]
    );
 
    if (!user) {
      response.status(401).json({ error: "Invalid username or password." });
      return;
    }
 
    // FIX (Session Fixation): always generate a fresh session ID after login;
    // never reuse whatever session ID may already be present in the cookie
    const sessionId = createSessionId();
 
    await db.run("DELETE FROM sessions WHERE user_id = ?", [user.id]);
    await db.run(
      "INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)",
      [sessionId, user.id, new Date().toISOString()]
    );
 
    // FIX (Auth/Session): add httpOnly to prevent JS access to the cookie;
    // add sameSite: "strict" as a CSRF defense
    response.cookie("sid", sessionId, {
      path: "/",
      httpOnly: true,
      sameSite: "strict"
    });
 
    response.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        displayName: user.display_name
      }
    });
  });
 
  app.post("/api/logout", async (request, response) => {
    if (request.cookies.sid) {
      await db.run("DELETE FROM sessions WHERE id = ?", [request.cookies.sid]);
    }
 
    response.clearCookie("sid");
    response.json({ ok: true });
  });
 
  app.get("/api/notes", requireAuth, async (request, response) => {
    // FIX (Authorization + Business Logic): ignore any ownerId supplied by the
    // client; always scope the query to the session user's own notes.
    // Admins are the only exception — they may pass an explicit ownerId.
    const ownerId =
      request.currentUser.role === "admin" && request.query.ownerId
        ? Number(request.query.ownerId)
        : request.currentUser.id;
 
    const search = request.query.search || "";
 
    // FIX (SQL Injection): use parameterized placeholders for both ownerId
    // and the search term so neither can alter the query structure
    const notes = await db.all(
      `SELECT
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
      ORDER BY notes.pinned DESC, notes.id DESC`,
      [ownerId, `%${search}%`, `%${search}%`]
    );
 
    response.json({ notes });
  });
 
  app.post("/api/notes", requireAuth, async (request, response) => {
    // FIX (Authorization + Business Logic): derive ownerId from the session,
    // not from the request body; the client must not choose who owns a note
    const ownerId = request.currentUser.id;
    const title = String(request.body.title || "");
    const body = String(request.body.body || "");
    const pinned = request.body.pinned ? 1 : 0;
 
    const result = await db.run(
      "INSERT INTO notes (owner_id, title, body, pinned, created_at) VALUES (?, ?, ?, ?, ?)",
      [ownerId, title, body, pinned, new Date().toISOString()]
    );
 
    response.status(201).json({
      ok: true,
      noteId: result.lastID
    });
  });
 
  app.get("/api/settings", requireAuth, async (request, response) => {
    // FIX (Authorization): ignore a client-supplied userId; always return the
    // session user's own settings. Admins may still query any user.
    const userId =
      request.currentUser.role === "admin" && request.query.userId
        ? Number(request.query.userId)
        : request.currentUser.id;
 
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
      [userId]
    );
 
    response.json({ settings });
  });
 
  app.post("/api/settings", requireAuth, async (request, response) => {
    // FIX (Authorization + Business Logic): derive userId from the session so a
    // user cannot overwrite another user's settings by changing the form field
    const userId = request.currentUser.id;
    const displayName = String(request.body.displayName || "");
    const statusMessage = String(request.body.statusMessage || "");
    const theme = String(request.body.theme || "classic");
    const emailOptIn = request.body.emailOptIn ? 1 : 0;
 
    await db.run("UPDATE users SET display_name = ? WHERE id = ?", [displayName, userId]);
    await db.run(
      "UPDATE settings SET status_message = ?, theme = ?, email_opt_in = ? WHERE user_id = ?",
      [statusMessage, theme, emailOptIn, userId]
    );
 
    response.json({ ok: true });
  });
 
  // FIX (CSRF): changed from GET to POST so a third-party page cannot trigger
  // this state-changing action by embedding a simple <img> or link
  app.post("/api/settings/toggle-email", requireAuth, async (request, response) => {
    const enabled = request.body.enabled === "1" ? 1 : 0;
 
    await db.run("UPDATE settings SET email_opt_in = ? WHERE user_id = ?", [
      enabled,
      request.currentUser.id
    ]);
 
    response.json({
      ok: true,
      userId: request.currentUser.id,
      emailOptIn: enabled
    });
  });
 
  // FIX (Authorization): replaced requireAuth with requireAdmin so only users
  // with role === "admin" can reach the user list; a non-admin is rejected
  // on the server regardless of what the client-side UI does or does not show
  app.get("/api/admin/users", requireAdmin, async (_request, response) => {
    const users = await db.all(`
      SELECT
        users.id,
        users.username,
        users.role,
        users.display_name AS displayName,
        COUNT(notes.id) AS noteCount
      FROM users
      LEFT JOIN notes ON notes.owner_id = users.id
      GROUP BY users.id, users.username, users.role, users.display_name
      ORDER BY users.id
    `);
 
    response.json({ users });
  });
 
  return app;
}
 
module.exports = {
  createApp
};