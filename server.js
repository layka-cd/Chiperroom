"use strict";

const path = require("path");
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  // Halaman disajikan oleh server ini sendiri (same-origin), jadi CORS tidak diperlukan.
  // Kalau front-end kamu dihosting di domain lain, set env ALLOWED_ORIGIN, mis.
  // ALLOWED_ORIGIN=https://chiperroom.onrender.com
  cors: process.env.ALLOWED_ORIGIN ? { origin: process.env.ALLOWED_ORIGIN } : undefined,
  maxHttpBufferSize: 512 * 1024 // 512KB per event: cukup untuk pesan teks dan gambar terkompres
});

app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------
// In-memory only. Nothing here ever touches disk or a database.
// roomId -> { members: Map<socket.id, username>, buffer: Array<msg>, bufferBytes: number }
// roomId is a SHA-256 hash the CLIENT computes from the room code — the
// server never learns the actual room code, and the hash alone cannot be
// reversed into the encryption key (different derivation context/salt).
// ---------------------------------------------------------------------
const rooms = new Map();

const MAX_BUFFER_PER_ROOM = 50; // recent ciphertext messages kept for late joiners in this session
const MAX_BUFFER_BYTES = 4 * 1024 * 1024; // total ciphertext per room (gambar bisa besar, jadi dibatasi per byte juga)
const MAX_MEMBERS_PER_ROOM = 60;
const MAX_IV_CHARS = 64;
const MAX_CT_CHARS = 400000; // ~300KB data asli; klien membaca batas ini dari ack "join"

// Very small per-socket rate limiter to blunt spam/flooding.
const RATE_LIMIT_WINDOW_MS = 10000;
const RATE_LIMIT_MAX_EVENTS = 40;

function getRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, { members: new Map(), buffer: [], bufferBytes: 0 });
  }
  return rooms.get(roomId);
}

function presenceList(room) {
  return Array.from(room.members.values());
}

function cleanupRoomIfEmpty(roomId) {
  const room = rooms.get(roomId);
  if (room && room.members.size === 0) {
    rooms.delete(roomId); // buffer is dropped too — no history survives an empty room
  }
}

io.on("connection", (socket) => {
  socket.data.roomId = null;
  socket.data.username = null;
  socket.data.eventTimestamps = [];

  function withinRateLimit() {
    const now = Date.now();
    socket.data.eventTimestamps = socket.data.eventTimestamps.filter(
      (t) => now - t < RATE_LIMIT_WINDOW_MS
    );
    socket.data.eventTimestamps.push(now);
    return socket.data.eventTimestamps.length <= RATE_LIMIT_MAX_EVENTS;
  }

  socket.on("join", ({ roomId, username }, ack) => {
    if (typeof roomId !== "string" || typeof username !== "string") {
      return ack && ack({ ok: false, error: "invalid_payload" });
    }
    const cleanRoomId = roomId.slice(0, 128);
    const cleanUsername = username.trim().slice(0, 24);
    if (!cleanRoomId || !cleanUsername) {
      return ack && ack({ ok: false, error: "invalid_payload" });
    }

    if (socket.data.roomId) handleLeave(); // socket yang sama join ulang: keluar dari ruang lama dulu

    const room = getRoom(cleanRoomId);
    if (room.members.size >= MAX_MEMBERS_PER_ROOM) {
      return ack && ack({ ok: false, error: "room_full" });
    }

    socket.data.roomId = cleanRoomId;
    socket.data.username = cleanUsername;
    socket.join(cleanRoomId);
    room.members.set(socket.id, cleanUsername);

    socket.to(cleanRoomId).emit("presence", { members: presenceList(room) });

    ack &&
      ack({
        ok: true,
        members: presenceList(room),
        recent: room.buffer, // ciphertext only: [{id, iv, ct}]
        limits: { maxCt: MAX_CT_CHARS }
      });
  });

  socket.on("message", (payload, ack) => {
    const reply = (r) => typeof ack === "function" && ack(r);
    if (!withinRateLimit()) return reply({ ok: false, error: "rate_limited" });
    const roomId = socket.data.roomId;
    if (!roomId) return reply({ ok: false, error: "not_in_room" });
    const { iv, ct } = payload || {};
    if (typeof iv !== "string" || typeof ct !== "string") return reply({ ok: false, error: "invalid_payload" });
    if (iv.length > MAX_IV_CHARS || ct.length > MAX_CT_CHARS) return reply({ ok: false, error: "too_large" }); // sanity caps

    const room = getRoom(roomId);
    const entry = {
      id: Date.now() + "-" + Math.random().toString(36).slice(2, 8),
      iv,
      ct
    };
    room.buffer.push(entry);
    room.bufferBytes += iv.length + ct.length;
    while (
      room.buffer.length > 1 &&
      (room.buffer.length > MAX_BUFFER_PER_ROOM || room.bufferBytes > MAX_BUFFER_BYTES)
    ) {
      const old = room.buffer.shift();
      room.bufferBytes -= old.iv.length + old.ct.length;
    }

    io.to(roomId).emit("message", entry);
    reply({ ok: true });
  });

  socket.on("leave", () => handleLeave());
  socket.on("disconnect", () => handleLeave());

  function handleLeave() {
    const roomId = socket.data.roomId;
    if (!roomId) return;
    const room = rooms.get(roomId);
    if (room) {
      room.members.delete(socket.id);
      socket.to(roomId).emit("presence", { members: presenceList(room) });
      cleanupRoomIfEmpty(roomId);
    }
    socket.leave(roomId);
    socket.data.roomId = null;
  }
});

server.listen(PORT, () => {
  console.log(`CipherRoom relay listening on port ${PORT}`);
});
