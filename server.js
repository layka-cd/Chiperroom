"use strict";

const path = require("path");
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
// Frontend dilayani dari server yang sama, jadi CORS tidak perlu dibuka.
// Kalau frontend ada di domain lain, set ALLOWED_ORIGIN (pisahkan dengan koma).
const allowedOrigins = (process.env.ALLOWED_ORIGIN || "").split(",").map((o) => o.trim()).filter(Boolean);
const io = new Server(server, {
  ...(allowedOrigins.length ? { cors: { origin: allowedOrigins } } : {}),
  maxHttpBufferSize: 512 * 1024 // 512KB per event: muat gambar terkompresi (~170KB) setelah dienkripsi
});

app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------
// In-memory only. Nothing here ever touches disk or a database.
// roomId -> { members: Map<socket.id, username>, buffer: Array<msg> }
// roomId is a SHA-256 hash the CLIENT computes from the room code — the
// server never learns the actual room code, and the hash alone cannot be
// reversed into the encryption key (different derivation context/salt).
// ---------------------------------------------------------------------
const rooms = new Map();

const MAX_BUFFER_PER_ROOM = 50; // recent ciphertext messages kept for late joiners in this session
const MAX_BUFFER_BYTES = 4 * 1024 * 1024; // batas memori per ruang (gambar bisa besar)
const MAX_CT_LENGTH = 300000; // panjang ciphertext base64 per pesan
const MAX_MEMBERS_PER_ROOM = 50;

// Very small per-socket rate limiter to blunt spam/flooding.
const RATE_LIMIT_WINDOW_MS = 10000;
const RATE_LIMIT_MAX_EVENTS = 40;

function getRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, { members: new Map(), buffer: [], bytes: 0 });
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
        recent: room.buffer.map(({ id, iv, ct }) => ({ id, iv, ct })) // ciphertext only
      });
  });

  socket.on("message", (payload, ack) => {
    const reply = (res) => typeof ack === "function" && ack(res);
    if (!withinRateLimit()) return reply({ ok: false, error: "rate_limited" });
    const roomId = socket.data.roomId;
    if (!roomId) return reply({ ok: false, error: "not_in_room" });
    const { iv, ct } = payload || {};
    if (typeof iv !== "string" || typeof ct !== "string") return reply({ ok: false, error: "invalid_payload" });
    if (iv.length > 64 || ct.length > MAX_CT_LENGTH) return reply({ ok: false, error: "too_large" }); // sanity caps

    const room = getRoom(roomId);
    const entry = {
      id: Date.now() + "-" + Math.random().toString(36).slice(2, 8),
      iv,
      ct
    };
    entry.size = iv.length + ct.length;
    room.buffer.push(entry);
    room.bytes += entry.size;
    while (room.buffer.length > MAX_BUFFER_PER_ROOM || (room.bytes > MAX_BUFFER_BYTES && room.buffer.length > 1)) {
      room.bytes -= room.buffer.shift().size;
    }

    io.to(roomId).emit("message", { id: entry.id, iv: entry.iv, ct: entry.ct });
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
