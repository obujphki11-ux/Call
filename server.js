require("dotenv").config();

const path = require("path");
const http = require("http");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*"
  }
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(150) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      name: user.name,
      email: user.email
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Login required"
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired token"
    });
  }
}

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "All fields are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters"
      });
    }

    const cleanEmail = email.toLowerCase().trim();

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [cleanEmail]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        message: "Email already registered"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
       (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, created_at`,
      [
        name.trim(),
        cleanEmail,
        passwordHash
      ]
    );

    const user = result.rows[0];

    res.json({
      message: "Account created successfully",
      user,
      token: createToken(user)
    });
  } catch (error) {
    console.error("Register error:", error);

    res.status(500).json({
      message: "Server error"
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const user = result.rows[0];

    const isPasswordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!isPasswordCorrect) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    res.json({
      message: "Login successful",
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      },
      token: createToken(user)
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      message: "Server error"
    });
  }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, created_at
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({
      message: "Server error"
    });
  }
});

app.get("/api/users", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, created_at
       FROM users
       WHERE id != $1
       ORDER BY name ASC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      message: "Server error"
    });
  }
});

app.get("/api/messages/:userId", authMiddleware, async (req, res) => {
  try {
    const otherUserId = Number(req.params.userId);

    const result = await pool.query(
      `SELECT id, sender_id, receiver_id, message, created_at
       FROM messages
       WHERE
         (sender_id = $1 AND receiver_id = $2)
         OR
         (sender_id = $2 AND receiver_id = $1)
       ORDER BY created_at ASC`,
      [
        req.user.id,
        otherUserId
      ]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      message: "Server error"
    });
  }
});

const onlineUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;

  if (!token) {
    return next(new Error("Authentication required"));
  }

  try {
    socket.user = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    next();
  } catch (error) {
    next(new Error("Invalid token"));
  }
});

io.on("connection", socket => {
  const userId = String(socket.user.id);

  onlineUsers.set(userId, socket.id);

  socket.on("send-message", async data => {
    try {
      const receiverId = Number(data.receiverId);
      const message = String(data.message || "").trim();

      if (!message || !receiverId) {
        return;
      }

      const result = await pool.query(
        `INSERT INTO messages
         (sender_id, receiver_id, message)
         VALUES ($1, $2, $3)
         RETURNING id, sender_id, receiver_id, message, created_at`,
        [
          socket.user.id,
          receiverId,
          message
        ]
      );

      const savedMessage = result.rows[0];

      socket.emit("new-message", savedMessage);

      const receiverSocketId = onlineUsers.get(
        String(receiverId)
      );

      if (receiverSocketId) {
        io.to(receiverSocketId).emit(
          "new-message",
          savedMessage
        );
      }
    } catch (error) {
      console.error("Message error:", error);
    }
  });

  socket.on("call-user", data => {
    const targetSocketId = onlineUsers.get(
      String(data.targetUserId)
    );

    if (!targetSocketId) {
      socket.emit("user-offline");
      return;
    }

    io.to(targetSocketId).emit("incoming-call", {
      callerId: socket.user.id,
      callerName: socket.user.name,
      offer: data.offer,
      callType: data.callType
    });
  });

  socket.on("answer-call", data => {
    const callerSocketId = onlineUsers.get(
      String(data.callerId)
    );

    if (callerSocketId) {
      io.to(callerSocketId).emit("call-answered", {
        answer: data.answer
      });
    }
  });

  socket.on("ice-candidate", data => {
    const targetSocketId = onlineUsers.get(
      String(data.targetUserId)
    );

    if (targetSocketId) {
      io.to(targetSocketId).emit("ice-candidate", {
        candidate: data.candidate,
        fromUserId: socket.user.id
      });
    }
  });

  socket.on("end-call", data => {
    const targetSocketId = onlineUsers.get(
      String(data.targetUserId)
    );

    if (targetSocketId) {
      io.to(targetSocketId).emit("call-ended");
    }
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(userId);
  });
});

const PORT = process.env.PORT || 3000;

createTables()
  .then(() => {
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database connection error:", error);
    process.exit(1);
  });
