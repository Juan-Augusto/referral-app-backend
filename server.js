const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 5000;
const db = new sqlite3.Database(":memory:");

app.use(express.json());
app.use(cors());

db.run(`CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT
)`);

db.run(`CREATE TABLE referrals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userID INTEGER,
  referralEmail TEXT,
  referralDescription TEXT,
  hiringDate TEXT,
  status TEXT,
  FOREIGN KEY (userID) REFERENCES users(id)
)`);

const isBcryptHash = (str) => {
  return /^\$2[ayb]\$.{56}$/.test(str);
};

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  try {
    let hashedPassword;
    if (isBcryptHash(password)) {
      hashedPassword = password;
    } else {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    db.run(
      `INSERT INTO users (email, password) VALUES (?, ?)`,
      [email, hashedPassword],
      (err) => {
        if (err) {
          return res.status(400).json({ error: "User already exists" });
        }
        res.status(201).json({ message: "User created" });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to create user" });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const token = jwt.sign({ id: user.id }, "your_jwt_secret", {
        expiresIn: "1h",
      });
      res.json({ token });
    });
  });
});

// List users endpoint
app.get("/users", (req, res) => {
  db.all(`SELECT id, email, password FROM users`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Failed to retrieve users" });
    }
    res.status(200).json({ users: rows });
  });
});

// Delete user endpoint
app.delete("/deleteUser", (req, res) => {
  const { email } = req.body;
  db.run(`DELETE FROM users WHERE email = ?`, [email], (err) => {
    if (err) {
      return res.status(500).json({ error: "Failed to delete user" });
    }
    res.status(200).json({ message: "User deleted" });
  });
});

// Referrals endpoint
app.post("/referrals", (req, res) => {
  const { userID, referralEmail, referralDescription } = req.body;
  db.run(
    `INSERT INTO referrals (userID, referralEmail, referralDescription, status) VALUES (?, ?, ?, ?)`,
    [userID, referralEmail, referralDescription, "We review eligibility"],
    (err) => {
      if (err) {
        return res.status(500).json({ error: "Failed to submit referral" });
      }
      res.status(201).json({ message: "Referral submitted" });
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
