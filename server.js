const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const cron = require("node-cron");
const { v4: uuidv4 } = require("uuid");

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
  hiringDate TEXT DEFAULT '',
  status TEXT DEFAULT 'We review eligibility',
  code TEXT,
  amount INTEGER,
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
      res.json({
        token,
        id: user.id,
        email: user.email,
      });
    });
  });
});

app.get("/users", (req, res) => {
  db.all(`SELECT id, email, password FROM users`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Failed to retrieve users" });
    }
    res.status(200).json({ users: rows });
  });
});

app.delete("/deleteUser", (req, res) => {
  const { email } = req.body;
  db.run(`DELETE FROM users WHERE email = ?`, [email], (err) => {
    if (err) {
      return res.status(500).json({ error: "Failed to delete user" });
    }
    res.status(200).json({ message: "User deleted" });
  });
});

app.post("/referrals", (req, res) => {
  const { userID, referralEmail, referralDescription } = req.body;
  const hiringDate = "";
  const status = "We review eligibility";

  db.run(
    `INSERT INTO referrals (userID, referralEmail, referralDescription, hiringDate, status) VALUES (?, ?, ?, ?, ?)`,
    [userID, referralEmail, referralDescription, hiringDate, status],
    (err) => {
      if (err) {
        return res.status(500).json({ error: "Failed to submit referral" });
      }
      res.status(201).json({ message: "Referral submitted" });
    }
  );
});

app.get("/referrals", (req, res) => {
  db.all(`SELECT * FROM referrals`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Failed to retrieve referrals" });
    }
    res.status(200).json(rows);
  });
});

app.put("/referrals/:id", async (req, res) => {
  const { id } = req.params;
  const { referralEmail, description } = req.body;

  if (!referralEmail || !description) {
    return res
      .status(400)
      .json({ message: "Email and description are required" });
  }

  try {
    db.run(
      `UPDATE referrals
        SET referralEmail = $1, referralDescription = $2
        WHERE id = $3
        RETURNING *`,
      [referralEmail, description, id]
    );

    db.get(`SELECT * FROM referrals WHERE id = ?`, [id], (err, row) => {
      if (err) {
        return res.status(500).json({ message: "Internal server error" });
      }
      res.status(200).json(row);
    });
  } catch (error) {
    console.error("Error updating referral", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete("/referrals/:id", async (req, res) => {
  const { id } = req.params;

  try {
    db.run(
      `DELETE FROM referrals
        WHERE id = $1
        RETURNING *`,
      [id]
    );

    res.status(200).json({ message: "Referral deleted" });
  } catch (error) {
    console.error("Error canceling referral", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

const generateCode = (referralId, amount) => {
  const code = uuidv4();
  db.run(
    `UPDATE referrals SET code = ?, amount = ? WHERE id = ?`,
    [code, amount, referralId],
    (err) => {
      if (err) {
        console.error(
          `Failed to generate code for referral ${referralId}`,
          err
        );
      }
    }
  );
};

cron.schedule("0 0 * * *", () => {
  const currentDate = new Date();
  const threeMonthsAgo = new Date(
    currentDate.setMonth(currentDate.getMonth() - 3)
  );
  const sixMonthsAgo = new Date(
    currentDate.setMonth(currentDate.getMonth() - 6)
  );

  db.all(
    `SELECT * FROM referrals WHERE hiringDate != "" AND status != "Referral stopped"`,
    [],
    (err, rows) => {
      if (err) {
        console.error("Failed to retrieve referrals", err);
        return;
      }

      rows.forEach((referral) => {
        const hiringDate = new Date(referral.hiringDate);

        if (hiringDate <= sixMonthsAgo) {
          generateCode(referral.id, 1200);
        } else if (hiringDate <= threeMonthsAgo) {
          generateCode(referral.id, 800);
        }
      });
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
