const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const cron = require("node-cron");
const { v4: uuidv4 } = require("uuid");
const swaggerUi = require("swagger-ui-express");
const swaggerSpec = require("./swagger");

const PORT = process.env.PORT || 5000;

const app = express();

const corsOptions = {
  origin: ["http://localhost:3000", "https://referral-app-weld.vercel.app"],
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true,
  optionsSuccessStatus: 204,
};

app.use(express.json());
app.use(cors(corsOptions));

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const db = new sqlite3.Database(":memory:");

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

/**
 * @swagger
 * /signup:
 *   post:
 *     summary: Register a new user
 *     description: Creates a new user with email and password
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       201:
 *         description: User created
 *       400:
 *         description: User already exists
 *       500:
 *         description: Failed to create user
 */
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

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in a user
 *     description: Authenticates a user and returns a JWT token
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       200:
 *         description: Successfully logged in
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *                 id:
 *                   type: integer
 *                   example: 1
 *                 email:
 *                   type: string
 *                   example: user@example.com
 *       401:
 *         description: Invalid credentials
 */
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

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users
 *     description: Returns a list of all users
 *     responses:
 *       200:
 *         description: List of users
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 users:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                       email:
 *                         type: string
 *                       password:
 *                         type: string
 *       500:
 *         description: Failed to retrieve users
 */
app.get("/users", (req, res) => {
  db.all(`SELECT id, email, password FROM users`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Failed to retrieve users" });
    }
    res.status(200).json({ users: rows });
  });
});

/**
 * @swagger
 * /deleteUser:
 *   delete:
 *     summary: Delete a user
 *     description: Deletes a user by email
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: User deleted
 *       500:
 *         description: Failed to delete user
 */
app.delete("/deleteUser", (req, res) => {
  const { email } = req.body;
  db.run(`DELETE FROM users WHERE email = ?`, [email], (err) => {
    if (err) {
      return res.status(500).json({ error: "Failed to delete user" });
    }
    res.status(200).json({ message: "User deleted" });
  });
});

/**
 * @swagger
 * /referrals:
 *   post:
 *     summary: Submit a referral
 *     description: Creates a new referral
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userID:
 *                 type: integer
 *                 example: 1
 *               referralEmail:
 *                 type: string
 *                 example: referral@example.com
 *               referralDescription:
 *                 type: string
 *                 example: This is a great candidate because...
 *     responses:
 *       201:
 *         description: Referral submitted
 *       500:
 *         description: Failed to submit referral
 */
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

/**
 * @swagger
 * /referrals:
 *   get:
 *     summary: Get all referrals
 *     description: Returns a list of all referrals
 *     responses:
 *       200:
 *         description: List of referrals
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   userID:
 *                     type: integer
 *                   referralEmail:
 *                     type: string
 *                   referralDescription:
 *                     type: string
 *                   hiringDate:
 *                     type: string
 *                   status:
 *                     type: string
 *                   code:
 *                     type: string
 *                   amount:
 *                     type: integer
 *       500:
 *         description: Failed to retrieve referrals
 */
app.get("/referrals", (req, res) => {
  db.all(`SELECT * FROM referrals`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Failed to retrieve referrals" });
    }
    res.status(200).json(rows);
  });
});

/**
 * @swagger
 * /referrals/{id}:
 *   put:
 *     summary: Update a referral
 *     description: Updates a referral by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the referral
 *         schema:
 *           type: integer
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               referralEmail:
 *                 type: string
 *                 example: updated@example.com
 *               description:
 *                 type: string
 *                 example: Updated description
 *     responses:
 *       200:
 *         description: Referral updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 referralEmail:
 *                   type: string
 *                 referralDescription:
 *                   type: string
 *       400:
 *         description: Email and description are required
 *       500:
 *         description: Internal server error
 */
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
        SET referralEmail = ?, referralDescription = ?
        WHERE id = ?`,
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

/**
 * @swagger
 * /referrals/{id}:
 *   delete:
 *     summary: Delete a referral
 *     description: Deletes a referral by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the referral
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Referral deleted
 *       500:
 *         description: Internal server error
 */
app.delete("/referrals/:id", async (req, res) => {
  const { id } = req.params;

  try {
    db.run(`DELETE FROM referrals WHERE id = ?`, [id]);

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
