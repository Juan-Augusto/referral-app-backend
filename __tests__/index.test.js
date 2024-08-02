const request = require("supertest");
const app = require("../api/index");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

let db;

beforeAll((done) => {
  db = new sqlite3.Database(":memory:", (err) => {
    if (err) return done(err);
    db.run(
      `CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT)`,
      () => {
        db.run(
          `CREATE TABLE referrals (id INTEGER PRIMARY KEY AUTOINCREMENT, userID INTEGER, referralEmail TEXT, referralDescription TEXT, hiringDate TEXT DEFAULT '', status TEXT DEFAULT 'We review eligibility', code TEXT, amount INTEGER, FOREIGN KEY (userID) REFERENCES users(id))`,
          done
        );
      }
    );
  });
});

afterAll((done) => {
  db.close(done);
});

describe("POST /signup", () => {
  it("should create a new user", async () => {
    const res = await request(app)
      .post("/signup")
      .send({ email: "test@example.com", password: "password123" });

    expect(res.statusCode).toEqual(201);
    expect(res.body.message).toBe("User created");
  });

  it("should not allow duplicate emails", async () => {
    await request(app)
      .post("/signup")
      .send({ email: "test@example.com", password: "password123" });

    const res = await request(app)
      .post("/signup")
      .send({ email: "test@example.com", password: "password456" });

    expect(res.statusCode).toEqual(400);
    expect(res.body.error).toBe("User already exists");
  });
});

describe("POST /login", () => {
  beforeAll(async () => {
    const hashedPassword = await bcrypt.hash("password123", 10);
    db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [
      "login@example.com",
      hashedPassword,
    ]);
  });

  it("should log in a user and return a token", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "login@example.com", password: "password123" });

    expect(res.statusCode).toEqual(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.email).toBe("login@example.com");
  });

  it("should not log in with incorrect credentials", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "login@example.com", password: "wrongpassword" });

    expect(res.statusCode).toEqual(401);
    expect(res.body.error).toBe("Invalid credentials");
  });
});

describe("Referrals API", () => {
  let token;
  let userId;

  beforeAll(async () => {
    const hashedPassword = await bcrypt.hash("password123", 10);
    db.run(
      `INSERT INTO users (email, password) VALUES (?, ?)`,
      ["referral@example.com", hashedPassword],
      function () {
        userId = this.lastID;
        token = jwt.sign({ id: userId }, "your_jwt_secret", {
          expiresIn: "1h",
        });
      }
    );
  });

  it("should create a new referral", async () => {
    const res = await request(app).post("/referrals").send({
      userID: userId,
      referralEmail: "referral@example.com",
      referralDescription: "Great candidate",
    });

    expect(res.statusCode).toEqual(201);
    expect(res.body.message).toBe("Referral submitted");
  });

  it("should get all referrals", async () => {
    const res = await request(app).get("/referrals");

    expect(res.statusCode).toEqual(200);
    expect(res.body.length).toBeGreaterThan(0);
  });

  it("should update a referral", async () => {
    const res = await request(app).put("/referrals/1").send({
      referralEmail: "updated@example.com",
      description: "Updated description",
    });

    expect(res.statusCode).toEqual(200);
    expect(res.body.referralEmail).toBe("updated@example.com");
  });

  it("should delete a referral", async () => {
    const res = await request(app).delete("/referrals/1");
    expect(res.statusCode).toEqual(200);
    expect(res.body.message).toBe("Referral deleted");
  });
});
