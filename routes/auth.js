const express = require("express");
const router = express.Router();
const pool = require("../config/db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { body, validationResult } = require("express-validator");
const { OAuth2Client } = require("google-auth-library");
const verifyToken = require("../middleware/authMiddleware");
require("dotenv").config();

// Register
router.post(
  "/register",
  [
    body("firstname").isString().trim().notEmpty().withMessage("First name is required"),
    body("lastname").isString().trim().notEmpty().withMessage("Last name is required"),
    body("username").isString().trim().notEmpty().withMessage("Username is required"),
    body("email").isEmail().withMessage("Please provide a valid email"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
    body("budget").isNumeric().withMessage("Budget must be a number"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { firstname, lastname, username, email, password, budget } = req.body;
    try {
      const [existingUser] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
      if (existingUser.length > 0)
        return res.status(400).json({ message: "User with this email already exists" });

      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query(
        "INSERT INTO users (firstname, lastname, username, email, password, budget) VALUES (?, ?, ?, ?, ?, ?)",
        [firstname, lastname, username, email, hashedPassword, budget]
      );
      res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Login
router.post(
  "/login",
  [
    body("email").isEmail().withMessage("Please provide a valid email"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    try {
      const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
      const user = users[0];
      if (!user) return res.status(401).json({ message: "Invalid credentials" });

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword)
        return res.status(401).json({ message: "Invalid credentials" });

      // Create short-lived Access Token
      const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "15m" });

      // Create long-lived Refresh Token
      const refreshToken = crypto.randomBytes(64).toString("hex");
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      // Store refresh token in the database
      await pool.query("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)", [user.id, refreshToken, expiresAt]);

      // Send refresh token in a secure, httpOnly cookie
      res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: process.env.NODE_ENV === "production", expires: expiresAt });

      res.json({
        token: accessToken,
        user: { id: user.id, firstname: user.firstname, lastname: user.lastname, username: user.username, email: user.email, budget: user.budget },
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Google Login
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

router.post(
  "/google-login",
  [body("credential").notEmpty().withMessage("Google credential token is required")],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { credential } = req.body;
    try {
      const ticket = await client.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      const { email, given_name, family_name } = payload;

      let user;
      const [existingUsers] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);

      if (existingUsers.length > 0) {
        user = existingUsers[0];
      } else {
        const randomPassword = crypto.randomBytes(16).toString('hex');
        const hashedPassword = await bcrypt.hash(randomPassword, 10);
        const username = email.split('@')[0] + Math.floor(Math.random() * 1000);

        const [result] = await pool.query(
          "INSERT INTO users (firstname, lastname, username, email, password, budget) VALUES (?, ?, ?, ?, ?, ?)",
          [given_name || 'Google', family_name || 'User', username, email, hashedPassword, 0]
        );
        const [newUsers] = await pool.query("SELECT * FROM users WHERE id = ?", [result.insertId]);
        user = newUsers[0];
      }

      // Issue our own application tokens
      const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "15m" });
      const refreshToken = crypto.randomBytes(64).toString("hex");
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      await pool.query("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)", [user.id, refreshToken, expiresAt]);

      res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: process.env.NODE_ENV === "production", expires: expiresAt });

      res.json({
        token: accessToken,
        user: { id: user.id, firstname: user.firstname, lastname: user.lastname, username: user.username, email: user.email, budget: user.budget },
      });
    } catch (error) {
      console.error("Google login error:", error);
      res.status(401).json({ message: "Google Sign-In failed. Please try again." });
    }
  }
);

// New endpoint to refresh the access token
router.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token not found." });
  }

  try {
    const [rows] = await pool.query(
      "SELECT * FROM refresh_tokens WHERE token = ?",
      [refreshToken]
    );
    const tokenData = rows[0];

    if (!tokenData || new Date() > new Date(tokenData.expires_at)) {
      await pool.query("DELETE FROM refresh_tokens WHERE token = ?", [refreshToken]);
      res.clearCookie("refreshToken");
      return res.status(403).json({ message: "Invalid or expired refresh token." });
    }

    // Token is valid, issue a new access token
    const newAccessToken = jwt.sign(
      { id: tokenData.user_id },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ token: newAccessToken });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Profile
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, firstname, lastname, username, email, budget FROM users WHERE id = ?",
      [req.user.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error("Failed to load profile:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Change budget
router.put(
  "/budget",
  verifyToken,
  [body("budget").isNumeric().withMessage("Budget must be a number")],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { budget } = req.body;
    try {
      await pool.query("UPDATE users SET budget = ? WHERE id = ?", [
        budget,
        req.user.id,
      ]);
      res.json({ message: "Budget updated successfully", budget });
    } catch (error) {
      console.error("Failed to update budget:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Delete user and their transactions
router.delete("/delete", verifyToken, async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id = ?", [req.user.id]);
    // Refresh tokens and transactions are deleted automatically due to ON DELETE CASCADE
    res.clearCookie("refreshToken").json({ message: "Account deleted successfully" });
  } catch (error) {
    console.error("Failed to delete account:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Logout - Now stateful and meaningful
router.post("/logout", async (req, res) => {
  const { refreshToken } = req.cookies;
  if (refreshToken) {
    try {
      // Delete the refresh token from the database
      await pool.query("DELETE FROM refresh_tokens WHERE token = ?", [refreshToken]);
    } catch (error) {
      // Log the error but don't prevent logout
      console.error("Error deleting refresh token:", error);
    }
  }
  res.clearCookie("refreshToken").status(200).json({ message: "Logged out successfully" });
});

module.exports = router;
