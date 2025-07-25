const express = require("express");
const router = express.Router();
const { check, validationResult } = require("express-validator");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const db = require("../config/db"); // Import the database connection pool
const authMiddleware = require("../middleware/authMiddleware");
const sendEmail = require("../utils/sendEmail");

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// @route   POST api/auth/register
// @desc    Register a new user
// @access  Public
router.post(
  "/register",
  [
    // --- Input Validation ---
    check("firstname", "First name is required").not().isEmpty(),
    check("lastname", "Last name is required").not().isEmpty(),
    check("username", "Username is required").not().isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // Return the first validation error message for simplicity
      return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { firstname, lastname, username, email, password, budget } = req.body;

    try {
      // 1. Check if user already exists
      const [existingUsers] = await db.query(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        [email, username]
      );

      if (existingUsers.length > 0) {
        return res.status(409).json({ message: "User with this email or username already exists" });
      }

      // 2. Hash the password
      const salt = await bcrypt.genSalt(10);
      const password_hash = await bcrypt.hash(password, salt);

      // 3. Save the user to the database
      const [result] = await db.query(
        "INSERT INTO users (firstname, lastname, username, email, password_hash, budget) VALUES (?, ?, ?, ?, ?, ?)",
        [firstname, lastname, username, email, password_hash, budget || null]
      );

      const newUser = {
        id: result.insertId,
        username,
        email,
      };

      // 4. Create and sign a JWT to log the user in
      const payload = {
        user: {
          id: newUser.id,
        },
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: "5h" }, // Token expires in 5 hours
        (err, token) => {
          if (err) throw err;
          // 5. Send success response with the token
          res.status(201).json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// @route   POST api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post(
  "/login",
  [
    check("email", "Please include a valid email").isEmail(),
    check("password", "Password is required").exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { email, password } = req.body;

    try {
      // 1. Find user by email
      const [users] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
      if (users.length === 0) {
        return res.status(400).json({ message: "Invalid credentials" });
      }
      const user = users[0];

      // For Google-based users who try to log in manually
      if (!user.password_hash) {
        return res.status(400).json({ message: "This account was created with Google. Please sign in with Google." });
      }

      // 2. Compare password
      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      // 3. Create and return JWT
      const payload = { user: { id: user.id } };
      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: "5h" },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// @route   POST api/auth/google-login
// @desc    Authenticate or register user with Google
// @access  Public
router.post("/google-login", async (req, res) => {
  const { credential } = req.body; // This is the token from the frontend
  if (!credential) {
    return res.status(400).json({ message: "Google credential token is required." });
  }

  try {
    // 1. Verify the Google token
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const { email, given_name, family_name } = ticket.getPayload();

    // 2. Check if user exists
    let [users] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    let user = users[0];

    if (!user) {
      // 3a. User doesn't exist, create a new one
      // We use the email as the username for simplicity for Google users.
      const [result] = await db.query(
        "INSERT INTO users (firstname, lastname, email, username) VALUES (?, ?, ?, ?)",
        [given_name, family_name, email, email]
      );
      user = { id: result.insertId, email };
    }

    // 4. User exists or was just created, create JWT
    const payload = { user: { id: user.id } };
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "5h" },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (error) {
    console.error("Google login error:", error);
    res.status(500).json({ message: "Google authentication failed" });
  }
});

// @route   GET api/auth/me
// @desc    Get current logged-in user's profile
// @access  Private
router.get("/me", authMiddleware, async (req, res) => {
  try {
    // req.user.id is attached by the authMiddleware
    const [users] = await db.query(
      "SELECT id, firstname, lastname, username, email, budget FROM users WHERE id = ?",
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ msg: "User not found" });
    }

    res.json(users[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// @route   PUT api/auth/budget
// @desc    Update user's budget
// @access  Private
router.put("/budget", authMiddleware, async (req, res) => {
  const { budget } = req.body;
  const userId = req.user.id;

  if (budget === undefined || isNaN(parseFloat(budget)) || parseFloat(budget) < 0) {
    return res.status(400).json({ msg: "Please provide a valid, non-negative budget." });
  }

  try {
    await db.query("UPDATE users SET budget = ? WHERE id = ?", [parseFloat(budget), userId]);
    res.json({ budget: parseFloat(budget) });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// @route   PUT api/auth/me
// @desc    Update user profile information (firstname, lastname, username)
// @access  Private
router.put(
  "/me",
  [
    authMiddleware,
    [
      check("firstname", "First name is required").not().isEmpty(),
      check("lastname", "Last name is required").not().isEmpty(),
      check("username", "Username is required").not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { firstname, lastname, username } = req.body;
    const userId = req.user.id;

    try {
      // Check if the new username is already taken by another user
      const [existingUser] = await db.query("SELECT id FROM users WHERE username = ? AND id != ?", [username, userId]);
      if (existingUser.length > 0) {
        return res.status(409).json({ msg: "Username is already taken" });
      }

      // Update user in the database
      await db.query("UPDATE users SET firstname = ?, lastname = ?, username = ? WHERE id = ?", [firstname, lastname, username, userId]);

      // Fetch the updated user to return it
      const [updatedUsers] = await db.query("SELECT id, firstname, lastname, username, email, budget FROM users WHERE id = ?", [userId]);

      res.json(updatedUsers[0]);
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server Error");
    }
  }
);

// @route   POST api/auth/forgot-password
// @desc    Request password reset link
// @access  Public
router.post('/forgot-password', [
    check('email', 'Please include a valid email').isEmail()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { email } = req.body;

    try {
        const [users] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
        if (users.length === 0) {
            // To prevent email enumeration, we send a success-like response even if the user doesn't exist.
            return res.status(200).json({ message: 'If a user with that email exists, a password reset link has been sent.' });
        }
        const user = users[0];

        // 1. Generate a random reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        // 2. Set token and expiry on the user record (token valid for 10 minutes)
        const tokenExpiry = Date.now() + 10 * 60 * 1000;
        await db.query("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?", [hashedToken, new Date(tokenExpiry), user.id]);

        // 3. Create reset URL and send email
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
        const emailHtml = `
            <h1>You have requested a password reset</h1>
            <p>Please click on the link below to reset your password:</p>
            <a href="${resetUrl}" clicktracking=off>${resetUrl}</a>
            <p>This link will expire in 10 minutes.</p>
            <p>If you did not request this, please ignore this email.</p>
        `;

        try {
            await sendEmail({
                email: user.email,
                subject: 'Password Reset Request',
                html: emailHtml
            });
            res.status(200).json({ message: 'If a user with that email exists, a password reset link has been sent.' });
        } catch (err) {
            console.error('Email sending error:', err);
            // In case of email error, clear the token from DB to allow user to try again
            await db.query("UPDATE users SET reset_token = NULL, reset_token_expiry = NULL WHERE id = ?", [user.id]);
            res.status(500).json({ message: 'Error sending email. Please try again later.' });
        }

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST api/auth/reset-password/:token
// @desc    Reset password using token
// @access  Public
router.post('/reset-password/:token', [
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ message: errors.array()[0].msg });
    }

    try {
        const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
        const [users] = await db.query("SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()", [hashedToken]);

        if (users.length === 0) {
            return res.status(400).json({ message: 'Token is invalid or has expired.' });
        }
        const user = users[0];

        const { password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);

        await db.query("UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?", [password_hash, user.id]);
        res.status(200).json({ message: 'Password has been reset successfully.' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   DELETE api/auth/delete
// @desc    Delete user account and all associated data
// @access  Private
router.delete("/delete", authMiddleware, async (req, res) => {
  const userId = req.user.id;

  try {
    // The ON DELETE CASCADE in the database schema will handle deleting
    // associated expenses, incomes, and categories automatically.
    await db.query("DELETE FROM users WHERE id = ?", [userId]);

    res.json({ msg: "User account deleted successfully." });
  } catch (err) {
    console.error("Error deleting user account:", err.message);
    res.status(500).send("Server Error");
  }
});

// @route   GET api/auth/logout
// @desc    Logout user
router.get("/logout", (req, res) => {
  res.cookie("token", "", {
    httpOnly: true,
    expires: new Date(0),
  });
  res.send("User logged out");
});

module.exports = router;