const { validationResult } = require("express-validator");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const db = require("../config/db");
const sendEmail = require("../utils/sendEmail");
const generateToken = require("../utils/generateToken");

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

exports.register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: errors.array()[0].msg });
  }

  const { firstname, lastname, username, email, password, budget } = req.body;

  try {
    const [existingUsers] = await db.query(
      "SELECT * FROM users WHERE email = ? OR username = ?",
      [email, username]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({ message: "User with this email or username already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const [result] = await db.query(
      "INSERT INTO users (firstname, lastname, username, email, password_hash, budget) VALUES (?, ?, ?, ?, ?, ?)",
      [firstname, lastname, username, email, password_hash, budget || null]
    );

    const token = await generateToken(result.insertId);
    res.status(201).json({ token });

  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
};

exports.login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: errors.array()[0].msg });
  }

  const { email, password } = req.body;

  try {
    const [users] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    if (users.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const user = users[0];

    if (!user.password_hash) {
      return res.status(400).json({ message: "This account was created with Google. Please sign in with Google." });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = await generateToken(user.id);
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
};

exports.googleLogin = async (req, res) => {
  const { credential } = req.body;
  if (!credential) {
    return res.status(400).json({ message: "Google credential token is required." });
  }

  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const { email, given_name, family_name, name } = ticket.getPayload();

    let [users] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    let user = users[0];

    let isNewUser = false;
    if (!user) {
      isNewUser = true;
      // If the user doesn't exist, create them.
      // We must ensure the username (which we default to the email) is unique.
      let username = email;
      const [existingUserByUsername] = await db.query("SELECT id FROM users WHERE username = ?", [username]);

      if (existingUserByUsername.length > 0) {
        // If username is taken, append a short random string to the part before the @.
        username = `${username.split('@')[0]}_${crypto.randomBytes(3).toString('hex')}`;
      }

      // Use fallback values if given_name or family_name are not provided by Google.
      const firstName = given_name || (name ? name.split(' ')[0] : email.split('@')[0]);
      const lastName = family_name || (name ? name.split(' ').slice(1).join(' ') : '');

      const [result] = await db.query(
        "INSERT INTO users (firstname, lastname, email, username) VALUES (?, ?, ?, ?)",
        [firstName, lastName, email, username]
      );
      user = { id: result.insertId };
    }

    // Fetch the full user profile to return to the client
    const [finalUserResult] = await db.query(
      "SELECT id, firstname, lastname, username, email, budget FROM users WHERE id = ?",
      [user.id]
    );
    const finalUser = finalUserResult[0];

    const token = await generateToken(user.id);
    
    // Return both token and user profile
    res.status(isNewUser ? 201 : 200).json({ token, user: finalUser });
  } catch (error) {
    console.error("Google login error:", error);
    res.status(500).json({ message: "Google authentication failed" });
  }
};

exports.getProfile = async (req, res) => {
  try {
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
};

exports.updateProfile = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { firstname, lastname, username } = req.body;
  const userId = req.user.id;

  try {
    const [existingUser] = await db.query("SELECT id FROM users WHERE username = ? AND id != ?", [username, userId]);
    if (existingUser.length > 0) {
      return res.status(409).json({ msg: "Username is already taken" });
    }

    await db.query("UPDATE users SET firstname = ?, lastname = ?, username = ? WHERE id = ?", [firstname, lastname, username, userId]);

    const [updatedUsers] = await db.query("SELECT id, firstname, lastname, username, email, budget FROM users WHERE id = ?", [userId]);

    res.json(updatedUsers[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
};

exports.updateBudget = async (req, res) => {
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
};

exports.forgotPassword = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { email } = req.body;

    try {
        const [users] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
        if (users.length === 0) {
            return res.status(200).json({ message: 'If a user with that email exists, a password reset link has been sent.' });
        }
        const user = users[0];

        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        const tokenExpiry = Date.now() + 10 * 60 * 1000;
        await db.query("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?", [hashedToken, new Date(tokenExpiry), user.id]);

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
        const emailHtml = `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2>Password Reset Request</h2>
            <p>Hello ${user.firstname || 'there'},</p>
            <p>You are receiving this email because a password reset request was made for your account.</p>
            <p>Please click on the button below to reset your password. This link is valid for 10 minutes.</p>
            <a href="${resetUrl}" style="background-color: #4CAF50; color: white; padding: 14px 25px; text-align: center; text-decoration: none; display: inline-block; border-radius: 5px;" clicktracking=off>Reset Password</a>
            <p>If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
            <p>Thank you,<br>The Expense Tracker Team</p>
            <hr style="border: none; border-top: 1px solid #eee;" />
            <p style="font-size: 0.8em; color: #777;">If you're having trouble clicking the button, copy and paste this URL into your web browser:<br><a href="${resetUrl}" clicktracking=off>${resetUrl}</a></p>
        </div>`;

        await sendEmail({ email: user.email, subject: 'Password Reset Request', html: emailHtml });
        res.status(200).json({ message: 'If a user with that email exists, a password reset link has been sent.' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

exports.resetPassword = async (req, res) => {
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
};

exports.deleteAccount = async (req, res) => {
  const userId = req.user.id;
  try {
    await db.query("DELETE FROM users WHERE id = ?", [userId]);
    res.json({ msg: "User account deleted successfully." });
  } catch (err) {
    console.error("Error deleting user account:", err.message);
    res.status(500).send("Server Error");
  }
};

exports.logout = (req, res) => {
  res.status(200).json({ message: "Logout successful" });
};
