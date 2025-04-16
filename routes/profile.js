const express = require('express');
const authenticate = require('../middleware/auth');
const db = require('../db'); // Import database connection
const router = express.Router();

// Get user profile
router.get('/', authenticate, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT username, email FROM users WHERE id = ?', [req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json(rows[0]);
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

module.exports = router;