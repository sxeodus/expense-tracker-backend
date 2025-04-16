const express = require('express'); // Import Express framework
const router = express.Router(); // Create a router instance
const db = require('../db'); // Import database connection

// POST route to add a new transaction
router.post('/', async (req, res) => {
  const { type, amount, description } = req.body; // Extract transaction details from request body

  // Validate input
  if (!type || !description || isNaN(amount)) {
    return res.status(400).json({ error: 'Invalid input' }); // Return error if input is invalid
  }

  try {
    // Insert transaction into the database
    await db.query(
      'INSERT INTO transactions (type, amount, description) VALUES (?, ?, ?)',
      [type, amount, description]
    );
    res.status(201).json({ message: 'Transaction added' }); // Return success message
  } catch (error) {
    console.error(error); // Log database error
    res.status(500).json({ error: 'Database error' }); // Return error response
  }
});

// GET route to fetch all transactions
router.get('/', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM transactions'); // Fetch all transactions from the database
    res.status(200).json(rows); // Return the transactions as JSON
  } catch (error) {
    console.error(error); // Log database error
    res.status(500).json({ error: 'Database error' }); // Return error response
  }
});

module.exports = router; // Export the router