const express = require("express");
const router = express.Router();
const pool = require("../config/db");
const verifyToken = require("../middleware/authMiddleware");const { body, validationResult } = require('express-validator');

router.use(verifyToken);

// ✅ Get all transactions for the logged-in user
router.get("/", async (req, res) => {
  const userId = req.user.id;
  try {
    const [transactions] = await pool.query(
      "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC",
      [userId]
    );
    res.json(transactions);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch transactions", error });
  }
});

// ✅ Create a new transaction
router.post("/", async (req, res) => {
  const userId = req.user.id;
  const { type, amount, description, category } = req.body;

  // Input Validation
  await Promise.all([
    body('type').isIn(['income', 'expense']).withMessage('Type must be income or expense').run(req),
    body('amount').isNumeric().withMessage('Amount must be a number').run(req),
    body('description').isString().trim().notEmpty().withMessage('Description is required').run(req),
    body('category').optional().isString().trim().run(req), // Category is optional but must be a string if provided
  ]);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const [result] = await pool.query(
      "INSERT INTO transactions (user_id, type, amount, description, category) VALUES (?, ?, ?, ?, ?)",
      [userId, type, amount, description, category || "General"] // Default category
    );

    // Fetch the inserted transaction with timestamps
    const [newTransaction] = await pool.query("SELECT * FROM transactions WHERE id = ?", [result.insertId]);

    res.status(201).json({ message: "Transaction added successfully", transaction: newTransaction[0] });
  } catch (error) {
    res.status(500).json({ message: "Failed to add transaction", error });
  }
});

// ✅ Update an existing transaction
router.put("/:id", async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;
  const { type, amount, description, category } = req.body;

  try {
    await pool.query(
      "UPDATE transactions SET type=?, amount=?, description=?, category=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?",
      [type, amount, description, category, id, userId]
    );

    const [updated] = await pool.query("SELECT * FROM transactions WHERE id = ?", [id]);

    res.status(200).json({ message: "Transaction updated", transaction: updated[0] });
  } catch (error) {
    res.status(500).json({ message: "Failed to update transaction", error });
  }
});

// ✅ Delete a transaction
router.delete("/:id", async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;

  try {
    await pool.query("DELETE FROM transactions WHERE id = ? AND user_id = ?", [id, userId]);
    res.status(200).json({ message: "Transaction deleted" });
  } catch (error) {
    res.status(500).json({ message: "Failed to delete transaction", error });
  }
});

module.exports = router;
