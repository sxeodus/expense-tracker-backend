const express = require("express");
const router = express.Router();
const authMiddleware = require("../middleware/authMiddleware");
const db = require("../config/db");
const { check, validationResult } = require("express-validator");

// @route   GET api/transactions
// @desc    Get all transactions (expenses and incomes) for a user
// @access  Private
router.get("/", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    // This query combines expenses and incomes into a single list
    const query = `
      (
        SELECT id, amount, description, 'expense' as type, category, expense_date as date, created_at, updated_at
        FROM expenses
        WHERE user_id = ?
      )
      UNION ALL
      (
        SELECT id, amount, description, 'income' as type, 'Income' as category, income_date as date, created_at, updated_at
        FROM incomes
        WHERE user_id = ?
      )
      ORDER BY date DESC, created_at DESC;
    `;

    const [transactions] = await db.query(query, [userId, userId]);
    res.json(transactions); // This now returns an array, which will fix the crash!
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// @route   POST api/transactions
// @desc    Add a new transaction (expense or income)
// @access  Private
router.post(
  "/",
  [
    authMiddleware,
    [
      check("type", "Type is required").isIn(["income", "expense"]),
      check("amount", "Amount must be a positive number").isFloat({ gt: 0 }),
      check("description", "Description is required").not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { type, amount, description, category } = req.body;
    const userId = req.user.id;
    const date = new Date(); // Use current date for simplicity

    try {
      let result;
      let newTransaction;

      if (type === "income") {
        [result] = await db.query(
          "INSERT INTO incomes (user_id, amount, description, income_date) VALUES (?, ?, ?, ?)",
          [userId, amount, description, date]
        );
        newTransaction = { id: result.insertId, type, amount, description, category: 'Income', date, created_at: date, updated_at: date };
      } else { // type === 'expense'
        const finalCategory = category.trim() || "General";
        [result] = await db.query(
          "INSERT INTO expenses (user_id, amount, description, category, expense_date) VALUES (?, ?, ?, ?, ?)",
          [userId, amount, description, finalCategory, date]
        );
        newTransaction = { id: result.insertId, type, amount, description, category: finalCategory, date, created_at: date, updated_at: date };
      }

      res.status(201).json({ transaction: newTransaction });
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server Error");
    }
  }
);

// @route   PUT api/transactions/:id
// @desc    Update a transaction
// @access  Private
router.put("/:id", authMiddleware, async (req, res) => {
    const { type, amount, description, category } = req.body;
    const { id } = req.params;
    const userId = req.user.id;

    try {
        let query;
        let params;

        if (type === 'expense') {
            query = `UPDATE expenses SET amount = ?, description = ?, category = ? WHERE id = ? AND user_id = ?`;
            params = [amount, description, category || 'General', id, userId];
        } else { // type === 'income'
            query = `UPDATE incomes SET amount = ?, description = ? WHERE id = ? AND user_id = ?`;
            params = [amount, description, id, userId];
        }

        // The 'updated_at' column will be updated automatically by MySQL
        const [result] = await db.query(query, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ msg: "Transaction not found or user not authorized" });
        }

        const updatedTransaction = { id: parseInt(id), type, amount, description, category, date: new Date() };
        res.json({ transaction: updatedTransaction });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

// @route   DELETE api/transactions/:id
// @desc    Delete a transaction
// @access  Private
router.delete("/:id", authMiddleware, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        // We need to try deleting from both tables since we don't know the type
        const [expenseResult] = await db.query("DELETE FROM expenses WHERE id = ? AND user_id = ?", [id, userId]);
        if (expenseResult.affectedRows > 0) {
            return res.json({ msg: "Transaction removed" });
        }

        const [incomeResult] = await db.query("DELETE FROM incomes WHERE id = ? AND user_id = ?", [id, userId]);
        if (incomeResult.affectedRows > 0) {
            return res.json({ msg: "Transaction removed" });
        }

        return res.status(404).json({ msg: "Transaction not found or user not authorized" });

    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

module.exports = router;