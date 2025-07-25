const express = require("express");
const router = express.Router();
const { check } = require("express-validator");
const authMiddleware = require("../middleware/authMiddleware");
const authController = require("../controllers/authController");

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
  authController.register
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
  authController.login
);

// @route   POST api/auth/google-login
// @desc    Authenticate or register user with Google
// @access  Public
router.post("/google-login", authController.googleLogin);

// @route   GET api/auth/me
// @desc    Get current logged-in user's profile
// @access  Private
router.get("/me", authMiddleware, authController.getProfile);

// @route   PUT api/auth/budget
// @desc    Update user's budget
// @access  Private
router.put("/budget", authMiddleware, authController.updateBudget);

// @route   PUT api/auth/me
// @desc    Update user profile information (firstname, lastname, username)
// @access  Private
router.put(
  "/me",
  authMiddleware,
  [
    check("firstname", "First name is required").not().isEmpty(),
    check("lastname", "Last name is required").not().isEmpty(),
    check("username", "Username is required").not().isEmpty(),
  ],
  authController.updateProfile
);

// @route   POST api/auth/forgot-password
// @desc    Request password reset link
// @access  Public
router.post(
  "/forgot-password",
  [check("email", "Please include a valid email").isEmail()],
  authController.forgotPassword
);

// @route   POST api/auth/reset-password/:token
// @desc    Reset password using token
// @access  Public
router.post(
  "/reset-password/:token",
  [check("password", "Please enter a password with 6 or more characters").isLength({ min: 6 })],
  authController.resetPassword
);

// @route   DELETE api/auth/delete
// @desc    Delete user account and all associated data
// @access  Private
router.delete("/delete", authMiddleware, authController.deleteAccount);

// @route   POST api/auth/logout
// @desc    Logout user (this endpoint is called by the frontend to signal logout)
// @access  Public
router.post("/logout", authController.logout);

module.exports = router;