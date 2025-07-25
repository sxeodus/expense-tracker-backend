const jwt = require("jsonwebtoken");
require("dotenv").config();

function authMiddleware(req, res, next) {
  // Get token from the Authorization header
  const authHeader = req.header("Authorization");

  // Check if no token is present or if it's not a Bearer token
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ msg: "No token, authorization denied" });
  }

  try {
    // Extract the token from "Bearer <token>"
    const token = authHeader.split(" ")[1];

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user; // Add user payload to the request object
    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    // This will catch expired tokens or invalid signatures
    console.error("Token verification failed:", err.message);
    res.status(401).json({ msg: "Token is not valid or has expired" });
  }
}

module.exports = authMiddleware;