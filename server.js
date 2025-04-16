require('dotenv').config(); // Load environment variables from .env
const express = require('express'); // Import Express framework
const cors = require('cors'); // Import CORS middleware to handle cross-origin requests
const db = require('./db'); // Import database connection
const transactionsRoutes = require('./routes/transactions'); // Import transaction routes
const authRoutes = require('./routes/auth'); // Import auth routes
const profileRoutes = require('./routes/profile'); // Import profile routes

const app = express(); // Initialize Express app

// Debug: Log environment variables to ensure they are loaded correctly
console.log('Environment Variables:', {
  DB_HOST: process.env.DB_HOST,
  DB_USER: process.env.DB_USER,
  DB_PASSWORD: process.env.DB_PASSWORD ? '******' : 'Not Set',
  DB_NAME: process.env.DB_NAME,
});

// Check for missing environment variables and exit if any are missing
if (!process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_NAME) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// Middleware
app.use(cors()); // Enable cross-origin requests
app.use(express.json()); // Parse incoming JSON request bodies

// Routes
app.use('/api/transactions', transactionsRoutes); // Mount transaction routes at /api/transactions
app.use('/api/auth', authRoutes); // Authentication routes
app.use('/api/profile', profileRoutes); // Profile routes

// Test route to verify the server is running
app.get('/', (req, res) => {
  res.send('Expense Tracker API is running...');
});

// Global error-handling middleware to catch unhandled errors
app.use((err, req, res, next) => {
  console.error(err.stack); // Log the error stack trace
  res.status(500).send({ error: 'Something went wrong!' }); // Send a generic error response
});

// Start the server on the specified port
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Graceful shutdown to close the database connection when the server stops
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  db.end((err) => {
    if (err) console.error('Error closing database connection:', err.stack);
    else console.log('Database connection closed.');
    process.exit(0);
  });
});