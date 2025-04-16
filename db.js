require('dotenv').config(); // Load environment variables from .env
const mysql = require('mysql2'); // Import MySQL library

// Create a connection pool to manage multiple database connections
const pool = mysql.createPool({
  host: process.env.DB_HOST, // Database host
  user: process.env.DB_USER, // Database username
  password: process.env.DB_PASSWORD, // Database password
  database: process.env.DB_NAME, // Database name
  waitForConnections: true, // Wait for available connections
  connectionLimit: 10, // Maximum number of connections in the pool
  queueLimit: 0, // Unlimited queue for waiting connections
});

// Test the database connection
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err.stack); // Log connection error
    return;
  }
  console.log('Connected to the database.'); // Log successful connection
  connection.release(); // Release the connection back to the pool
});

module.exports = pool.promise(); // Export the connection pool with promise support