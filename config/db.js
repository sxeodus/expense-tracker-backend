const mysql = require("mysql2/promise");
require("dotenv").config();

let pool;

// For production environments like Render/PlanetScale that provide a DATABASE_URL
if (process.env.DATABASE_URL) {
  console.log("Connecting to production database via DATABASE_URL...");
  pool = mysql.createPool({
    uri: process.env.DATABASE_URL,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    // PlanetScale and other modern providers require a secure SSL connection
    ssl: {
      rejectUnauthorized: true,
    },
  });
} else {
  // For local development using individual .env variables
  console.log("Connecting to local database...");
  pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    // Add SSL for production environments like AlwaysData
    // Render sets NODE_ENV to 'production' automatically.
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined
  });
}

// A quick test to see if the connection is successful when the server starts
pool
  .getConnection()
  .then((connection) => {
    console.log("MySQL Database connected successfully.");
    connection.release();
  })
  .catch((err) => {
    console.error("Error connecting to MySQL:", err.message);
    // Exit the process with a failure code if we can't connect to the DB
    process.exit(1);
  });

module.exports = pool;