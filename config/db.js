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
  // For local development or production using individual .env variables
  const isProduction = process.env.NODE_ENV === 'production';
  console.log(isProduction ? "Connecting to production database..." : "Connecting to local database...");
  pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    // Only enable SSL in production if DB_SSL is explicitly set to 'true'
    ssl: isProduction && process.env.DB_SSL === 'true' ? { rejectUnauthorized: true } : undefined
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
    // Allow the application to fail gracefully if the DB isn't available.
    // Render will show this in the logs and the deployment will fail as expected.
    throw err;
  });

module.exports = pool;