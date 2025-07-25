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
    // For services like Railway that use self-signed certs, we must disable strict validation by setting rejectUnauthorized to false.
    ssl: {
      rejectUnauthorized: false
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
    // Add a configurable connection timeout. Render can sometimes have slower network.
    connectTimeout: parseInt(process.env.DB_CONNECT_TIMEOUT) || (isProduction ? 20000 : 10000),
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
    // Provide more specific advice for common errors.
    if (err.code === 'ETIMEDOUT') {
        console.error("Error connecting to MySQL: Connection Timed Out.");
        console.error("This is likely a firewall issue. Please ensure your database host allows remote connections from all IPs (using the '%' wildcard). Look for a 'Remote MySQL' setting in your control panel.");
    } else if (err.code === 'ENOTFOUND') {
        console.error(`Error connecting to MySQL: Hostname not found. Check if the DB_HOST environment variable ('${process.env.DB_HOST}') is correct.`);
    } else {
        console.error("Error connecting to MySQL:", err.message);
    }
    // Allow the application to fail gracefully if the DB isn't available.
    // Render will show this in the logs and the deployment will fail as expected.
    throw err;
  });

module.exports = pool;