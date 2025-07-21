const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const authRoutes = require("./routes/auth");
const transactionRoutes = require("./routes/transactions");
const cron = require("node-cron");
const { sendMonthlyReports } = require("./services/reportingService");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// --- Production Security Setup ---

// Set security HTTP headers. It's a good practice to use helmet for security.
app.use(helmet());

// Configure CORS for your live frontend on Netlify and local development
const allowedOrigins = ['http://localhost:3000', 'https://your-netlify-app-name.netlify.app']; // IMPORTANT: Replace with your actual Netlify URL
app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
}));

// Rate limiting to prevent brute-force attacks
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }); // 100 requests per 15 minutes
app.use('/api', limiter); // Apply to all API routes

app.use(express.json());
app.use(cookieParser());

app.use("/api/auth", authRoutes);
app.use("/api/transactions", transactionRoutes);

// Schedule the monthly report job.
// This cron expression '0 0 1 * *' means "at 00:00 on day-of-month 1".
cron.schedule("0 0 1 * *", () => {
  console.log("Running monthly report job...");
  sendMonthlyReports();
}, {
  scheduled: true,
  timezone: "UTC" // Use UTC to avoid timezone issues
});

app.get("/", (req, res) => {
  res.send("API is running...");
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});