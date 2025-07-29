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

// Trust the first proxy in front of the app. This is necessary for services like Render.
// It allows express-rate-limit to correctly identify the user's IP address.
app.set('trust proxy', 1);

// --- Production Security Setup ---

// Set security HTTP headers. It's a good practice to use helmet for security.
// The default Cross-Origin-Opener-Policy (COOP) of 'same-origin' can block
// Google's OAuth popup from communicating with your app. We relax it here.
app.use(helmet({
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  // Setting COEP to false is often necessary for Google Sign-In to work smoothly.
  crossOriginEmbedderPolicy: false,
}));

// --- CORS Configuration ---
// Define a whitelist of allowed origins. We'll get these from environment variables.
const whitelist = [
  process.env.FRONTEND_URL,         // Your deployed Netlify site URL
  process.env.CUSTOM_DOMAIN_URL,    // Your custom domain e.g., https://segunodumeso.site
  'http://localhost:3000'           // For local development
].filter(Boolean); // This removes any undefined entries if the env vars aren't set

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests) or from our whitelist
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
};
app.use(cors(corsOptions));

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

// --- Global Error Handler ---
// This should be the last middleware. It catches any unhandled errors from your routes.
app.use((err, req, res, next) => {
  console.error(`--- UNHANDLED ERROR: ${req.method} ${req.originalUrl} ---`);
  console.error(err.stack);
  // Avoid sending stack trace to the client in production
  res.status(500).json({ message: 'An unexpected error occurred on the server.' });
});

app.listen(PORT, () => {
  console.log(`Server started successfully on port ${PORT}`);
});