// middleware/wafVerification.js
const crypto = require("crypto");

module.exports = (req, res, next) => {
  const secret = process.env.WAF_SHARED_SECRET;
  if (!secret) {
    console.error("CRITICAL: WAF_SHARED_SECRET is not configured in .env");
    return res.status(500).json({ error: "Internal WAF Configuration Error" });
  }

  const timestamp = Date.now().toString();
  
  // Create a cryptographic signature combining the method, path, and timestamp
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(`${req.method}:${req.originalUrl}:${timestamp}`);
  const signature = hmac.digest("hex");

  // Pass these tokens along to the backend
  req.headers["x-waf-timestamp"] = timestamp;
  req.headers["x-waf-signature"] = signature;

  console.log(`✓ Request signed securely by WAF. Timestamp: ${timestamp}`);
  next();
};