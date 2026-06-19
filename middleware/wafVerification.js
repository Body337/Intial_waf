// middleware/wafVerification.js
const crypto = require("crypto");

module.exports = (req, res, next) => {
  const secret = process.env.WAF_SHARED_SECRET;
  if (!secret) {
    console.error("CRITICAL: WAF_SHARED_SECRET is not configured in .env");
    return res.status(500).json({ error: "Internal WAF Configuration Error" });
  }

  // Resolve the verified IP at the WAF perimeter
  const clientIp = req.headers["x-forwarded-for"] 
    ? req.headers["x-forwarded-for"].split(",")[0].trim() 
    : req.ip;

  const timestamp = Date.now().toString();
  
  // Include clientIp inside the signed data string!
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(`${req.method}:${req.originalUrl}:${timestamp}:${clientIp}`);
  const signature = hmac.digest("hex");

  // Pass tokens forward
  req.headers["x-waf-timestamp"] = timestamp;
  req.headers["x-waf-signature"] = signature;
  req.headers["x-waf-client-ip"] = clientIp; // The backend reads this securely

  console.log(`✓ Request signed with client IP: ${clientIp}`);
  next();
};