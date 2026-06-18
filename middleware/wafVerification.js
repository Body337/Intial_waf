// middleware/secureHeaderForwarder.js
const crypto = require("crypto");

module.exports = (req, res, next) => {
  const sharedSecret = process.env.WAF_SHARED_SECRET || "super-secret-key-change-me";

  const headerData = {
    method: req.method,
    originalUrl: req.originalUrl,
    timestamp: new Date().toISOString(),
    clientIp: req.ip,
  };

  const payloadBase64 = Buffer.from(JSON.stringify(headerData)).toString("base64");
  
  // Create an HMAC signature to prove authenticity
  const signature = crypto
    .createHmac("sha256", sharedSecret)
    .update(payloadBase64)
    .digest("hex");

  // Combine payload and signature: payload.signature
  req.headers["x-waf-forward"] = `${payloadBase64}.${signature}`;

  next();
};