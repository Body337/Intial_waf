// middleware/rateLimiter.js

// Maps: clientIp -> { count: number, resetTime: number }
const ipCache = new Map();

const WINDOW_MS = 60 * 1000; // 1 minute window
const MAX_REQUESTS = 20;     // Max requests per window allowed by WAF

module.exports = (req, res, next) => {
  // Extract real client IP (handling reverse proxy deployments like Railway/Vercel)
  const clientIp = req.headers["x-forwarded-for"] 
    ? req.headers["x-forwarded-for"].split(",")[0].trim() 
    : req.ip;

  const now = Date.now();
  
  if (!ipCache.has(clientIp)) {
    // New IP tracking entry
    ipCache.set(clientIp, {
      count: 1,
      resetTime: now + WINDOW_MS
    });
    return next();
  }

  const record = ipCache.get(clientIp);

  // If the window has expired, reset the counter
  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + WINDOW_MS;
    return next();
  }

  // Increment request count
  record.count++;

  // Check if threshold exceeded
  if (record.count > MAX_REQUESTS) {
    console.warn(`⚠️ WAF RATE LIMIT BLOCK: IP ${clientIp} exceeded threshold (${record.count}/${MAX_REQUESTS})`);

    // Calculate seconds remaining until block lift for user experience/analytics
    const retryAfter = Math.ceil((record.resetTime - now) / 1000);

    res.setHeader("Retry-After", retryAfter);
    return res.status(429).json({
      blocked: true,
      error: "Too Many Requests",
      message: `You have exceeded the maximum request allowance. Please try again in ${retryAfter} seconds.`
    });
  }

  next();
};

// Housekeeping: Periodic cleanup loop to prevent memory leaks during testing
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of ipCache.entries()) {
    if (now > record.resetTime) {
      ipCache.delete(ip);
    }
  }
}, 5 * 60 * 1000); // Clean up every 5 minutes