require("dotenv").config();

const requestLogger = require("./middleware/requestLogger");
const rateLimiter = require("./middleware/rateLimiter");
const securityInspector = require("./middleware/securityInspector");
const wafVerification = require("./middleware/wafVerification");

const express = require("express");
// imports the proxy middleware and the fixRequestBody utility for handling request body streams
const { createProxyMiddleware, fixRequestBody } = require("http-proxy-middleware");

const app = express();

// Parse JSON and URL-encoded bodies - necessary for WAF inspection
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security & Logging Middleware
app.use(requestLogger);
app.use(rateLimiter); // Limits the number of requests from a single IP
app.use(securityInspector); // Inspects Requests for malicious patterns and blocks them
app.use(wafVerification); // Adds verification signature/headers

// Proxy middleware configuration
app.use(
  "/",
  createProxyMiddleware({
    target: process.env.TARGET_API,
    changeOrigin: true,
    logLevel: "debug",
    // Log when request is sent to target and fix the body stream deadlock
    onProxyReq: (proxyReq, req, res) => {
      console.log("Proxying request:", req.method, req.originalUrl);

      // Only intervene for methods that typically carry payloads
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        
        // If Express body-parser consumed the stream, req.body will exist
        if (req.body) {
          let bodyData = '';

          // 1. If the body actually contains data, normalize and stringify it
          if (Object.keys(req.body).length > 0) {
            if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
              bodyData = JSON.stringify(req.body);
              proxyReq.setHeader('Content-Type', 'application/json');
            } else if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
              bodyData = Object.keys(req.body)
                .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(req.body[k])}`)
                .join('&');
              proxyReq.setHeader('Content-Type', 'application/x-www-form-urlencoded');
            }
          }

          // 2. Explicitly tell the backend exactly how many bytes to expect.
          // For an 'approve' request, this will correctly calculate to 0.
          proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));

          // 3. Write the data to the stream (if any exists)
          if (bodyData) {
            proxyReq.write(bodyData);
          }

          // 4. CRITICAL FIX: Always end the proxy stream for these methods!
          // This tells the backend "I'm done sending data, process the request now."
          proxyReq.end();
        }
      }
    },
    // Log responses from target
    onProxyRes: (proxyRes, req, res) => {
      console.log("Received response from target:", {
        statusCode: proxyRes.statusCode,
      });
    },
    onError: (err, req, res) => {
      console.error("WAF Proxy Error:", err);
      res.status(502).json({ error: "Bad Gateway", message: "WAF failed to connect to backend upstream." });
    }
  })
);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`WAF listening on port ${PORT}`);
});