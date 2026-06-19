require("dotenv").config();

const requestLogger = require("./middleware/requestLogger");
const rateLimiter = require("./middleware/rateLimiter");
const securityInspector = require("./middleware/securityInspector");
const wafVerification = require("./middleware/wafVerification");

const express = require("express");
// Change: Import fixRequestBody alongside createProxyMiddleware
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
      console.log("Proxying request with headers:", {
        method: req.method,
        url: req.originalUrl,
        xWafForward: req.headers["x-waf-forward"] ? "✓ Present" : "✗ Missing",
      });

      // Fix: If an express body parser has parsed the body, restream it to the proxy request target.
      if (req.body && Object.keys(req.body).length > 0) {
        // Option A: Use the built-in utility
        fixRequestBody(proxyReq, req);
        
        /*If fixRequestBody ever misbehaves with custom content types, 
          the explicit manual fallback is to intercept it right here:
          
          const bodyData = JSON.stringify(req.body);
          proxyReq.setHeader('Content-Type', 'application/json');
          proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
          proxyReq.write(bodyData);
        */
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