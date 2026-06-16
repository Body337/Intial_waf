require("dotenv").config();

const requestLogger = require("./middleware/requestLogger");
const sqliDetector = require("./middleware/sqliDetector");
const wafVerification = require("./middleware/wafVerification");

const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");

const app = express();

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security & Logging Middleware
app.use(requestLogger);
app.use(sqliDetector);
app.use(wafVerification); // Add x-waf-forward: true if request passed all security checks


// Debug middleware - removed as functionality moved to requestLogger
// Proxy middleware configuration
app.use(
  "/",
  createProxyMiddleware({
    target: process.env.TARGET_API,
    changeOrigin: true,
    logLevel: "debug",
    // Ensure request body is forwarded
    proxyReqBodyExtender: (bodyContent, srcReq) => {
      // Forward the parsed body as-is, includes x-waf-forward header
      if (srcReq.body && Object.keys(srcReq.body).length > 0) {
        console.log("Forwarding body data:", srcReq.body);
        return JSON.stringify(srcReq.body);
      }
      return bodyContent;
    },
    // Log when request is sent to target
    onProxyReq: (proxyReq, req, res) => {
      console.log("Proxying request with headers:", {
        method: req.method,
        url: req.originalUrl,
        xWafForward: req.headers["x-waf-forward"] ? "✓ Present" : "✗ Missing",
      });
    },
    // Log responses from target
    onProxyRes: (proxyRes, req, res) => {
      console.log("Received response from target:", {
        statusCode: proxyRes.statusCode,
        headers: proxyRes.headers,
      });
    },
  })
);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`WAF listening on port ${PORT}`);
});