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
      console.log("Proxying request with headers:", {
        method: req.method,
        url: req.originalUrl,
        xWafForward: req.headers["x-waf-forward"] ? "✓ Present" : "✗ Missing",
      });

      // THE FIX: Explicitly rewrite the body stream if Express consumed it
      if (req.body && Object.keys(req.body).length > 0) {
        
        let bodyData;
        
        // Handle JSON payloads (Most common for React/Vercel frontends)
        if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
            bodyData = JSON.stringify(req.body);
            proxyReq.setHeader('Content-Type', 'application/json');
        } 
        // Handle Form Data
        else if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
            bodyData = Object.keys(req.body)
                .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(req.body[k])}`)
                .join('&');
            proxyReq.setHeader('Content-Type', 'application/x-www-form-urlencoded');
        }

        // Write the data to the proxy stream
        if (bodyData) {
            proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
            proxyReq.write(bodyData);
            // End the write stream so the proxy knows the body is complete
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