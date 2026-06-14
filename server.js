require("dotenv").config();

const requestLogger = require("./middleware/requestLogger");
const sqliDetector = require("./middleware/sqliDetector");

const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");

const app = express();


app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(requestLogger);
app.use(sqliDetector);


app.use((req, res, next) => {
  console.log("Incoming:", req.method, req.originalUrl);
  next();
});

app.use(
  "/",
  createProxyMiddleware({
    target: process.env.TARGET_API,
    changeOrigin: true,
    logLevel: "debug",
    
  })
);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`WAF listening on port ${PORT}`);
});