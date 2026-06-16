module.exports = (req, res, next) => {
  // Extract any JSON data from headers, body, or query params
  const headerData = {
    method: req.method,
    originalUrl: req.originalUrl,
    timestamp: new Date().toISOString(),
    clientIp: req.ip,
    headers: req.headers,
  };

  // Include request body if present
  if (req.body && Object.keys(req.body).length > 0) {
    headerData.bodyData = req.body;
  }

  // Include query params if present
  if (req.query && Object.keys(req.query).length > 0) {
    headerData.queryParams = req.query;
  }

  // Append the x-waf-forward header with encoded JSON data
  req.headers["x-waf-forward"] = Buffer.from(JSON.stringify(headerData)).toString("base64");

  console.log("X-WAF-Forward Header Added:", headerData);

  next();
};
