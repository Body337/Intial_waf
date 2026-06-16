module.exports = (req, res, next) => {
  // Add verification header after all security checks pass
  // This signals to the backend that the request passed WAF inspection
  req.headers["x-waf"] = "verified";
  req.headers["x-waf-timestamp"] = new Date().toISOString();

  console.log("✓ Request verified by WAF and marked as safe");

  next();
};
