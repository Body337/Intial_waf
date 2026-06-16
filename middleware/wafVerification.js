module.exports = (req, res, next) => {
  // Add verification header after all security checks pass
  // This signals to the backend that the request passed WAF inspection
  req.headers["x-waf-forward"] = "true";

  console.log("✓ Request verified by WAF - x-waf-forward: true");

  next();
};
