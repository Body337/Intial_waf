const patterns = [
  /union\s+select/i,
  /or\s+1=1/i,
  /drop\s+table/i,
  /insert\s+into/i,
  /delete\s+from/i,
  /--/i,
  /'/i
];

module.exports = (req, res, next) => {
  const payload = JSON.stringify({
    query: req.query,
    body: req.body,
    params: req.params,
    url: req.originalUrl
  });

  console.log("Inspecting:", payload);

  for (const pattern of patterns) {
    if (pattern.test(payload)) {
      console.log("BLOCKED SQLI:", payload);

      return res.status(403).json({
        blocked: true,
        reason: "SQL Injection Detected"
      });
    }
  }

  next();
};