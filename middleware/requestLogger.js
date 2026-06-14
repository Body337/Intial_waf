module.exports = (req, res, next) => {
  console.log({
    ip: req.ip,
    method: req.method,
    path: req.originalUrl,
    timestamp: new Date().toISOString()
  });

  next();
};