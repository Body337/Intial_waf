// middleware/securityInspector.js

// Domain-specific signature definitions
const RULES = {
  SQL_INJECTION: [
    { pattern: /\b(union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|delete\s+from)\b/i, name: "SQL Keyword Injection" },
    { pattern: /\b(or|and)\s+\d+=\d+/i, name: "Tautology Bypass (e.g., OR 1=1)" },
    { pattern: /exec\s*\(.*\)/i, name: "Stored Procedure Execution" },
    { pattern: /--/i, name: "SQL Comment Obfuscation" }
  ],
  CROSS_SITE_SCRIPTING: [
    { pattern: /<script[^>]*>([\s\S]*?)<\/script>/i, name: "Classic Script Tag Injection" },
    { pattern: /javascript:/i, name: "URI Scheme Injection" },
    { pattern: /\bon\w+\s*=/i, name: "Malicious HTML Event Attribute (e.g., onload, onerror)" },
    { pattern: /<\s*iframe|<\s*object|<\s*embed/i, name: "Sub-document Element Injection" }
  ],
  PATH_TRAVERSAL: [
    { pattern: /\.\.\//, name: "Relative Directory Traversal (../)" },
    { pattern: /%2e%2e%2f/i, name: "Encoded Directory Traversal" },
    { pattern: /\b(etc\/passwd|boot\.ini|win\.ini)\b/i, name: "Sensitive OS File Access Attempt" }
  ]
};

// Helper function to recursively scan text values within nested request objects
function inspectValue(value, category, rule, details) {
  if (typeof value === "string") {
    if (rule.pattern.test(value)) {
      details.matchedValue = value;
      return true;
    }
  } else if (typeof value === "object" && value !== null) {
    for (const key of Object.keys(value)) {
      if (inspectValue(value[key], category, rule, details)) {
        details.matchedKey = key;
        return true;
      }
    }
  }
  return false;
}

module.exports = (req, res, next) => {
  const targetData = {
    url: req.originalUrl,
    query: req.query,
    body: req.body,
    params: req.params
  };

  // Run validation loops through rules
  for (const [category, ruleList] of Object.entries(RULES)) {
    for (const rule of ruleList) {
      let details = {};
      
      // Separately evaluate URL paths vs deep parameters to limit structural false positives
      if (rule.pattern.test(targetData.url) || inspectValue(targetData.query, category, rule, details) || inspectValue(targetData.body, category, rule, details)) {
        
        console.error(`🚨 WAF BLOCK [${category}]: ${rule.name}`);
        console.error(`Context: Key [${details.matchedKey || "URL"}] matched payload: "${details.matchedValue || targetData.url}"`);

        // Academic Project Value: Returning rich debug info makes demoing for graduation defense intuitive
        return res.status(403).json({
          blocked: true,
          error: "Security Policy Violation",
          incidentDetails: {
            class: category,
            ruleTriggered: rule.name
          }
        });
      }
    }
  }

  next();
};