#!/usr/bin/env node
/**
 * Bob SAST Auto-Patcher
 * Reads Semgrep JSON results and applies safe code fixes automatically.
 * Supports: XSS, dangerouslySetInnerHTML, eval(), hardcoded secrets,
 *           console.log leaks, insecure randomness, prototype pollution.
 */

const fs = require("fs");
const path = require("path");

const resultsFile = process.argv[2] || "/tmp/semgrep-results.json";
const patchCountFile = "/tmp/sast-patch-count.txt";

// ── Fix catalogue ──────────────────────────────────────────────────────────
// Each entry: { rulePattern, description, fix(fileContent, finding) → string }
const FIXERS = [
  // 1. dangerouslySetInnerHTML without sanitization
  {
    rulePattern: /dangerouslySetInnerHTML|react\.dangerous/i,
    description: "dangerouslySetInnerHTML → DOMPurify sanitization",
    fix(content, finding) {
      // Add DOMPurify import if missing
      let result = content;
      if (!result.includes("DOMPurify")) {
        result = result.replace(
          /^(import .+;\n)/m,
          `$1import DOMPurify from 'dompurify';\n`
        );
      }
      // Wrap raw __html values
      result = result.replace(
        /dangerouslySetInnerHTML=\{\{(\s*)__html:\s*([^}]+)\}\}/g,
        (match, space, expr) =>
          `dangerouslySetInnerHTML={{${space}__html: DOMPurify.sanitize(${expr.trim()})}}`
      );
      return result;
    },
  },

  // 2. eval() usage
  {
    rulePattern: /javascript\.lang\.security\.audit\.eval/i,
    description: "eval() → Function constructor removal",
    fix(content) {
      return content.replace(
        /\beval\s*\(([^)]+)\)/g,
        "/* Bob-AutoFix: eval() removed — use JSON.parse or safer alternative */ JSON.parse($1)"
      );
    },
  },

  // 3. Hardcoded secrets / API keys in source
  {
    rulePattern: /generic\.secrets|hardcoded.?(secret|key|password|token)/i,
    description: "Hardcoded secret → process.env reference",
    fix(content, finding) {
      const line = finding.start?.line;
      if (!line) return content;
      const lines = content.split("\n");
      const target = lines[line - 1];
      // Match: const API_KEY = "abc123" style
      const secretMatch = target.match(
        /((?:const|let|var)\s+\w+\s*=\s*)(["'`][^"'`]{8,}["'`])/
      );
      if (secretMatch) {
        const varName = target.match(/(?:const|let|var)\s+(\w+)/)?.[1] || "SECRET";
        const envKey = varName.toUpperCase().replace(/[^A-Z0-9]/g, "_");
        lines[line - 1] = target.replace(
          secretMatch[0],
          `${secretMatch[1]}process.env.${envKey} /* Bob-AutoFix: moved to env */`
        );
        return lines.join("\n");
      }
      return content;
    },
  },

  // 4. console.log with sensitive-looking data
  {
    rulePattern: /javascript\.browser\.security\..*console|no-console/i,
    description: "console.log(sensitive) → removed in production",
    fix(content) {
      return content.replace(
        /console\.(log|info|debug|warn)\s*\(([^)]*(?:password|token|secret|key|auth|credential)[^)]*)\)/gi,
        "/* Bob-AutoFix: sensitive console.log removed */"
      );
    },
  },

  // 5. Math.random() for security purposes
  {
    rulePattern: /insecure.?random|math\.random/i,
    description: "Math.random() → crypto.getRandomValues()",
    fix(content) {
      if (!content.includes("Math.random()")) return content;
      let result = content;
      // Add helper if not present
      if (!result.includes("getRandomValues") && !result.includes("secureRandom")) {
        const helper = `
// Bob-AutoFix: Replaced Math.random() with cryptographically secure alternative
const secureRandom = () => crypto.getRandomValues(new Uint32Array(1))[0] / 0xFFFFFFFF;
`;
        result = result.replace(/^(import .*\n)+/m, (m) => m + helper);
      }
      result = result.replace(/Math\.random\(\)/g, "secureRandom()");
      return result;
    },
  },

  // 6. Object prototype pollution via merge
  {
    rulePattern: /prototype.pollution|object\.assign.*req\./i,
    description: "Prototype pollution → Object.create(null) guard",
    fix(content) {
      // Wrap unsafe Object.assign calls that use request data
      return content.replace(
        /Object\.assign\s*\(\s*(\w+)\s*,\s*(req\.\w+[^)]*)\)/g,
        `Object.assign($1, JSON.parse(JSON.stringify($2))) /* Bob-AutoFix: prototype pollution guard */`
      );
    },
  },

  // 7. innerHTML direct assignment
  {
    rulePattern: /innerHTML/i,
    description: "innerHTML direct assignment → textContent or DOMPurify",
    fix(content) {
      return content.replace(
        /(\w+)\.innerHTML\s*=\s*(?!DOMPurify)([^;]+);/g,
        (match, el, val) => {
          // If it's plain text, use textContent
          if (!val.includes("<") && !val.includes("html")) {
            return `${el}.textContent = ${val}; /* Bob-AutoFix: innerHTML → textContent */`;
          }
          return `${el}.innerHTML = DOMPurify.sanitize(${val}); /* Bob-AutoFix: sanitized */`;
        }
      );
    },
  },

  // 8. localStorage storing sensitive keys
  {
    rulePattern: /localstorage.*token|localstorage.*secret/i,
    description: "localStorage sensitive storage → sessionStorage warning",
    fix(content) {
      return content.replace(
        /localStorage\.setItem\s*\(\s*(["'`][^"'`]*(?:token|secret|key|auth)[^"'`]*["'`])\s*,/gi,
        `/* Bob-AutoFix: Consider using httpOnly cookies instead of localStorage for tokens */\n  localStorage.setItem($1,`
      );
    },
  },
];

// ── Main ───────────────────────────────────────────────────────────────────
function main() {
  if (!fs.existsSync(resultsFile)) {
    console.log("No Semgrep results file found. Skipping SAST auto-fix.");
    fs.writeFileSync(patchCountFile, "0");
    return;
  }

  const raw = JSON.parse(fs.readFileSync(resultsFile, "utf8"));
  const findings = raw.results || [];

  if (findings.length === 0) {
    console.log("✅ No SAST findings. Nothing to fix.");
    fs.writeFileSync(patchCountFile, "0");
    return;
  }

  // Group findings by file
  const byFile = {};
  for (const finding of findings) {
    const file = finding.path;
    if (!file || file.startsWith("/tmp") || file.startsWith("node_modules")) continue;
    if (!byFile[file]) byFile[file] = [];
    byFile[file].push(finding);
  }

  let totalPatched = 0;

  for (const [filePath, filefindings] of Object.entries(byFile)) {
    if (!fs.existsSync(filePath)) continue;

    const ext = path.extname(filePath);
    if (![".js", ".jsx", ".ts", ".tsx", ".mjs"].includes(ext)) continue;

    let content = fs.readFileSync(filePath, "utf8");
    let changed = false;

    for (const finding of filefindings) {
      const ruleId = finding.check_id || "";

      for (const fixer of FIXERS) {
        if (fixer.rulePattern.test(ruleId) || fixer.rulePattern.test(finding.extra?.message || "")) {
          const original = content;
          try {
            content = fixer.fix(content, finding.start || {});
            if (content !== original) {
              console.log(`  🔧 [${fixer.description}] → ${filePath}:${finding.start?.line}`);
              changed = true;
              totalPatched++;
            }
          } catch (err) {
            console.warn(`  ⚠️  Fixer failed for ${ruleId}: ${err.message}`);
          }
          break;
        }
      }
    }

    if (changed) {
      fs.writeFileSync(filePath, content, "utf8");
    }
  }

  fs.writeFileSync(patchCountFile, String(totalPatched));
  console.log(`\n✅ Bob SAST Auto-Fix complete: ${totalPatched} patches applied`);
}

main();
