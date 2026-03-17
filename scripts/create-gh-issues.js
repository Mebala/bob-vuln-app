#!/usr/bin/env node
/**
 * Bob GitHub Issue Creator
 * Opens GitHub Issues for critical/high vulnerabilities that could not be auto-fixed.
 * Called after all auto-fix jobs have run.
 */

const https = require("https");
const fs = require("fs");

const [, , token, repo, sha, branch, scaStatus, sastStatus, iacStatus] = process.argv;

if (!token || token === "undefined") {
  console.log("No token provided. Skipping issue creation.");
  process.exit(0);
}

function githubRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request(
      {
        hostname: "api.github.com",
        path,
        method,
        headers: {
          Authorization: `token ${token}`,
          "User-Agent": "Bob-Security-Bot",
          "Content-Type": "application/json",
          Accept: "application/vnd.github.v3+json",
          ...(payload ? { "Content-Length": Buffer.byteLength(payload) } : {}),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(data);
          }
        });
      }
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// Collect unfixed findings from audit files
function collectUnfixedFindings() {
  const findings = [];

  // SCA — remaining npm audit vulns
  if (fs.existsSync("/tmp/audit-after.json")) {
    try {
      const audit = JSON.parse(fs.readFileSync("/tmp/audit-after.json", "utf8"));
      const advisories = audit.vulnerabilities || {};
      for (const [pkg, info] of Object.entries(advisories)) {
        if (["critical", "high"].includes(info.severity)) {
          findings.push({
            type: "SCA",
            severity: info.severity.toUpperCase(),
            title: `${pkg} — ${info.severity} dependency vulnerability`,
            body: [
              `**Package:** \`${pkg}\``,
              `**Severity:** ${info.severity.toUpperCase()}`,
              `**Via:** ${(info.via || []).map(v => typeof v === 'string' ? v : v.title).join(", ")}`,
              `**Fix:** ${info.fixAvailable ? `Upgrade to ${typeof info.fixAvailable === 'object' ? info.fixAvailable.version : 'latest'}` : "No fix available — mitigation required"}`,
              ``,
              `> Auto-fix was attempted but this vulnerability persists. Manual intervention needed.`,
              ``,
              `**Commit:** \`${sha}\` on branch \`${branch}\``,
            ].join("\n"),
          });
        }
      }
    } catch (e) {
      console.warn("Could not parse npm audit results:", e.message);
    }
  }

  // SAST — remaining Semgrep findings
  if (fs.existsSync("/tmp/semgrep-results.json")) {
    try {
      const semgrep = JSON.parse(fs.readFileSync("/tmp/semgrep-results.json", "utf8"));
      for (const finding of semgrep.results || []) {
        const sev = finding.extra?.severity || "";
        if (!["ERROR", "WARNING"].includes(sev)) continue;
        findings.push({
          type: "SAST",
          severity: sev === "ERROR" ? "HIGH" : "MEDIUM",
          title: `${finding.check_id} — ${finding.extra?.message?.slice(0, 60) || "SAST finding"}`,
          body: [
            `**Rule:** \`${finding.check_id}\``,
            `**File:** \`${finding.path}:${finding.start?.line}\``,
            `**Severity:** ${sev}`,
            `**Message:** ${finding.extra?.message}`,
            ``,
            `**Snippet:**`,
            "```",
            finding.extra?.lines?.trim() || "(see file)",
            "```",
            ``,
            `> Bob SAST Auto-Patcher could not safely fix this pattern. Manual review required.`,
            ``,
            `**Commit:** \`${sha}\` on branch \`${branch}\``,
          ].join("\n"),
        });
      }
    } catch (e) {
      console.warn("Could not parse Semgrep results:", e.message);
    }
  }

  return findings;
}

async function getExistingIssues(repoPath) {
  const issues = await githubRequest("GET", `/repos/${repoPath}/issues?labels=bob-security&state=open&per_page=100`);
  return Array.isArray(issues) ? issues.map((i) => i.title) : [];
}

// Generate tickets when an auto-fix job itself failed
function collectJobFailureFindings() {
  const failures = [];
  const jobs = [
    { name: "SCA Auto-Fix", status: scaStatus, type: "SCA" },
    { name: "SAST Auto-Fix", status: sastStatus, type: "SAST" },
    { name: "IaC Auto-Fix", status: iacStatus, type: "IaC" },
  ];
  for (const job of jobs) {
    if (job.status === "failure") {
      failures.push({
        type: job.type,
        severity: "HIGH",
        title: `${job.name} job failed — manual review required`,
        body: [
          `**Job:** ${job.name}`,
          `**Status:** ❌ Failed`,
          `**Severity:** HIGH`,
          ``,
          `The Bob auto-fix job for **${job.type}** crashed during execution.`,
          `This means vulnerabilities in this category may not have been scanned or fixed.`,
          ``,
          `**Action required:** Check the [GitHub Actions run](https://github.com/${repo}/actions) for logs, then manually review and fix vulnerabilities.`,
          ``,
          `**Commit:** \`${sha}\` on branch \`${branch}\``,
        ].join("\n"),
      });
    }
  }
  return failures;
}

async function main() {
  const findings = [
    ...collectUnfixedFindings(),
    ...collectJobFailureFindings(),
  ];

  if (findings.length === 0) {
    console.log("✅ No unfixed critical/high findings. No issues to create.");
    return;
  }

  console.log(`📋 Creating GitHub Issues for ${findings.length} unfixed finding(s)...`);

  const existingTitles = await getExistingIssues(repo);

  for (const finding of findings) {
    const issueTitle = `[Bob Security] ${finding.type} ${finding.severity}: ${finding.title}`;

    // Deduplicate — don't reopen same issue
    if (existingTitles.includes(issueTitle)) {
      console.log(`  ⬜ Already open: ${issueTitle}`);
      continue;
    }

    const issue = await githubRequest("POST", `/repos/${repo}/issues`, {
      title: issueTitle,
      body: finding.body,
      labels: ["bob-security", `severity-${finding.severity.toLowerCase()}`, finding.type.toLowerCase()],
    });

    if (issue.number) {
      console.log(`  ✅ Opened Issue #${issue.number}: ${issueTitle}`);
    } else {
      console.warn(`  ⚠️  Failed to create issue:`, JSON.stringify(issue).slice(0, 200));
    }
  }
}

main().catch((err) => {
  console.error("Issue creation failed:", err.message);
  process.exit(0); // Don't fail the pipeline for issue creation errors
});
