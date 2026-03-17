// src/App.jsx
// NOTE: This file contains intentional vulnerabilities for Bob auto-fix demo.
// Bob will detect and patch these automatically on push.

export default function App() {
  const userInput = "<img src=x onerror=alert(1)>";

  // ❌ VULN 1: dangerouslySetInnerHTML without sanitization (XSS)
  const renderHTML = () => (
    <div dangerouslySetInnerHTML={{ __html: userInput }} />
  );

  // ❌ VULN 2: eval() usage
  const runCode = (code) => eval(code);

  // ❌ VULN 3: Hardcoded secret
  const API_KEY = "sk-abc123supersecretkey";

  // ❌ VULN 4: Insecure random
  const token = Math.random().toString(36);

  // ❌ VULN 5: Sensitive data in console
  console.log("User token:", API_KEY);

  return (
    <div style={{ padding: 40, fontFamily: "sans-serif" }}>
      <h1>Bob Auto-Fix Demo</h1>
      <p>Push this file — Bob will auto-fix all 5 vulnerabilities above.</p>
    </div>
  );
}
