# Bob Auto-Fix — Minimal Repo

Push any commit → Bob automatically scans and fixes vulnerabilities.

## Run locally

```bash
npm install
npm run dev
# → http://localhost:5173
```

## Push to GitHub

```bash
git init
git add .
git commit -m "initial commit"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

Then go to **GitHub → Actions tab** to watch Bob fix vulnerabilities automatically.

## One required setting

GitHub repo → **Settings → Actions → General → Workflow permissions**
→ Select **"Read and write permissions"** → Save

## What Bob fixes automatically

| Type | Examples |
|------|---------|
| SCA | Vulnerable npm packages |
| SAST | `eval()`, XSS, hardcoded secrets, insecure random, `console.log(token)` |
| IaC | Dockerfile root user, `:latest` tags, missing HEALTHCHECK |

If a fix fails → GitHub Issue is opened automatically.

## Files

```
.github/workflows/bob-autofix.yml  ← pipeline (runs on every push)
scripts/sast-autofix.js            ← patches JS/JSX code
scripts/iac-autofix.py             ← hardens Dockerfile + K8s
scripts/create-gh-issues.js        ← opens tickets for unfixed vulns
src/App.jsx                        ← demo app with intentional vulns
```
