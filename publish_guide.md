# Standard Procedure to Publish an NPM Package (CI/CD + GitHub Actions)

This is a **lifetime-safe guide** for publishing NPM packages using versioning and GitHub Actions.

---

## 1. Prepare Final Changes Locally

- Finalize feature or bug fix.
- Update `README.md`, changelog, etc.
- Run all tests:
  ```bash
  npm test
  ```

---

## 2. Bump the Version Properly

Use **one** of the following commands:

```bash
# For bug fixes or tiny improvements
npm version patch     # e.g., 1.0.2 → 1.0.3

# For new features (non-breaking)
npm version minor     # e.g., 1.0.3 → 1.1.0

# For breaking changes
npm version major     # e.g., 1.1.0 → 2.0.0
```

  This command will:

- Update `package.json` and `package-lock.json`
- Commit with message like `v1.1.0`
- Create a Git tag `v1.1.0`

---

## 3. Push Code and Tags to Remote

```bash
git push origin main --follow-tags
```

  This pushes:

- Code (including version bump commit)
- Tags (required for triggering GitHub Actions)

---

## 4. Let GitHub Actions Handle Publishing

Ensure your workflow (`.github/workflows/publish.yml`) does:

```yaml
steps:
  - uses: actions/checkout@v3
  - uses: actions/setup-node@v3
    with:
      node-version: '18'
      registry-url: 'https://registry.npmjs.org/'
  - run: npm ci
  - run: npm test
  - run: npm publish --access public
    env:
      NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```
Add your NPM_TOKEN to GitHub repo **secrets**.

---

## 5. Verify the Publish

Visit:

```
https://www.npmjs.com/package/@ssktechnologies/awsforge (awsforge package specific)
https://www.npmjs.com/package/<your-package-name>
```

Check:

- Correct version is live (e.g., `1.1.0`)
- Published files are clean

---

## Summary Cheatsheet

```bash
npm test                             # Always test

npm version patch   # 1.0.2 → 1.0.3
npm version minor   # 1.0.3 → 1.1.0
npm version major   # 1.1.0 → 2.0.0

git push origin main --follow-tags  # Push code + tags
# GitHub Action runs & publishes automatically
```

---
Done. Your new version is live. Repeat this same process every time.
🚀 Automate versioning. Let tools do the work — stop running things manually.
