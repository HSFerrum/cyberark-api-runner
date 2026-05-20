# GitHub Upload

This project intentionally ignores generated CSV files because they can contain real CyberArk tenant data.

## Create A GitHub Repository

Create an empty GitHub repository, then add it as the local remote:

```bash
git remote add origin https://github.com/<owner>/<repo>.git
git branch -M main
git push -u origin main
```

If Git asks for credentials, use a GitHub personal access token as the password.

## Recommended Repository Name

```text
cyberark-api-runner
```
