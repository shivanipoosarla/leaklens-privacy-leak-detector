# GitHub Upload Guide

## Recommended repository settings

- Repository name: `leaklens-privacy-leak-detector`
- Visibility: Public
- Description: `Python post-processor that summarizes potential privacy leaks in taint-style KLEE/KLEE-taint logs.`
- Do not initialize the GitHub repo with a README, license, or `.gitignore`; this project already includes them.

## Suggested GitHub topics

```text
python
cybersecurity
privacy
klee
llvm
symbolic-execution
taint-analysis
application-security
static-analysis
security-tools
```

## Push commands

Run these from inside the project folder after unzipping it:

```bash
git init
git add .
git commit -m "Initial LeakLens prototype"
git branch -M main
git remote add origin https://github.com/shivanipoosarla/leaklens-privacy-leak-detector.git
git push -u origin main
```

## After pushing

1. Open the repository on GitHub.
2. Confirm the README renders correctly.
3. Confirm the GitHub Actions test badge appears.
4. Wait for the first test run to pass.
5. Add the suggested topics in the repository sidebar.
6. Pin this repository on your GitHub profile.
7. Add the GitHub URL to your resume and LinkedIn only after the public page and tests look clean.

## What to say if asked in an interview

LeakLens is a prototype post-processor for taint-style KLEE/KLEE-taint logs. I built it to explore how symbolic-execution outputs could be summarized into privacy-leak reports when symbolic inputs reach unsafe output sinks. The current version focuses on log parsing and report generation; future work would add `.ktest` parsing and tighter integration with raw KLEE output.
