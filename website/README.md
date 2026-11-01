# KECHAA Marketing Website

This directory contains the static marketing website for KECHAA. It is separate from the Python security package and uses no runtime dependencies.

## Local preview

```bash
cd website
python3 -m http.server 8080
```

Open `http://localhost:8080`.

## Deployment

The repository includes `.github/workflows/pages.yml`, which publishes the `website/` directory with GitHub Pages.

Manual repository setting required once:

1. Open the repository settings on GitHub.
2. Go to **Pages**.
3. Set **Build and deployment** source to **GitHub Actions**.
4. Merge website changes to `main` or run the workflow manually from a trusted branch.

Expected GitHub Pages URL after deployment:

```text
https://ruchithamohan.github.io/KECHAA-Kernel-Enforced-Containment-for-Hijacked-AI-Agents/
```

## Content direction

The homepage is intentionally concise and product-led. It focuses on implemented KECHAA concepts: signed grants, task contracts, history-aware policy, supervised execution architecture, tool effect contracts, quarantine, recovery and audit evidence.
