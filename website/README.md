# KECHAA Marketing Website

This directory contains the static marketing website for KECHAA. It is intentionally separate from the Python security package and uses no runtime dependencies.

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
4. Merge the website branch to `main` or run the workflow manually if the branch is trusted.

Expected GitHub Pages URL after deployment:

```text
https://ruchithamohan.github.io/KECHAA-Kernel-Enforced-Containment-for-Hijacked-AI-Agents/
```

## Claim discipline

Homepage language is intentionally product-led but evidence bounded:

- Control-plane capabilities are described as implemented where supported by repository code and tests.
- Linux whole-agent containment is described as pending certification until LC-001 through LC-013 run in a disposable Linux VM.
- MCP language is limited to effect-contract authorization, not complete protocol mediation.
- Production readiness is not claimed.
