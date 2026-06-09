# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report security issues to: agentguardx@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

We will respond within 72 hours and aim to patch critical issues within 14 days.

## Security Design Notes

AgentGuard-X is itself a security product. Its supply chain is held to a high standard:

- All Python dependencies are pinned to exact versions and SHA-256 hashes.
- All Docker base images are pinned by digest.
- All GitHub Actions are pinned to full commit SHAs.
- No model weights are committed to the repository.
- No secrets are hardcoded; `.env` is git-ignored.
- The mitmproxy CA private key is generated at runtime, never committed.
- CodeQL, Trivy, gitleaks, and pip-audit run on every push.
- SBOM generated via syft/CycloneDX on every release.

## Threat Model

AgentGuard-X is designed to intercept and analyze agentic AI behavior.
Known limitations of the PoC:

- The triage engine is not a replacement for human oversight.
- The grey-band hold queue requires an operator monitoring it.
- Docker-only mode (default on WSL2) provides weaker isolation than gVisor.
- The RAG knowledge base can be poisoned if an attacker can inject into analyst
  decisions — this is the LLM04 risk the product itself defends against.
- gVisor sandbox performance depends on host platform capabilities.
