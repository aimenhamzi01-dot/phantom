<div align="center">

# Phantom

### Mizan's signed evidence worker for authorized security research.

<p><strong>Collect bounded evidence. Let Muse Spark organize it. Let Mizan make it reviewable.</strong></p>

[![CI](https://github.com/aimenhamzi01-dot/phantom/actions/workflows/ci.yml/badge.svg)](https://github.com/aimenhamzi01-dot/phantom/actions/workflows/ci.yml)
[![Meta Muse Spark](https://img.shields.io/badge/Powered%20by-Meta%20Muse%20Spark-0866ff?style=for-the-badge)](https://dev.meta.ai/docs/models)
[![Parent project](https://img.shields.io/badge/Parent%20workbench-Mizan-55d6c2?style=for-the-badge)](https://github.com/aimenhamzi01-dot/mizan)

**Evidence worker for the [Meta Global AI Developer Hackathon 2026](https://dev.meta.ai/events/global-hackathon)**

</div>

> Phantom is not a second product pitch. It is the controlled evidence layer that makes Mizan's review workflow richer without turning an AI scanner into an autonomous decision-maker.

## The role in one picture

```text
Mizan creates a signed, time-limited task
                    ↓
Phantom verifies scope and collects bounded evidence
                    ↓
Semgrep adds source-level signals when requested
                    ↓
Meta Muse Spark organizes the evidence
                    ↓
Mizan imports provenance-rich data for human review
```

Mizan remains the product, the decision plane, and the judge-facing interface. Phantom is the focused worker behind the evidence loop.

## Why Phantom makes Mizan stronger

### From pasted context to collected evidence
Mizan can review a report and researcher-supplied code. Phantom extends that workflow with authorized HTTPS, DNS, TLS, and remote-source context that can be handed back to the same evidence-led review surface.

### From scanner output to explainable findings
For code targets, Phantom can run a language-aware Semgrep configuration and preserve the rule ID, line range, code snippet, CWE/OWASP metadata, and source fingerprint. Muse Spark organizes those signals into a readable report; Mizan keeps the result explicitly reviewable.

### From tool integration to accountable provenance
Every handoff is versioned. The Mizan manifest carries a signed execution policy. Phantom returns analysis status, engine, selected configuration, source byte count, and SHA-256 provenance for retrieved source. Mizan presents the imported result as evidence, not as an automatic verdict.

## What is implemented

- **Signed Mizan handoff:** HMAC-SHA256 signatures, expiry, supported scope, execution policy, and target allowlists.
- **Bounded collection:** HTTPS-only requests, validated public IP pinning, original-host TLS verification, no redirects, and a streaming 2 MB source limit.
- **Source evidence:** optional Semgrep analysis with language-aware rule selection and explicit statuses such as `complete`, `source-unavailable`, `semgrep-unavailable`, and `semgrep-timeout`.
- **Meta organization:** Muse Spark receives bounded collected context and returns structured report data for Mizan review.
- **Versioned contracts:** [`mizan-phantom-task-v1`](schemas/mizan-phantom-task-v1.schema.json) and [`phantom-scan-result-v1`](schemas/phantom-scan-result-v1.schema.json).
- **Mizan-ready handback:** results are designed for import, provenance inspection, citation matching, and human disposition.
- **FastAPI service:** asynchronous scan status, JSON result export, text report export, health endpoint, and OpenAPI documentation.

## Judge-facing story

The most powerful Phantom scene takes 20–30 seconds inside the Mizan demo:

1. Mizan prepares a signed task for an authorized target.
2. Phantom rejects an unsigned or out-of-scope request.
3. Phantom accepts the signed task and returns a provenance-rich result.
4. Mizan imports it as **reviewable evidence**.
5. The human reviewer inspects the source and records the final disposition.

This single scene shows technical ambition, real Meta Model API usage, secure tool boundaries, and a product philosophy that keeps humans accountable.

## Quick start

Use a private, controlled environment and an asset you are explicitly authorized to assess.

```bash
git clone https://github.com/aimenhamzi01-dot/phantom.git
cd phantom
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pytest                 # development/test dependency
cp .env.example .env
```

Configure the same signing key used by Mizan, a Phantom service token, a precise authorized-target allowlist, and an authorized Meta Model API key. For code targets, install Semgrep in the worker environment.

```bash
python main.py
```

Then open:

- Health: `http://127.0.0.1:8000/health`
- OpenAPI: `http://127.0.0.1:8000/docs`

For a local two-service demo, run Mizan and Phantom on loopback and transfer only the signed manifest and the resulting JSON file between them.

## API surface

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | Worker and Meta configuration status |
| `POST` | `/scan/start` | Start a signed, bounded evidence task |
| `GET` | `/scan/{scan_id}/status` | Follow progress and analysis phase |
| `GET` | `/scan/{scan_id}/result` | Export the structured evidence result |
| `GET` | `/scan/{scan_id}/report` | Export a readable report |
| `DELETE` | `/scan/{scan_id}` | Remove a local scan result |
| `GET` | `/scans` | List local scan summaries |
| `GET` | `/docs` | Explore the OpenAPI contract |

Secure requests carry the signed Mizan manifest:

```json
{
  "manifest": {
    "format": "mizan-phantom-task-v1",
    "task_id": "issued-by-mizan",
    "target": "https://authorized.example.com",
    "target_type": "code",
    "scope": ["idor", "auth"],
    "execution": {
      "mode": "manual-handoff-only",
      "automatic_execution": false,
      "network_access_by_mizan": false,
      "max_duration_minutes": 20,
      "result_format": "phantom-scan-result-v1"
    },
    "signature_algorithm": "HMAC-SHA256",
    "signature": "issued-by-mizan"
  }
}
```

Submit it with `X-Phantom-API-Token`. The result is designed to move back into Mizan for evidence inspection and human disposition.

## Provenance-rich result design

For a code task, the result records the analysis story alongside the findings:

```json
{
  "analysis_status": "complete",
  "analysis_engine": "semgrep",
  "analysis_config": "p/python",
  "source_sha256": "…",
  "source_bytes": 18420,
  "lines_of_code": 612,
  "static_findings": []
}
```

A status such as `semgrep-unavailable` or `source-unavailable` is preserved as a first-class signal. This keeps “no finding returned” distinct from “the analysis did not run,” which makes Mizan's review experience more trustworthy.

## Architecture principles

- **Mizan owns the decision.** Phantom supplies evidence; the reviewer decides.
- **Scope is signed.** Every task carries a time limit, target type, requested categories, and execution policy.
- **Evidence stays inspectable.** Findings retain source location, tool metadata, and source provenance.
- **Meta organizes; humans verify.** Muse Spark structures the collected context but does not establish exploitability by itself.
- **Workers stay bounded.** Phantom is intended for controlled, authorized, loopback/private-network deployments.

## Validation

The current test suite covers manifest integrity, expiry, execution policy, target allowlists, public-IP resolution, pinned TLS behavior, API authentication, and scan lifecycle behavior. CI runs tests and builds the container image.

## Shared project links

- [Mizan — the judge-facing workbench](https://github.com/aimenhamzi01-dot/mizan)
- [Mizan–Phantom integration guide](https://github.com/aimenhamzi01-dot/mizan/blob/main/docs/PHANTOM_INTEGRATION.md)
- [Meta Model API models](https://dev.meta.ai/docs/models)
- [Meta Global AI Developer Hackathon](https://dev.meta.ai/events/global-hackathon)

## License

See [LICENSE.txt](LICENSE.txt).
