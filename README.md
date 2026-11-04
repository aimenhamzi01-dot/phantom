# Phantom

**Mizan's signed, bounded evidence worker—powered exclusively by Meta Muse Spark.**

Phantom is a secondary worker inside **Mizan**, the main project submitted to the Meta Global AI Developer Hackathon. It performs a narrow, authorized collection pass, runs optional Semgrep checks for code targets, and asks Meta Muse Spark to organize the resulting evidence. It is not an independent product, final validator, bounty oracle, or decision-maker.

> **Security status:** Phantom accepts signed Mizan manifests only by default. It also requires a service token, an explicit target allowlist, HTTPS, TLS verification, no redirects, and rejects private/reserved destinations. Keep it private and use it only for targets you are authorized to assess.

## What is implemented

- **Signed Mizan handoff:** accepts a task only when its HMAC-SHA256 manifest, expiry, scope, execution policy, and target allowlist all verify.
- **Bounded evidence collection:** uses HTTPS-only requests with TLS verification, no redirects, public-target checks, selected DNS/certificate metadata, and a 2 MB source limit.
- **Code evidence:** optionally fetches an authorized source URL and runs a language-appropriate Semgrep ruleset. This is remote source retrieval, not local-file upload or code execution.
- **Meta-only analysis:** `AIEngine` calls Meta Model API with Muse Spark (`muse-spark-1.3` and configured Muse Spark fallbacks). Output is generated analysis, never independent verification.
- **Safe handback:** returns findings as untrusted evidence for Mizan's import, source matching, human review, and final disposition.
- **In-memory job tracking:** scan state and results are held in process memory and are lost on restart. This is suitable only for local experimentation.

Phantom does not execute proof-of-concept code, exploit a target, apply remediation, estimate a bounty, or recommend a program. Mizan is the orchestrator and final decision plane; Phantom findings are imported as untrusted evidence. A signed scope is enforced before execution and is also sent to the model as context.

## Role in the Meta hackathon project

Mizan is the product. Phantom exists to demonstrate a controlled extension point for the same evidence-led workflow:

```text
Mizan creates signed task
          ↓
Phantom verifies and collects bounded evidence
          ↓
Meta Muse Spark organizes the evidence
          ↓
Mizan imports it as untrusted data
          ↓
Human reviewer decides
```

This separation is intentional. It shows how an AI security workflow can gain useful tool-assisted evidence without turning a scanner into an autonomous actor. The judge-facing demo should open in Mizan; Phantom is a short supporting scene, not a second product pitch.

### Suggested Phantom scene in the 3-minute demo

Spend no more than 20–30 seconds on Phantom: show Mizan issuing a signed task, show Phantom rejecting an unsigned arbitrary-target request, then show the accepted result returning to Mizan as an explicitly unverified import. Return immediately to Mizan's evidence matching and human disposition panel.

## Requirements and current setup caveats

- Python 3.11 or later.
- A Meta Model API key (`MODEL_API_KEY`, `META_API_KEY`, or `META_MODEL_API_KEY`).
- The same `MIZAN_PHANTOM_SIGNING_KEY` configured in Mizan, plus `PHANTOM_API_TOKEN` and `PHANTOM_ALLOWED_TARGETS`.
- For `target_type: "code"`, install the Semgrep CLI separately. Without it, source may be fetched but no Semgrep findings will be produced.

Never use credentials from old commits. Use new, least-privilege credentials and keep them in a local `.env` file that is not committed.

## Local quick start

Use an isolated development environment and targets you own or are explicitly authorized to assess.

```bash
git clone https://github.com/aimenhamzi01-dot/phantom.git
cd phantom
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` locally. Set the Meta key and the same signing key used by Mizan, then configure the Phantom service token and exact authorized target allowlist. Do not paste real credentials into issues, pull requests, or public logs.

The example environment binds the Python server to loopback. Start it from the project directory:

```bash
python main.py
```

Check `http://127.0.0.1:8000/health` and open the FastAPI schema at `http://127.0.0.1:8000/docs`. The repository currently provides an API; it does not include a bundled web frontend.

The Docker files bind to loopback for the local demo. Do not expose Phantom directly to the internet.

## API overview

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | Basic service and configured-integration status |
| `POST` | `/scan/start` | Start an asynchronous scan |
| `GET` | `/scan/{scan_id}/status` | Read in-memory job status |
| `GET` | `/scan/{scan_id}/result` | Read the completed JSON result |
| `GET` | `/scan/{scan_id}/report` | Export a plain-text report |
| `DELETE` | `/scan/{scan_id}` | Remove a scan from the current process memory |
| `GET` | `/scans` | List scan summaries held by the current process |
| `GET` | `/docs` | Interactive OpenAPI documentation |

Secure request shape: Phantom receives the signed manifest created by Mizan, not an arbitrary target:

```json
{
  "manifest": {
    "format": "mizan-phantom-task-v1",
    "task_id": "issued-by-mizan",
    "target": "https://authorized.example.com",
    "target_type": "web",
    "scope": ["xss", "sqli"],
    "execution": {"mode": "manual-handoff-only", "automatic_execution": false},
    "signature_algorithm": "HMAC-SHA256",
    "signature": "issued-by-mizan"
  }
}
```

Submit it to `POST /scan/start` with `X-Phantom-API-Token`. The API returns a scan ID that can be used with the authenticated status and result routes. The service performs network activity when a web or code scan is started; use only a target you own or are explicitly authorized to assess.

Supported `target_type` values are `web`, `code`, `mobile`, and `hardware`. The competition demo focuses on `web` and the limited remote-source `code` path. Mobile and hardware are accepted as bounded metadata types but are not presented as implemented analyzers.

## Security limitations

The current implementation is not suitable for multi-user or internet-facing deployment:

- Scan start, status, and result endpoints require `X-Phantom-API-Token`; the start endpoint also requires a valid signed Mizan manifest.
- The manifest scope and target allowlist are enforced, but do not replace human authorization.
- Web and code targets can cause outbound requests. Targets must be HTTPS, redirects are disabled, TLS is verified, and private/reserved destinations are rejected.
- CORS configuration is permissive and is not an access-control mechanism.
- There are no durable storage, per-user isolation, rate limits, quotas, or robust concurrency controls.
- The AI report can contain fabricated or overstated claims. Treat all findings and model-provided values as unverified until checked independently.

Run only in a controlled, isolated environment on assets for which you have explicit permission. Do not deploy the current service on a public VPS or connect it to untrusted users. The presence of Docker or an API key does not make the service production-safe.

## Historical credential notice

A historical commit in this repository included a `.env` file. The maintainer reports that the credentials in it were revoked, and the current `main` tree does not contain that file. At the time this README was updated, GitHub still returned the historical commit by its SHA; complete server-side removal has not been verified. Do not reuse any credential found in historical data. If you cloned the repository before the history rewrite, discard that clone and make a fresh clone of the current `main` branch.

## Contributing

Please avoid committing `.env`, provider tokens, scan outputs containing sensitive target data, or unredacted logs. Report security issues privately to the maintainer rather than publishing exploit details or credentials in an issue.

## License

See [LICENSE.txt](LICENSE.txt).
