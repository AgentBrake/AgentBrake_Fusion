# Submission Checklist

## Required Materials

- Work report PDF: place under `submission_materials/report_pdf/` before final official submission.
- Work report Word: place under `submission_materials/report_word/` before final official submission.
- Signed originality statement: place under `submission_materials/originality_statement/`.
- Source code: included in the generated zip.
- Environment dependencies: `pyproject.toml`, `backend/requirements.txt`, `web/studio/package.json`, `web/studio/package-lock.json`.
- One-click scripts: `scripts/bootstrap.*`, `scripts/run_all.*`, `scripts/run_demo.*`, `scripts/run_tests.*`.
- Deployment guide: `docs/DEPLOYMENT.md`.
- Security boundary statement: `docs/SECURITY_BOUNDARY.md`.

## Recommended Supporting Materials

- Demo video: place under `artifacts/videos/` or provide a link in that directory.
- Defense PPT: place under `submission_materials/ppt/`.
- Experiment data: `data/agentdojo_results/`, `data/sample_traces/`.
- System screenshots: `artifacts/screenshots/`.
- Figures: `artifacts/figures/`.
- Topic correspondence explanation: include in the work report or add a supplementary note under `docs/`.

## Before Packaging

Run:

```bash
bash scripts/run_tests.sh
python scripts/package_submission.py
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_tests.ps1
python scripts/package_submission.py
```

Confirm:

- `dist/AgentBrake-Fusion_Submission.zip` exists.
- `.env`, `.venv`, `.git`, `node_modules`, and real secrets are not inside the zip.
- `SUBMISSION_MANIFEST.md` and `CHECKSUMS.sha256` are inside the zip.
