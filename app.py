"""Vercel entry point for the read-only, synthetic-data ThreatLens demo."""

import os

hosted_demo = os.environ.get("CYBER_ASSESSMENT_HOSTED_DEMO", "").strip().lower()
if hosted_demo not in {"1", "true"}:
    raise RuntimeError(
        "Vercel deployment requires CYBER_ASSESSMENT_HOSTED_DEMO=1."
    )

if not os.environ.get("CYBER_ASSESSMENT_SECRET_KEY", "").strip():
    raise RuntimeError(
        "Vercel deployment requires a non-empty CYBER_ASSESSMENT_SECRET_KEY."
    )

from src.cyber_assessment.web.wsgi import app
