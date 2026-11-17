"""WSGI entry point for the isolated Render demonstration."""

import os

from . import create_app

if os.environ.get("CYBER_ASSESSMENT_HOSTED_DEMO", "").strip().lower() not in {
    "1",
    "true",
}:
    raise RuntimeError("The public WSGI entry point requires hosted demo mode.")

app = create_app()
