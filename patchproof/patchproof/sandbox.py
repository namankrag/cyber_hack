"""Load a (possibly patched) copy of the target app in isolation.

Given the target source text, write it to a temp file, import it under a unique
module name, and return a fresh Flask test client. This lets the verifier run
the original and the patched code side by side in the same process without one
polluting the other.
"""
from __future__ import annotations

import importlib.util
import tempfile
import uuid
from pathlib import Path


def client_from_source(source: str):
    """Return a Flask test client built from the given app source text."""
    tmp = Path(tempfile.gettempdir()) / f"vulnbank_{uuid.uuid4().hex}.py"
    tmp.write_text(source)
    try:
        mod_name = f"vulnbank_dyn_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(mod_name, tmp)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        app = module.create_app()
        app.testing = True
        return app.test_client()
    finally:
        tmp.unlink(missing_ok=True)
