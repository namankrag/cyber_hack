"""Keep the test run hermetic.

``agentshield.config`` loads ``./.env`` into the process environment when it
builds a Config. On a developer machine that file holds real API keys, a
harness secret and a deeper detector stack; letting it leak into tests makes
results depend on whose laptop runs them (and can call paid LLM APIs). Tests
set every variable they need explicitly via monkeypatch instead.

This runs at collection time, before any test module builds a gateway.
"""
import agentshield.config as _config

_config._load_dotenv = lambda: None
