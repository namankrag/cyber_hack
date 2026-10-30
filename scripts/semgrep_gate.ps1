# Semgrep SAST gate (runs OUTSIDE the project venv).
# semgrep pins mcp==1.29.0, which conflicts with this repo's mcp==2.3.0,
# so it lives in an isolated venv under %TEMP% and never touches .venv.
# (`python -m semgrep` shim exits silently here, so we call click's main.)
$ErrorActionPreference = "Stop"
$ToolsVenv = Join-Path $env:TEMP "semgrep_venv"
$Py = Join-Path $ToolsVenv "Scripts\python.exe"
if (-not (Test-Path $Py)) {
  python -m venv $ToolsVenv
  & $Py -m pip install -q semgrep
}
$Repo = Split-Path -Parent $PSScriptRoot
& $Py -c "import sys; sys.argv=['semgrep']+sys.argv[1:]; from semgrep.main import main; main()" scan --config p/python --config p/owasp-top-ten --config p/security-audit --error --json -o (Join-Path $Repo "semgrep.json") $Repo
exit $LASTEXITCODE
