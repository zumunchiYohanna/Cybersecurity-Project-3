$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$sourceRoot = Join-Path $projectRoot "src"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Project virtual-environment Python was not found at $python"
}

$previousPythonPath = $env:PYTHONPATH
if ([string]::IsNullOrWhiteSpace($previousPythonPath)) {
    $env:PYTHONPATH = $sourceRoot
} else {
    $env:PYTHONPATH = "$sourceRoot;$previousPythonPath"
}

Push-Location -LiteralPath $projectRoot
try {
    Write-Host "Starting ThreatLens Local at http://127.0.0.1:5000"
    Write-Host "The server is loopback-only. Press Ctrl+C to stop it."
    & $python -m cyber_assessment.web
    if ($LASTEXITCODE -ne 0) {
        throw "The local web application exited with code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
    if ([string]::IsNullOrEmpty($previousPythonPath)) {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    } else {
        $env:PYTHONPATH = $previousPythonPath
    }
}
