# find_api.ps1
Write-Host "🔍 Searching for API routes..." -ForegroundColor Green

# Find all Python files
$pythonFiles = Get-ChildItem -Recurse -Filter "*.py" | Where-Object { 
    $_.FullName -notmatch "__pycache__" -and $_.FullName -notmatch "venv" 
}

Write-Host "Found $($pythonFiles.Count) Python files" -ForegroundColor Yellow

# Search for route patterns
$routePatterns = @(
    "@app\.route",
    "@api\.route", 
    "@bp\.route",
    "Blueprint",
    "/api/"
)

foreach ($file in $pythonFiles) {
    $content = Get-Content $file.FullName -Raw
    $foundRoutes = @()
    
    foreach ($pattern in $routePatterns) {
        if ($content -match $pattern) {
            $foundRoutes += $pattern
        }
    }
    
    if ($foundRoutes.Count -gt 0) {
        Write-Host "`n📁 $($file.FullName)" -ForegroundColor Cyan
        Write-Host "   Found: $($foundRoutes -join ', ')" -ForegroundColor White
        
        # Show specific route lines
        $lines = Get-Content $file.FullName
        for ($i = 0; $i -lt $lines.Count; $i++) {
            foreach ($pattern in $routePatterns) {
                if ($lines[$i] -match $pattern) {
                    Write-Host "   Line $($i+1): $($lines[$i].Trim())" -ForegroundColor Gray
                }
            }
        }
    }
}

Write-Host "`n✅ API discovery complete!" -ForegroundColor Green