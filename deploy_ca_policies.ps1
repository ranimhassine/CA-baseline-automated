# ======= CONFIGURATION =======
$tenantId     = "d01f5e5e-d665-406a-aabc-246c69f24fda"
$clientId     = "d37bafef-ae8e-4533-a871-c0f06782d5e6"
$clientSecret = "~Lg8Q~G6XiBgEZU3vmquP9lICVc_G2ErJqtgDcmG"

# ======= AUTHENTICATE TO MICROSOFT GRAPH =======
$tokenBody = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

Write-Host "`n🔐 Getting access token..." -ForegroundColor Yellow
$tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $tokenBody
$accessToken = $tokenResponse.access_token

if (-not $accessToken) {
    Write-Error "❌ Failed to retrieve access token."
    exit 1
}

# ======= DEPLOY POLICIES =======
$policyFolder = "."
$policyFiles = Get-ChildItem -Path $policyFolder -Filter *.json

Write-Host "`n🚀 Starting deployment of $($policyFiles.Count) Conditional Access policies..." -ForegroundColor Cyan

foreach ($file in $policyFiles) {
    $policyName = $file.Name
    Write-Host "`n📄 Deploying policy: $policyName" -ForegroundColor Blue
    try {
        $policyJson = Get-Content -Raw -Path $file.FullName
        $response = Invoke-RestMethod -Method Post `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
            -Headers @{ Authorization = "Bearer $accessToken" } `
            -Body $policyJson `
            -ContentType "application/json"

        Write-Host "✅ Successfully deployed: $($response.displayName)" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to deploy $policyName" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
}

Write-Host "`n🎉 All done!" -ForegroundColor Green
