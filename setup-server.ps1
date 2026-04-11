## FIFA 17 FUT Private Server - Bootstrap Script
## Run this in PowerShell as Administrator from C:\Users\Jad\fifa17-server

$base = "C:\Users\Jad\fifa17-server"

# Create directory structure
New-Item -ItemType Directory -Force -Path "$base\src\blaze" | Out-Null

# package.json
@'
{
  "name": "fifa17-fut-server",
  "version": "0.1.0",
  "description": "FIFA 17 Ultimate Team Private Server",
  "type": "module",
  "scripts": {
    "dev": "npx tsx watch src/index.ts",
    "start": "npx tsx src/index.ts"
  },
  "dependencies": {
    "express": "^4.18.2",
    "tsx": "^4.6.0",
    "typescript": "^5.3.2",
    "@types/express": "^4.17.21",
    "@types/node": "^20.10.0"
  }
}
'@ | Set-Content "$base\package.json" -Encoding UTF8

Write-Host "Installing dependencies..."
Set-Location $base
npm install

Write-Host "Setup complete! Run the server with:"
Write-Host "  cd C:\Users\Jad\fifa17-server"
Write-Host "  npm start"
