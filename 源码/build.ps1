$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$output = Join-Path (Split-Path $PSScriptRoot -Parent) 'ClearWebGuard.exe'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ ("/out:"+$output) ("/win32manifest:"+(Join-Path $PSScriptRoot 'app.manifest')) /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll ("/resource:"+(Join-Path $PSScriptRoot 'engine.ps1')+',engine.ps1') (Join-Path $PSScriptRoot 'Program.cs')
if ($LASTEXITCODE -ne 0) { throw 'Compilation failed' }
Get-FileHash -LiteralPath $output -Algorithm SHA256
