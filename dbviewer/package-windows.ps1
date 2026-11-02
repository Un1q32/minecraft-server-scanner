$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$toolsRoot = Join-Path $workspaceRoot 'viewer-build-tools'
$qtRoot = Join-Path $toolsRoot 'qt\6.8.3\mingw_64'
$compilerBin = Join-Path $toolsRoot 'toolchain\Tools\mingw1310_64\bin'
$env:PATH = "$compilerBin;$qtRoot\bin;$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:QMAKE = Join-Path $qtRoot 'bin\qmake.exe'
$env:CARGO_TARGET_DIR = Join-Path $toolsRoot 'target'
$env:CXXSTDLIB = 'static=stdc++'
$env:CARGO_ENCODED_RUSTFLAGS = '-Lnative=' + (Join-Path $toolsRoot 'toolchain\Tools\mingw1310_64\lib\gcc\x86_64-w64-mingw32\13.1.0')
$appFolder = Join-Path $env:LOCALAPPDATA 'Programs\MC Server DB Viewer'
$database = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Minecraft Server Database\servers.db'

Push-Location $PSScriptRoot
try {
    $env:DBVIEWER_TEST_PYTHON = Join-Path $toolsRoot 'python\Scripts\python.exe'
    & "$env:USERPROFILE\.cargo\bin\cargo.exe" test --release --locked -- --include-ignored
    if ($LASTEXITCODE -ne 0) { throw 'Rust viewer tests failed.' }
    & "$env:USERPROFILE\.cargo\bin\cargo.exe" build --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust viewer release build failed.' }
    New-Item -ItemType Directory -Path $appFolder -Force | Out-Null
    $executable = Join-Path $appFolder 'dbviewer.exe'
    Copy-Item -LiteralPath (Join-Path $env:CARGO_TARGET_DIR 'release\dbviewer.exe') -Destination $executable -Force
    foreach ($backendFile in 'mcscan.py','scanner.py','qt_helpers.py','db_format.py') {
        Copy-Item -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) $backendFile) -Destination $appFolder -Force
    }
    Set-Content -LiteralPath (Join-Path $appFolder 'python-path.txt') -Value (Join-Path $toolsRoot 'python\Scripts\python.exe') -Encoding utf8NoBOM
    & (Join-Path $qtRoot 'bin\windeployqt.exe') --release --qmldir (Join-Path $PSScriptRoot 'qml') --no-translations $executable
    if ($LASTEXITCODE -ne 0) { throw 'Qt runtime deployment failed.' }
    foreach ($runtimeDll in 'libgcc_s_seh-1.dll','libstdc++-6.dll','libwinpthread-1.dll') {
        Copy-Item -LiteralPath (Join-Path $compilerBin $runtimeDll) -Destination $appFolder -Force
    }

    $initialHash = (Get-FileHash -LiteralPath $database -Algorithm SHA256).Hash
    $stdout = Join-Path $toolsRoot 'viewer-selftest.log'
    $stderr = Join-Path $toolsRoot 'viewer-selftest-errors.log'
    $testProcess = Start-Process -FilePath $executable -ArgumentList @('--selftest', ('"' + $database + '"')) -WorkingDirectory $appFolder -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
    Get-Content -LiteralPath $stdout
    Get-Content -LiteralPath $stderr
    if ($testProcess.ExitCode -ne 0) { throw "Viewer self-test failed: $($testProcess.ExitCode)" }
    if ((Get-FileHash -LiteralPath $database -Algorithm SHA256).Hash -ne $initialHash) { throw 'Viewer unexpectedly changed the database.' }

    $shortcutShell = New-Object -ComObject WScript.Shell
    $shortcut = $shortcutShell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'MC Server DB Viewer.lnk'))
    $shortcut.TargetPath = $executable
    $shortcut.Arguments = '"' + $database + '" --sort last_seen:desc'
    $shortcut.WorkingDirectory = $appFolder
    $shortcut.Description = 'Rust Minecraft database viewer with manual server tools'
    $shortcut.IconLocation = "$executable,0"
    $shortcut.Save()
    Write-Output "Installed: $executable"
    Write-Output "Database: $database"
    Write-Output 'Database checksum is unchanged after load, search, detail, and sort checks.'
} finally {
    Pop-Location
}
