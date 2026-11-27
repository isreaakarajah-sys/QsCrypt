# NTFS writing checked by Windows itself.
#  1. Windows formats a VHD; QsCrypt fills it (thousands of changes), then
#     Windows mounts it: chkdsk must find no problems and every file must
#     read back exactly as QsCrypt's model expects.
#  2. Windows writes into it; QsCrypt must still check clean and write again;
#     chkdsk once more.
#  3. The disks formatted by mkntfs and written by QsCrypt on Linux (see
#     ntfs_compat.sh) go through chkdsk and the same comparison.
$ErrorActionPreference = 'Stop'
$probe = (Resolve-Path 'core\target\release\examples\fsprobe.exe').Path
$manifest = 'core\testdata\manifest.py'
$work = "$env:RUNNER_TEMP\ntfs"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$env:PYTHONUTF8 = '1'
$script:fail = 0
$tops = @('stress', 'from-qscrypt', 'churn', 'linux', 'churn2', 'stress2', 'windows')

function Dp([string]$text) {
    $f = "$work\dp.txt"
    $text | Set-Content -Path $f -Encoding ascii
    $out = diskpart /s $f | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Host $out; throw "diskpart failed" }
}

function Attach([string]$vhd, [string]$letter) {
    Dp "select vdisk file=`"$vhd`"`r`nattach vdisk`r`nselect partition 1`r`nassign letter=$letter"
    for ($i = 0; $i -lt 30 -and -not (Test-Path "$letter`:\"); $i++) { Start-Sleep -Seconds 1 }
}

function Detach([string]$vhd) {
    Dp "select vdisk file=`"$vhd`"`r`ndetach vdisk"
}

function Check([string]$letter, [string]$label) {
    fsutil dirty query "$letter`:" | Out-Host
    $out = chkdsk "$letter`:" 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host $out
    # mkntfs picks journal sizes Windows would not: chkdsk then only wants to
    # resize $LogFile (which QsCrypt never changes). Anything else fails.
    $problems = $out -match '(?im)^\s*(Errors found|Found |.*\bis (incorrect|invalid|corrupt)|Deleting|Correcting|Replacing|Inserting|Recovering|Cleaning up \d+ unused)'
    $onlyLog = $out -match 'adjusting the size of the log file' -and -not $problems
    if ($code -eq 0 -and $out -match 'found no problems') {
        Write-Host "PASS chkdsk $label"
    } elseif ($onlyLog) {
        Write-Host "PASS chkdsk $label (only the journal size mkntfs chose)"
    } else {
        Write-Host "FAIL chkdsk $label (exit $code)"
        $script:fail = 1
    }
}

function Same([string]$a, [string]$b, [string]$label) {
    python $manifest diff $a $b | Out-Host
    if ($LASTEXITCODE -ne 0) { Write-Host "FAIL $label"; $script:fail = 1 } else { Write-Host "PASS $label" }
}

function Probe([string[]]$cmd) {
    & $probe @cmd
    if ($LASTEXITCODE -ne 0) { Write-Host "FAIL fsprobe $($cmd -join ' ')"; $script:fail = 1 }
}

function Windows-Writes([string]$letter) {
    New-Item -ItemType Directory -Force -Path "$letter`:\windows\added" | Out-Null
    1..250 | ForEach-Object { Set-Content -Path "$letter`:\windows\added\w$_.txt" -Value "windows $_" }
    $rnd = New-Object byte[] 3000000; (New-Object Random 5).NextBytes($rnd)
    [IO.File]::WriteAllBytes("$letter`:\windows\random.bin", $rnd)
    Copy-Item -Recurse -Path 'core\testdata' -Destination "$letter`:\windows\testdata"
    if (Test-Path "$letter`:\from-qscrypt\fs") { Remove-Item -Recurse -Force -Path "$letter`:\from-qscrypt\fs" }
    if (Test-Path "$letter`:\churn\renamed 004.txt") { Rename-Item -Path "$letter`:\churn\renamed 004.txt" -NewName 'renamed by windows.txt' }
}

# --- 1 + 2: a VHD formatted by Windows
$vhd = "$work\win.vhd"
Dp "create vdisk file=`"$vhd`" maximum=300 type=fixed`r`nselect vdisk file=`"$vhd`"`r`nattach vdisk`r`ncreate partition primary`r`nformat fs=ntfs quick label=QSWIN`r`nassign letter=Q"
New-Item -ItemType Directory -Force -Path 'Q:\linux' | Out-Null
Set-Content -Path 'Q:\linux\hello.txt' -Value 'made on windows before qscrypt'
Detach $vhd
Probe @('stress', "$vhd@1", '/stress', '1500', '3', 'keep')
Probe @('write', "$vhd@1", 'core\crates\qscrypt-core\src', '/from-qscrypt')
Probe @('churn', "$vhd@1", '/churn')
Probe @('check', "$vhd@1")
python $manifest probe $probe "$vhd@1" @tops > "$work\ours.txt"
Attach $vhd 'Q'
Check 'Q' 'Windows-formatted volume after QsCrypt wrote'
python $manifest walk 'Q:\' @tops > "$work\win.txt"
Same "$work\ours.txt" "$work\win.txt" 'Windows reads what QsCrypt wrote'
Windows-Writes 'Q'
Detach $vhd
Probe @('check', "$vhd@1")
Probe @('churn', "$vhd@1", '/churn2')
Probe @('stress', "$vhd@1", '/stress2', '800', '4', 'keep')
Probe @('check', "$vhd@1")
python $manifest probe $probe "$vhd@1" @tops > "$work\ours2.txt"
Attach $vhd 'Q'
Check 'Q' 'after Windows and QsCrypt both wrote'
python $manifest walk 'Q:\' @tops > "$work\win2.txt"
Same "$work\ours2.txt" "$work\win2.txt" 'round trip with Windows writes'
Detach $vhd

# --- 3: disks formatted by mkntfs and written by QsCrypt on Linux
foreach ($d in Get-ChildItem -Path 'ntfs-out' -Filter '*.vhd' -ErrorAction SilentlyContinue) {
    $name = $d.BaseName
    try {
        Attach $d.FullName 'R'
        Check 'R' "$name"
        python $manifest walk 'R:\' @tops > "$work\$name.win.txt"
        Same "ntfs-out\$name.manifest" "$work\$name.win.txt" "$name read by Windows"
        Windows-Writes 'R'
        Detach $d.FullName
        Probe @('check', "$($d.FullName)@1")
        Probe @('churn', "$($d.FullName)@1", '/stress2')
        Probe @('check', "$($d.FullName)@1")
        Attach $d.FullName 'R'
        Check 'R' "$name after Windows and QsCrypt both wrote"
        Detach $d.FullName
    } catch {
        Write-Host "FAIL ${name}: $_"
        $script:fail = 1
        try { Detach $d.FullName } catch {}
    }
}
Copy-Item -Path $vhd -Destination 'ntfs-out\win.vhd' -ErrorAction SilentlyContinue
exit $script:fail
