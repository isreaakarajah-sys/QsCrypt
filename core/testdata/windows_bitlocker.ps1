# Creates BitLocker containers (fixed VHDs) with QsCrypt, then asks Windows
# itself to mount them and unlock them with the password and the recovery
# password. Informational: hosted runners may lack the BitLocker feature.
$ErrorActionPreference = 'Continue'
$probe = Join-Path $PWD 'core\target\release\examples\bdeprobe.exe'
$work = Join-Path $env:RUNNER_TEMP 'qs'
New-Item -ItemType Directory -Force $work | Out-Null
$pw = 'QsCrypt-Password-1'
$fail = 0
Write-Host "== Windows $([Environment]::OSVersion.VersionString)"
Get-Command manage-bde, Unlock-BitLocker -ErrorAction SilentlyContinue | Format-Table Name, Source | Out-String | Write-Host
try { Get-WindowsFeature *BitLocker* | Format-Table Name, InstallState | Out-String | Write-Host } catch {}
foreach ($combo in @('exfat xts128', 'fat xts256', 'exfat cbc128')) {
  $fs, $m = $combo.Split(' ')
  $img = Join-Path $work "qs-$fs-$m.vhd"
  $rp = & $probe vhd $img 134217728 $fs $pw $m
  if ($LASTEXITCODE -ne 0) { Write-Host "FAIL create $combo"; $fail = 1; continue }
  foreach ($cred in @('password', 'recovery')) {
    try {
      $di = Mount-DiskImage -ImagePath $img -StorageType VHD -PassThru -ErrorAction Stop
      Start-Sleep -Seconds 3
      $disk = $di | Get-Disk
      $part = $disk | Get-Partition | Where-Object { $_.Type -ne 'Reserved' } | Select-Object -First 1
      Write-Host "PASS Windows mounted the VHD $combo : disk $($disk.Number), partition at $($part.Offset), $($part.Size) bytes"
      if (-not $part.DriveLetter) { $part | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; $part = $disk | Get-Partition | Select-Object -First 1 }
      $root = "$($part.DriveLetter):"
      manage-bde -status $root | Out-String | Write-Host
      if ($cred -eq 'password') {
        manage-bde -unlock $root -Password $pw 2>&1 | Out-String | Write-Host
        if ($LASTEXITCODE -ne 0) {
          $sec = ConvertTo-SecureString $pw -AsPlainText -Force
          Unlock-BitLocker -MountPoint $root -Password $sec -ErrorAction SilentlyContinue | Out-Null
        }
      } else {
        manage-bde -unlock $root -RecoveryPassword $rp 2>&1 | Out-String | Write-Host
      }
      $hello = Get-Content "$root\hello.txt" -ErrorAction Stop
      $big = (Get-Item "$root\مجلد\big.bin" -ErrorAction Stop).Length
      if ($hello -eq 'QsCrypt BitLocker' -and $big -eq 5000000) { Write-Host "PASS Windows unlocked $combo with the $cred" } else { Write-Host "FAIL content $combo : $hello $big"; $fail = 1 }
      chkdsk $root | Out-String | Write-Host
    } catch {
      Write-Host "FAIL $combo ($cred): $($_.Exception.Message)"; $fail = 1
    } finally {
      Dismount-DiskImage -ImagePath $img -ErrorAction SilentlyContinue | Out-Null
    }
  }
}
exit $fail
