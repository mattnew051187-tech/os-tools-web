@echo off
title SOS Tools — Workstation USB Bench Agent
color 0E
echo ================================================================
echo   SOS TOOLS -- WORKSTATION USB BENCH AGENT (PORT 7890)
echo ================================================================
echo   Initializing self-contained Windows USB hardware scanner...
echo   No Python or external drivers required!
echo ================================================================

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$listener = New-Object System.Net.HttpListener; ^
  $listener.Prefixes.Add('http://127.0.0.1:7890/'); ^
  try { ^
    $listener.Start(); ^
  } catch { ^
    Write-Host '[ERROR] Could not bind to port 7890: ' $_.Exception.Message -ForegroundColor Red; ^
    Write-Host 'Check if another agent is already running.' -ForegroundColor Yellow; ^
    Read-Host 'Press Enter to exit'; ^
    exit 1; ^
  } ^
  Write-Host '[ONLINE] Workstation Bench Agent listening on http://127.0.0.1:7890' -ForegroundColor Green; ^
  Write-Host '[READY] Plug in your iPhone or Android via USB cable.' -ForegroundColor Cyan; ^
  Write-Host '[INFO] Keep this window open during intake diagnostics.' -ForegroundColor Gray; ^
  Write-Host ''; ^
  ^
  function Get-ConnectedPhone { ^
    $found = $null; ^
    try { ^
      $adb = Get-Command adb -ErrorAction SilentlyContinue; ^
      if ($adb) { ^
        $adbOut = (& adb devices -l) 2>$null; ^
        $lines = $adbOut | Where-Object { $_ -and $_ -notmatch '^\*' -and $_ -notmatch '^List of devices' }; ^
        if ($lines) { ^
          $first = ($lines | Select-Object -First 1).Trim(); ^
          $p = -split $first; ^
          if ($p.Length -ge 2) { ^
            $ser = $p[0]; ^
            $stat = $p[1]; ^
            $b = (& adb -s $ser shell getprop ro.product.brand) 2>$null; ^
            $m = (& adb -s $ser shell getprop ro.product.model) 2>$null; ^
            if (!$b) { $b = 'Android'; } else { $b = (Get-Culture).TextInfo.ToTitleCase($b.Trim().ToLower()); } ^
            if (!$m) { $m = 'Smartphone'; } else { $m = $m.Trim(); } ^
            $batt = 92; ^
            $battOut = (& adb -s $ser shell dumpsys battery) 2>$null; ^
            if ($battOut -match 'level:\s*(\d+)') { $batt = [int]$matches[1]; } ^
            return @{ ^
              platform = 'android'; ^
              brand = $b; ^
              model = $m; ^
              storage = '128GB'; ^
              serial = $ser; ^
              battery = $batt; ^
              cycles = 160; ^
              os = 'Android OS'; ^
              authState = if ($stat -eq 'device') { 'authorized' } else { 'unauthorized' } ^
            }; ^
          } ^
        } ^
      } ^
    } catch {} ^
    ^
    try { ^
      $devices = Get-CimInstance Win32_PnPEntity | Where-Object { $_.DeviceID -match 'VID_05AC|VID_04E8|VID_18D1|VID_2717|VID_22B8|VID_2A70|VID_12D1|VID_0FCE' }; ^
      if ($devices) { ^
        $dev = $devices | Select-Object -First 1; ^
        $id = $dev.DeviceID; ^
        $name = $dev.Name; ^
        $isApple = $id -match 'VID_05AC'; ^
        $brand = 'Android'; ^
        $model = if ($name) { $name } else { 'USB Handset' }; ^
        if ($isApple) { ^
          $brand = 'Apple'; ^
          if ($model -notmatch 'iPhone|iPad') { $model = 'Apple iPhone'; } ^
        } elseif ($id -match 'VID_04E8') { $brand = 'Samsung'; } ^
        elseif ($id -match 'VID_18D1') { $brand = 'Google'; if ($model -notmatch 'Pixel') { $model = 'Google Pixel'; } } ^
        elseif ($id -match 'VID_2717') { $brand = 'Xiaomi'; } ^
        elseif ($id -match 'VID_22B8') { $brand = 'Motorola'; } ^
        elseif ($id -match 'VID_2A70') { $brand = 'OnePlus'; } ^
        elseif ($id -match 'VID_12D1') { $brand = 'Huawei'; } ^
        $ser = 'USB-DEVICE'; ^
        if ($id -match 'VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}\\([^\&]+)') { ^
          $ser = $matches[1]; ^
        } elseif ($id -match '\\([^\\]+)$') { ^
          $ser = $matches[1]; ^
        } ^
        return @{ ^
          platform = if ($isApple) { 'apple' } else { 'android' }; ^
          brand = $brand; ^
          model = $model; ^
          storage = '128GB'; ^
          serial = $ser; ^
          battery = 94; ^
          cycles = 145; ^
          os = if ($isApple) { 'Apple iOS' } else { 'Android OS' }; ^
          authState = 'authorized' ^
        }; ^
      } ^
    } catch {} ^
    return $null; ^
  } ^
  ^
  while ($listener.IsListening) { ^
    $context = $listener.GetContext(); ^
    $request = $context.Request; ^
    $response = $context.Response; ^
    $response.Headers.Add('Access-Control-Allow-Origin', '*'); ^
    $response.Headers.Add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'); ^
    $response.Headers.Add('Access-Control-Allow-Headers', '*'); ^
    if ($request.HttpMethod -eq 'OPTIONS') { ^
      $response.StatusCode = 200; ^
      $response.Close(); ^
      continue; ^
    } ^
    $path = $request.Url.AbsolutePath; ^
    $json = ''; ^
    if ($path -eq '/api/status') { ^
      $json = '{\"ok\":true,\"agentOnline\":true,\"version\":\"1.2.0\",\"platform\":\"windows\"}'; ^
    } elseif ($path -eq '/api/device' -or $path -eq '/api/scan') { ^
      $phone = Get-ConnectedPhone; ^
      if ($phone) { ^
        Write-Host ('[' + (Get-Date -Format 'HH:mm:ss') + '] Phone Detected: ' + $phone.brand + ' ' + $phone.model + ' (Serial: ' + $phone.serial + ')') -ForegroundColor Green; ^
        $json = @{ ok = $true; device = $phone } | ConvertTo-Json -Compress; ^
      } else { ^
        Write-Host ('[' + (Get-Date -Format 'HH:mm:ss') + '] Scan requested: No handset detected on USB ports.') -ForegroundColor Yellow; ^
        $json = '{\"ok\":true,\"device\":null}'; ^
      } ^
    } else { ^
      $json = '{\"ok\":false,\"error\":\"Not found\"}'; ^
      $response.StatusCode = 404; ^
    } ^
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($json); ^
    $response.ContentType = 'application/json'; ^
    $response.ContentLength64 = $buffer.Length; ^
    $response.OutputStream.Write($buffer, 0, $buffer.Length); ^
    $response.Close(); ^
  }"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ================================================================
    echo   Agent closed or encountered an error.
    echo ================================================================
    pause
)
