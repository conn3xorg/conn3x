# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Shared by apply_package.ps1 and apply_download.ps1.

# Save-Download downloads into $file, following up to five redirects itself so
# none can drop from https to http unless that's allowed, and stops at $max
# bytes. A partial file is left for the caller to delete.
function Save-Download([string]$url, $out, [long]$max, [bool]$allowHttp) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $uri = New-Object Uri($url)
  for ($hop = 0; $hop -le 5; $hop++) {
    if ($uri.Scheme -ne 'https' -and -not ($allowHttp -and $uri.Scheme -eq 'http')) {
      throw "the download went to a $($uri.Scheme) address, $($uri.Host); only https is allowed, or http with allow_http"
    }
    # A connection dropped before any answer is tried again, twice; an answer,
    # even an error, is final.
    $res = $null
    for ($try = 1; -not $res; $try++) {
      $req = [Net.WebRequest]::Create($uri)
      $req.AllowAutoRedirect = $false
      $req.KeepAlive = $false
      try { $res = $req.GetResponse() } catch {
        # PowerShell wraps a method's exception, so look inside for the
        # WebException: its response carries the HTTP status.
        $we = $_.Exception
        while ($we -and $we -isnot [Net.WebException]) { $we = $we.InnerException }
        if ($we -and $we.Response) { $res = $we.Response }
        elseif ($try -ge 3) { throw }
        else { Start-Sleep -Seconds 2 }
      }
    }
    $code = [int]$res.StatusCode
    if ($code -ge 300 -and $code -lt 400) {
      $next = $res.Headers['Location']
      $res.Close()
      if (-not $next) { throw "the download redirected (HTTP $code) without saying where" }
      $uri = New-Object Uri($uri, $next)
      continue
    }
    if ($code -ne 200) { $res.Close(); throw "the download failed with HTTP $code" }
    if ($res.ContentLength -gt $max) { $res.Close(); throw "the download is $($res.ContentLength) bytes, more than max_size_mb allows" }
    $in = $res.GetResponseStream()
    try {
      $buf = New-Object byte[] 65536
      $total = [long]0
      while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) {
        $total += $n
        if ($total -gt $max) { throw "the download is more than max_size_mb allows" }
        $out.Write($buf, 0, $n)
      }
    } finally { $in.Dispose(); $res.Close() }
    return
  }
  throw 'the download redirected more than five times'
}
