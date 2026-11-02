#!/usr/bin/env pwsh
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Checks the Windows modules' scripts with PowerShell's own parser.
#
#   pwsh scripts/ps-rules.ps1 <file.ps1>...
#
# Every script: values arrive as param($A), so no $Args, no making code from
# strings, and -LiteralPath because -Path treats [ and * as wildcards.
# read_*.ps1 too: commands and methods only from the lists below, since a plan
# must change nothing on the host. Exits 1 if any rule is broken.
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Files)

$readCommands = 'Get-CimInstance', 'Get-Item', 'Get-ItemProperty', 'Get-NetIPAddress', 'Get-NetRoute',
  'Get-NetTCPConnection', 'Get-Service', 'Import-Module', 'Select-Object', 'Sort-Object', 'Test-Path', 'Where-Object', 'ForEach-Object'
$readImports = 'CimCmdlets', 'NetTCPIP'
$readMethods = 'GetCurrent', 'IsInRole', 'ToString'
$bannedText = 'Win32_Product'

$failed = 0
function Report($file, $ast, $why) {
  Write-Output "$($file):$($ast.Extent.StartLineNumber): $why"
  $script:failed++
}
foreach ($file in $Files) {
  $errors = $null
  $tree = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $file), [ref]$null, [ref]$errors)
  foreach ($e in $errors) { Write-Output "$($file): parse error: $($e.Message)"; $failed++ }
  $isRead = (Split-Path -Leaf $file) -like 'read_*'
  $all = $tree.FindAll({ $true }, $true)
  foreach ($a in $all) {
    switch ($a.GetType().Name) {
      'VariableExpressionAst' {
        if ($a.VariablePath.UserPath -ieq 'args') { Report $file $a 'use param($A) and $A.name, not $Args' }
      }
      'CommandParameterAst' {
        if ($a.ParameterName -ieq 'Path') { Report $file $a 'use -LiteralPath, not -Path' }
      }
      'CommandAst' {
        $name = $a.GetCommandName()
        if ($name -in 'Invoke-Expression', 'iex') { Report $file $a "$name makes code from a string" }
        if ($isRead) {
          if (-not $name) { Report $file $a 'a read script may only call commands by name' }
          elseif ($name -notin $readCommands) { Report $file $a "$name isn't on the list of read commands" }
          elseif ($name -eq 'Import-Module') {
            foreach ($e in $a.CommandElements | Select-Object -Skip 1) {
              foreach ($v in $e.FindAll({ param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
                if ($v.Value -notin $readImports) { Report $file $v "Import-Module $($v.Value) isn't on the list" }
              }
            }
          }
        }
      }
      'InvokeMemberExpressionAst' {
        $m = $a.Member.Extent.Text
        if ($m -ieq 'Create' -and $a.Expression.Extent.Text -imatch 'scriptblock') { Report $file $a '[scriptblock]::Create makes code from a string' }
        if ($isRead -and $m -notin $readMethods) { Report $file $a "method $m isn't on the list for read scripts" }
      }
      'FileRedirectionAst' {
        if ($isRead -and $a.Location.Extent.Text -notin '$null') { Report $file $a 'a read script may not write to a file' }
      }
      'StringConstantExpressionAst' {
        if ($isRead -and $a.Value -imatch $bannedText) { Report $file $a "$bannedText can trigger an MSI repair" }
      }
    }
  }
}
if ($failed) { Write-Output "$failed problem(s)"; exit 1 }
Write-Output "$($Files.Count) script(s) pass"
