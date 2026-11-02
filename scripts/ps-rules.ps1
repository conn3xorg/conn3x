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
# read_*.ps1 too: commands and methods only from the lists below, and no setting
# properties, since a plan must change nothing on the host. Prints each problem
# and exits 1 if any rule is broken.
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Files)

$readCommands = 'Get-Acl', 'Get-CimInstance', 'Get-FileHash', 'Get-Item', 'Get-ItemProperty', 'Get-NetIPAddress', 'Get-NetRoute', 'Get-WindowsFeature',
  'Get-LocalGroup', 'Get-LocalGroupMember', 'Get-LocalUser', 'Get-NetTCPConnection', 'Get-Service', 'Import-Module', 'Select-Object', 'Sort-Object', 'Test-Path', 'Where-Object', 'ForEach-Object'
$readImports = 'CimCmdlets', 'Microsoft.PowerShell.LocalAccounts', 'NetTCPIP', 'ServerManager'
# Types and methods together: a name alone would pass [IO.File]::Replace for
# [BitConverter]'s text, or [IO.File]::Create for [SHA256]::Create.
$readStatic = 'BitConverter::GetBytes', 'BitConverter::ToString', 'BitConverter::ToUInt32', 'BitConverter::ToUInt64', 'Convert::ToBase64String',
  'IO.Path::GetDirectoryName', 'Security.Cryptography.SHA256::Create', 'Security.Principal.SecurityIdentifier::new', 'Security.Principal.WindowsIdentity::GetCurrent',
  'string::Join'
$readInstance = 'Close', 'ComputeHash', 'GetAccessRules', 'GetBytes', 'GetOwner', 'GetType', 'GetValue', 'GetValueKind', 'Invoke', 'InvokeMember', 'IsInRole', 'OpenSubKey',
  'Replace', 'ToLowerInvariant', 'ToString', 'Translate'
# Cmdlets that treat a positional argument as a -Path, with their usual aliases.
$pathCommands = 'Add-Content', 'Clear-Content', 'Clear-Item', 'Copy-Item', 'Get-Acl', 'Get-ChildItem', 'Get-Content', 'Get-FileHash', 'Get-Item', 'Get-ItemProperty', 'Invoke-Item',
  'Move-Item', 'Remove-Item', 'Rename-Item', 'Resolve-Path', 'Set-Acl', 'Set-Content', 'Set-Item', 'Set-ItemProperty', 'Set-Location', 'Test-Path',
  'ac', 'cat', 'cd', 'copy', 'cp', 'del', 'dir', 'gc', 'gci', 'gi', 'gp', 'ii', 'ls', 'move', 'mv', 'rd', 'ren', 'ri', 'rm', 'rni', 'rvpa', 'sc', 'si', 'sl', 'sp', 'type'
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
  # A read may fill in a table it made itself, and set nothing else's properties.
  $tables = @{}
  foreach ($a in $all | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left -is [Management.Automation.Language.VariableExpressionAst] }) {
    $name = $a.Left.VariablePath.UserPath
    $isTable = $a.Right.Extent.Text -match '^@\{'
    if (-not $tables.ContainsKey($name)) { $tables[$name] = $isTable } else { $tables[$name] = $tables[$name] -and $isTable }
  }
  function Test-OwnTable($target) {
    while ($target -is [Management.Automation.Language.MemberExpressionAst] -or $target -is [Management.Automation.Language.IndexExpressionAst]) {
      if ($target -is [Management.Automation.Language.MemberExpressionAst] -and $target.Static) { return $false }
      $target = if ($target -is [Management.Automation.Language.MemberExpressionAst]) { $target.Expression } else { $target.Target }
    }
    ($target -is [Management.Automation.Language.VariableExpressionAst]) -and $tables[$target.VariablePath.UserPath]
  }
  foreach ($a in $all) {
    switch ($a.GetType().Name) {
      'VariableExpressionAst' {
        if ($a.VariablePath.UserPath -ieq 'args') { Report $file $a 'use param($A) and $A.name, not $Args' }
        # $env: and scope qualifiers are fine; a filesystem or registry drive, as in ${C:\x}, reads or writes the host.
        if ($isRead -and $a.VariablePath.IsDriveQualified -and $a.VariablePath.DriveName.ToLowerInvariant() -notin 'env', 'global', 'local', 'script', 'private', 'using', 'variable') {
          Report $file $a "a read script may not use the $($a.VariablePath.DriveName): drive through a variable"
        }
      }
      'CommandParameterAst' {
        # PowerShell takes any unambiguous start of a name, so -Pa is -Path.
        if ('Path'.StartsWith($a.ParameterName, [StringComparison]::OrdinalIgnoreCase)) { Report $file $a 'use -LiteralPath, not -Path' }
      }
      'CommandAst' {
        $name = $a.GetCommandName()
        if ($name -in 'Invoke-Expression', 'iex') { Report $file $a "$name makes code from a string" }
        if ($name -in $pathCommands) {
          $literal = $a.CommandElements | Where-Object { $_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -match '^(L|Li|Lit|Lite|Liter|Litera|Literal|LiteralP|LiteralPa|LiteralPat|LiteralPath|LP|PSPath)$' }
          if (-not $literal) { Report $file $a "use -LiteralPath with $name, as a positional path is a -Path" }
        }
        if ($isRead) {
          if (-not $name) { Report $file $a 'a read script may only call commands by name' }
          elseif ($name -eq 'Install-WindowsFeature') {
            $whatIf = $a.CommandElements | Where-Object { $_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -ieq 'WhatIf' -and -not $_.Argument }
            if (-not $whatIf) { Report $file $a 'a read script may run Install-WindowsFeature only with -WhatIf' }
          }
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
        if ($isRead) {
          $who = $a.Expression.Extent.Text
          if ($a.Static) {
            $type = if ($a.Expression -is [Management.Automation.Language.TypeExpressionAst]) { $a.Expression.TypeName.FullName } else { $who }
            if ("${type}::$m" -notin $readStatic) { Report $file $a "${type}::$m isn't on the list for read scripts" }
          }
          elseif ($m -notin $readInstance) { Report $file $a "method $m isn't on the list for read scripts" }
          # FileInfo has a Replace, and a registry key opens for writing.
          elseif ($m -ieq 'Replace' -and $who -notmatch '^\(\[BitConverter\]::ToString\(') { Report $file $a 'a read script may use Replace only on the text from [BitConverter]::ToString' }
          # ADSI runs any method by name: a read may only list members and read a SID.
          elseif ($m -ieq 'Invoke' -and ($a.Arguments.Count -ne 1 -or $a.Arguments[0].Extent.Text -ine "'Members'")) { Report $file $a "a read script may use Invoke only as Invoke('Members')" }
          elseif ($m -ieq 'InvokeMember' -and ($a.Arguments.Count -lt 2 -or $a.Arguments[0].Extent.Text -ine "'objectSid'" -or $a.Arguments[1].Extent.Text -ine "'GetProperty'")) { Report $file $a "a read script may use InvokeMember only to get objectSid" }
          elseif ($m -ieq 'OpenSubKey' -and ($a.Arguments.Count -ne 2 -or $a.Arguments[1].Extent.Text -ine '$false')) { Report $file $a 'OpenSubKey in a read script must say $false for writable' }
        }
      }
      'AssignmentStatementAst' {
        if ($isRead -and $a.Left -isnot [Management.Automation.Language.VariableExpressionAst] -and -not (Test-OwnTable $a.Left)) { Report $file $a 'a read script may not set a property of something it did not make' }
      }
      'UnaryExpressionAst' {
        if ($isRead -and $a.TokenKind -in 'PlusPlus', 'MinusMinus', 'PostfixPlusPlus', 'PostfixMinusMinus' -and $a.Child -isnot [Management.Automation.Language.VariableExpressionAst] -and -not (Test-OwnTable $a.Child)) { Report $file $a 'a read script may not set a property of something it did not make' }
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
