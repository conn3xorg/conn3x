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

$readCommands = 'Get-Acl', 'Get-ADDomain', 'Get-ADGroup', 'Get-ADObject', 'Get-ADOrganizationalUnit', 'Get-ADUser', 'Get-CimInstance', 'Get-DnsClientServerAddress', 'Get-FileHash', 'Get-Item', 'Get-ItemProperty', 'Get-NetIPAddress', 'Get-NetRoute', 'Get-WindowsFeature', 'Get-WindowsOptionalFeature', 'Get-TimeZone',
  'Get-LocalGroup', 'Get-LocalGroupMember', 'Get-LocalUser', 'Get-NetFirewallAddressFilter', 'Get-NetFirewallPortFilter', 'Get-NetFirewallRule', 'Get-NetFirewallProfile', 'Get-NetFirewallApplicationFilter', 'Get-NetFirewallServiceFilter', 'Get-NetConnectionProfile',
  'Get-NetTCPConnection', 'Get-ScheduledTask', 'Get-Service', 'Get-SmbShare', 'Get-SmbShareAccess', 'Get-DnsServerZone', 'Get-DnsServerResourceRecord', 'Import-Module', 'Select-Object', 'Sort-Object', 'Start-Sleep', 'Test-Path', 'Where-Object', 'ForEach-Object'
# Start-Sleep only waits: read_pending_reboot.ps1 waits out Windows servicing.
# Get-TimeZone only reads: read_timezone.ps1 lists the zones with -ListAvailable.
# The firewall profile, filter and connection-profile commands only read: read_firewall_profile.ps1
# lists the rules in force for the lockout check, and ExpandEnvironmentVariables only expands a
# rule's program path to compare it with sshd's.
# Get-WindowsOptionalFeature only reads DISM's list of features.
# GetEnvironmentVariable only reads one, and read_choco_package.ps1 reads a .nuspec with an
# XmlReader, whose settings prohibit a DTD and fetch nothing.
$readImports = 'ActiveDirectory', 'CimCmdlets', 'DnsClient', 'NetConnection', 'Microsoft.PowerShell.LocalAccounts', 'NetSecurity', 'NetTCPIP', 'ScheduledTasks', 'ServerManager'
# Types and methods together: a name alone would pass [IO.File]::Replace for
# [BitConverter]'s text, or [IO.File]::Create for [SHA256]::Create.
# DirectorySearcher only searches; read_ad_group.ps1 pages through a big
# group's members with it, and sets its PageSize and Filter, as on any search
# it makes. NTAccount only names an account: Translate asks LSA for its SID.
$readStatic = 'BitConverter::GetBytes', 'BitConverter::ToString', 'BitConverter::ToUInt32', 'BitConverter::ToUInt64', 'Convert::ToBase64String',
  'DirectoryServices.DirectorySearcher::new',
  'Environment::ExpandEnvironmentVariables', 'IO.File::ReadAllBytes', 'IO.Path::GetDirectoryName', 'Microsoft.Web.Administration.ServerManager::new', 'Reflection.Assembly::Load',
  'Security.Cryptography.SHA256::Create', 'Security.Principal.NTAccount::new', 'Security.Principal.SecurityIdentifier::new', 'Security.Principal.WindowsIdentity::GetCurrent',
  'string::Join', 'Conn3xLsaRead::Accounts', 'Environment::GetEnvironmentVariable', 'Xml.XmlReader::Create'
$readInstance = 'Close', 'ComputeHash', 'CreateUpdateSearcher', 'Dispose', 'FindAll', 'Search', 'GetAccessRules', 'GetBytes', 'GetOwner', 'GetType', 'GetValue', 'GetValueKind', 'Invoke', 'InvokeMember', 'IsInRole', 'OpenSubKey',
  'Replace', 'ToLowerInvariant', 'ToString', 'Translate', 'ReadToFollowing', 'ReadElementContentAsString'
# Cmdlets that treat a positional argument as a -Path, with their usual aliases.
$pathCommands = 'Add-Content', 'Clear-Content', 'Clear-Item', 'Copy-Item', 'Get-Acl', 'Get-ChildItem', 'Get-Content', 'Get-FileHash', 'Get-Item', 'Get-ItemProperty', 'Invoke-Item',
  'Move-Item', 'Remove-Item', 'Rename-Item', 'Resolve-Path', 'Set-Acl', 'Set-Content', 'Set-Item', 'Set-ItemProperty', 'Set-Location', 'Test-Path',
  'ac', 'cat', 'cd', 'copy', 'cp', 'del', 'dir', 'gc', 'gci', 'gi', 'gp', 'ii', 'ls', 'move', 'mv', 'rd', 'ren', 'ri', 'rm', 'rni', 'rvpa', 'sc', 'si', 'sl', 'sp', 'type'
$bannedText = 'Win32_Product'
# The one type a read script may compile: read_user_right.ps1's, which opens
# the LSA policy for lookups only (0x801, a literal) and lists who holds a
# right. It's pinned as text, not a hash, so a change to it is a diff here.
# Windows PowerShell 5.1 compiles it with csc.exe, through temporary files.
$lsaReadType = @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

// Lists who holds a user right. It opens the local LSA policy with
// POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION (0x801) and nothing
// else, a literal here, so no caller can ask for more: it can read rights,
// never change them.
public static class Conn3xLsaRead
{
    [StructLayout(LayoutKind.Sequential)]
    struct LsaObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LsaUnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public string Buffer;
    }

    [DllImport("advapi32.dll")]
    static extern uint LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes attributes, uint access, out IntPtr policy);

    [DllImport("advapi32.dll")]
    static extern uint LsaEnumerateAccountsWithUserRight(IntPtr policy, ref LsaUnicodeString right, out IntPtr buffer, out uint count);

    [DllImport("advapi32.dll")]
    static extern uint LsaFreeMemory(IntPtr buffer);

    [DllImport("advapi32.dll")]
    static extern uint LsaClose(IntPtr policy);

    [DllImport("advapi32.dll")]
    static extern int LsaNtStatusToWinError(uint status);

    const uint StatusNoMoreEntries = 0x8000001A;
    const uint StatusNoSuchPrivilege = 0xC0000060;

    public static string[] Accounts(string right)
    {
        LsaObjectAttributes attributes = new LsaObjectAttributes();
        attributes.Length = Marshal.SizeOf(typeof(LsaObjectAttributes));
        IntPtr policy;
        uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x00000801, out policy);
        if (status != 0)
        {
            throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(status));
        }
        try
        {
            LsaUnicodeString name = new LsaUnicodeString();
            name.Buffer = right;
            name.Length = (ushort)(right.Length * 2);
            name.MaximumLength = (ushort)(right.Length * 2 + 2);
            IntPtr buffer;
            uint count;
            status = LsaEnumerateAccountsWithUserRight(policy, ref name, out buffer, out count);
            if (status == StatusNoMoreEntries)
            {
                return new string[0];
            }
            if (status == StatusNoSuchPrivilege)
            {
                throw new ArgumentException("Windows has no user right named " + right);
            }
            if (status != 0)
            {
                throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(status));
            }
            try
            {
                string[] sids = new string[count];
                for (int i = 0; i < count; i++)
                {
                    IntPtr sid = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                    sids[i] = new SecurityIdentifier(sid).Value;
                }
                return sids;
            }
            finally
            {
                LsaFreeMemory(buffer);
            }
        }
        finally
        {
            LsaClose(policy);
        }
    }
}
'@

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
  # Both load a DLL as the script is parsed, before any rule below could matter.
  # pwsh 7 no longer parses #Requires -Assemblies, which 5.1 on the host still
  # honours, so it's matched as text.
  if ($isRead -and (Get-Content -LiteralPath $file -Raw) -imatch '(?m)^\s*#requires\b.*\s-a') { Report $file $tree 'a read script may not load an assembly with #Requires -Assemblies' }
  $all = $tree.FindAll({ $true }, $true)
  # A read may fill in a table it made itself, or set up a directory search it
  # made, and set nothing else's properties.
  $tables = @{}
  foreach ($a in $all | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left -is [Management.Automation.Language.VariableExpressionAst] }) {
    $name = $a.Left.VariablePath.UserPath
    $isTable = $a.Right.Extent.Text -match '^(@\{|\[DirectoryServices\.DirectorySearcher\]::new\()'
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
          elseif ($name -eq 'Add-Type') {
            # Only read_user_right.ps1, and only the pinned type, as the one argument.
            $rest = @($a.CommandElements | Select-Object -Skip 1)
            $ok = (Split-Path -Leaf $file) -eq 'read_user_right.ps1' -and $rest.Count -eq 2 -and $rest[0].Extent.Text -ceq '-TypeDefinition' -and
              $rest[1] -is [Management.Automation.Language.StringConstantExpressionAst] -and ($rest[1].Value -replace "`r", '') -ceq ($lsaReadType -replace "`r", '')
            if (-not $ok) { Report $file $a 'a read script may use Add-Type only in read_user_right.ps1, as -TypeDefinition with the type pinned in ps-rules.ps1' }
          }
          elseif ($name -eq 'New-Object') {
            # Only Windows Update's session, whose searcher reads and changes nothing.
            $parts = @($a.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text })
            if (($parts -join ' ') -ne '-ComObject Microsoft.Update.Session') { Report $file $a 'a read script may use New-Object only as New-Object -ComObject Microsoft.Update.Session' }
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
            # Loading an assembly runs its initialisers: only the IIS one, by its full name.
            elseif ("${type}::$m" -eq 'Reflection.Assembly::Load' -and ($a.Arguments.Count -ne 1 -or $a.Arguments[0].Extent.Text -cne "'Microsoft.Web.Administration, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'")) { Report $file $a 'a read script may load only Microsoft.Web.Administration, by its full name' }
            # Opened any other way, a ServerManager can commit changes to IIS.
            elseif ("${type}::$m" -eq 'Microsoft.Web.Administration.ServerManager::new' -and ($a.Arguments.Count -ne 2 -or $a.Arguments[0].Extent.Text -ine '$true')) { Report $file $a 'ServerManager in a read script must be opened read-only, with $true first' }
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
      'UsingStatementAst' {
        if ($isRead -and $a.UsingStatementKind -eq 'Assembly') { Report $file $a 'a read script may not load an assembly with using assembly' }
      }
      'StringConstantExpressionAst' {
        if ($isRead -and $a.Value -imatch $bannedText) { Report $file $a "$bannedText can trigger an MSI repair" }
      }
    }
  }
}
if ($failed) { Write-Output "$failed problem(s)"; exit 1 }
Write-Output "$($Files.Count) script(s) pass"
