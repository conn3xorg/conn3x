param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$root = if ($A.user) { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
$key = $root.CreateSubKey($A.key)
$changed = $false
try {
  $old = $key.GetValue($A.name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  if ($A.absent) {
    if ($null -ne $old) { $key.DeleteValue($A.name, $false); $changed = $true }
  } else {
    # Keep a String or ExpandString as it is: Path is ExpandString, so its
    # %SystemRoot% stays unexpanded. A new value with % in it is ExpandString.
    $string = [Microsoft.Win32.RegistryValueKind]::String
    $expand = [Microsoft.Win32.RegistryValueKind]::ExpandString
    $kind = if ($A.value.Contains('%')) { $expand } else { $string }
    $same = $false
    if ($null -ne $old) {
      $oldKind = $key.GetValueKind($A.name)
      if ($oldKind -eq $string -or $oldKind -eq $expand) {
        $kind = $oldKind
        $same = $old -ceq [string]$A.value
      }
    }
    if (-not $same) { $key.SetValue($A.name, [string]$A.value, $kind); $changed = $true }
  }
} finally { $key.Close() }
if (-not $changed) { return }
# Tell Explorer and other listening programs the environment changed, as
# Ansible's win_environment does, so a program Explorer starts next sees it
# without a new logon. The value is already written: a hung window, a timeout
# or no desktop at all must not fail the step, so any failure is ignored.
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class Conn3xSettingChange
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr SendMessageTimeoutW(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);

    // HWND_BROADCAST, WM_SETTINGCHANGE "Environment", SMTO_ABORTIFHUNG, 5 s.
    public static bool Environment()
    {
        UIntPtr result;
        return SendMessageTimeoutW(new IntPtr(0xFFFF), 0x001A, UIntPtr.Zero, "Environment", 0x0002, 5000, out result) != IntPtr.Zero;
    }
}
'@
  $null = [Conn3xSettingChange]::Environment()
} catch { $null = $_ }
