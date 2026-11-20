param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# No cmdlet reads a user right, so this compiles a small LSA type that opens
# the policy for lookups only. scripts/ps-rules.ps1 pins its text: any change
# to it there or here fails the rules.
Add-Type -TypeDefinition @'
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
$out = @{ holders = @([Conn3xLsaRead]::Accounts([string]$A.name)); sids = @{} }
foreach ($p in @($A.principals)) {
  if (-not $p) { continue }
  try {
    if ($p -match '^S-1-[0-9-]+$') { $out.sids[$p] = ([Security.Principal.SecurityIdentifier]$p).Value }
    else {
      # LSA doesn't take .\ for this computer, as a logon does.
      $n = $p -replace '^\.\\', ($env:COMPUTERNAME + '\')
      $out.sids[$p] = ([Security.Principal.NTAccount]$n).Translate([Security.Principal.SecurityIdentifier]).Value
    }
  } catch { $out.sids[$p] = '' }
}
$out
