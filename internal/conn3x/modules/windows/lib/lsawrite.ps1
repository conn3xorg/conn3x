# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# Grants and revokes user rights through the LSA policy. Named apart from
# read_user_right.ps1's Conn3xLsaRead, so one can't stand in for the other.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class Conn3xLsaWrite
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
    static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, LsaUnicodeString[] rights, uint count);

    [DllImport("advapi32.dll")]
    static extern uint LsaRemoveAccountRights(IntPtr policy, byte[] sid, [MarshalAs(UnmanagedType.U1)] bool allRights, LsaUnicodeString[] rights, uint count);

    [DllImport("advapi32.dll")]
    static extern uint LsaClose(IntPtr policy);

    [DllImport("advapi32.dll")]
    static extern int LsaNtStatusToWinError(uint status);

    static void Check(uint status)
    {
        if (status != 0)
        {
            throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(status));
        }
    }

    // Grants right to each SID in add and revokes it from each in remove.
    public static void Change(string right, string[] add, string[] remove)
    {
        LsaObjectAttributes attributes = new LsaObjectAttributes();
        attributes.Length = Marshal.SizeOf(typeof(LsaObjectAttributes));
        IntPtr policy;
        // POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, as granting needs.
        Check(LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x00000810, out policy));
        try
        {
            LsaUnicodeString[] rights = new LsaUnicodeString[1];
            rights[0].Buffer = right;
            rights[0].Length = (ushort)(right.Length * 2);
            rights[0].MaximumLength = (ushort)(right.Length * 2 + 2);
            foreach (string s in add)
            {
                Check(LsaAddAccountRights(policy, Bytes(s), rights, 1));
            }
            foreach (string s in remove)
            {
                Check(LsaRemoveAccountRights(policy, Bytes(s), false, rights, 1));
            }
        }
        finally
        {
            LsaClose(policy);
        }
    }

    static byte[] Bytes(string sid)
    {
        SecurityIdentifier id = new SecurityIdentifier(sid);
        byte[] b = new byte[id.BinaryLength];
        id.GetBinaryForm(b, 0);
        return b;
    }
}
'@
