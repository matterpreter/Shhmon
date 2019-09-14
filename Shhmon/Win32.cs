using System;
using System.Runtime.InteropServices;

namespace Shhmon
{
    class Win32
    {
        #region pinvokes

        [DllImport("fltlib.dll")]
        public static extern uint FilterUnload(
            [MarshalAs(UnmanagedType.LPWStr)] string filterName);

        [DllImport("fltlib.dll")]
        public static extern uint FilterFindFirst(
            [MarshalAs(UnmanagedType.I4)] FilterInformationClass informationClass,
            IntPtr buffer,
            uint bufferSize,
            out uint bytesReturned,
            out IntPtr filterFind);

        [DllImport("fltlib.dll")]
        public static extern uint FilterFindNext(
            IntPtr filterFind,
            [MarshalAs(UnmanagedType.I4)] FilterInformationClass informationClass,
            IntPtr buffer,
            uint bufferSize,
            out uint bytesReturned);

        [DllImport("fltlib.dll")]
        public static extern uint FilterFindClose(
            IntPtr filterFind);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void ZeroMemory(
            IntPtr handle,
            uint length);

        [DllImport("kernel32.dll")]
        internal static extern Boolean OpenProcessToken(
            IntPtr hProcess,
            uint dwDesiredAccess,
            out IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            uint BufferLengthInBytes,
            ref TOKEN_PRIVILEGES PreviousState,
            out uint ReturnLengthInBytes);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            ref LUID luid);
        #endregion pinvokes

        #region structs
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public uint HighPart;
        }
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct FilterAggregateStandardInformation
        {
            public const uint FltflAsiIsMinifilter = 0x00000001;
            public const uint FltflAsiIsLegacyfilter = 0x00000002;
            [MarshalAs(UnmanagedType.U4)]
            public uint NextEntryOffset;
            [MarshalAs(UnmanagedType.U4)]
            public uint Flags;
            [MarshalAs(UnmanagedType.U4)]
            public uint StructureOffset;
            public static int GetStructureOffset()
            {
                return Marshal.OffsetOf(typeof(FilterAggregateStandardInformation), nameof(StructureOffset)).ToInt32();
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct FilterAggregateStandardMiniFilterInformation
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint Flags;
            [MarshalAs(UnmanagedType.U4)]
            public uint FrameId;
            [MarshalAs(UnmanagedType.U4)]
            public uint NumberOfInstances;
            [MarshalAs(UnmanagedType.U2)]
            public ushort FilterNameLength;
            [MarshalAs(UnmanagedType.U2)]
            public ushort FilterNameBufferOffset;
            [MarshalAs(UnmanagedType.U2)]
            public ushort FilterAltitudeLength;
            [MarshalAs(UnmanagedType.U2)]
            public ushort FilterAltitudeBufferOffset;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct FilterAggregateStandardLegacyFilterInformation
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint Flags;
            [MarshalAs(UnmanagedType.U2)]
            public ushort FilterNameLength;
            [MarshalAs(UnmanagedType.U2)]
            public ushort FilterNameBufferOffset;
            [MarshalAs(UnmanagedType.U2)]
            public ushort FilterAltitudeLength;
            [MarshalAs(UnmanagedType.U2)]
            public ushort FilterAltitudeBufferOffset;
        }
        #endregion structs

        #region enums
        internal enum FilterInformationClass
        {
            FilterFullInformation = 0,
            FilterAggregateBasicInformation,
            FilterAggregateStandardInformation
        }
        #endregion enums

        #region constants
        public const uint Ok = 0;
        public const uint ErrorOperationAborted = 0x800703E3;
        public const uint ErrorIoPending = 0x800703E5;
        public const uint WaitTimeout = 0x80070102;
        public const uint ErrorAlreadyExists = 0x800700B7;
        public const uint ErrorFileNotFound = 0x80070002;
        public const uint ErrorServiceAlreadyRunning = 0x80070420;
        public const uint ErrorBadExeFormat = 0x800700C1;
        public const uint ErrorBadDriver = 0x800707D1;
        public const uint ErrorInvalidImageHash = 0x80070241;
        public const uint ErrorFltInstanceAltitudeCollision = 0x801F0011;
        public const uint ErrorFltInstanceNameCollision = 0x801F0012;
        public const uint ErrorFltFilterNotFound = 0x801F0013;
        public const uint ErrorFltInstanceNotFound = 0x801F0015;
        public const uint ErrorNotFound = 0x80070490;
        public const uint ErrorNoMoreItems = 0x80070103;
        public const uint ErrorInsufficientBuffer = 0x8007007A;

        public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const uint STANDARD_RIGHTS_READ = 0x00020000;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_IMPERSONATE = 0x0004;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_QUERY_SOURCE = 0x0010;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_ADJUST_GROUPS = 0x0040;
        public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        public const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        public const uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        public const uint SE_PRIVILEGE_ENABLED = 0x2;
        public const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
        public const uint SE_PRIVILEGE_REMOVED = 0x4;
        public const uint SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;
        #endregion constants
    }
}