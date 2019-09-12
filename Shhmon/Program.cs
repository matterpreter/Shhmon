using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Shhmon
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) // We need SeDebugPrivilege for this to work (I think, need to verify)
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    Console.WriteLine("[-] You need administrator rights to interact for this to work.");
                }
            }

            CollectFilterDetails();
        }

        public static void CollectFilterDetails()
        {
            List<FilterInfo> result = new List<FilterInfo>();
            //Hunting for driver at altitude 385201

            uint ERROR_INSUFFICIENT_BUFFER = 2147942522;
            uint ERROR_NO_MORE_ITEMS = 2147942659;
            uint ERROR_SUCCESS = 0;

            //FltUserStructures._FILTER_INFORMATION_CLASS finfo = new FltUserStructures._FILTER_INFORMATION_CLASS();
            uint bytesReturned = 0;
            IntPtr hDevice = IntPtr.Zero;
            IntPtr buffer = Marshal.AllocHGlobal(42);
            uint hr;

            hr = FilterFindFirst(FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, IntPtr.Zero, 0, ref bytesReturned, ref hDevice);

            if (hr.Equals(ERROR_INSUFFICIENT_BUFFER))
            {
                
                Marshal.ReAllocHGlobal(buffer, new IntPtr(bytesReturned));
                RtlZeroMemory(buffer, (int)bytesReturned);
                Console.WriteLine("Resized buffer to " + bytesReturned + " bytes");
                hr = FilterFindFirst(FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, buffer, bytesReturned, ref bytesReturned, ref hDevice);
            }

            if (hr != ERROR_SUCCESS) //Catch generic failure
            {
                Console.WriteLine("HRESULT: " + hr);
                string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                Console.WriteLine("Last Win32 Error: " + errorMessage);
                if (hr.Equals(ERROR_NO_MORE_ITEMS))
                {
                    Console.WriteLine("[-] No drivers found"); 
                    throw Marshal.GetExceptionForHR(unchecked((int)hr));
                }
            }

            //result.AddRange(MarshalFilterInfo(buffer));

            while (true)
            {
                hr = FilterFindNext(hDevice, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, buffer, bytesReturned, out bytesReturned);
                if (hr == ERROR_INSUFFICIENT_BUFFER)
                {
                    Console.WriteLine("Found another driver. Need buffer of length " + bytesReturned );
                    IntPtr buf2 = Marshal.AllocHGlobal((int)bytesReturned);
                    //Marshal.ReAllocHGlobal(buffer, new IntPtr(bytesReturned));
                    RtlZeroMemory(buf2, (int)bytesReturned);
                    Console.WriteLine("Resized buffer to " + bytesReturned + " bytes");
                    hr = FilterFindNext(hDevice, FltUserStructures._FILTER_INFORMATION_CLASS.FilterAggregateBasicInformation, buf2, bytesReturned, out bytesReturned);
                }

                if (hr != ERROR_SUCCESS)
                {
                    if (hr == ERROR_NO_MORE_ITEMS)
                    {
                        Console.WriteLine("Enumerated all drivers. Breaking loop.");
                        break;
                    }

                    throw Marshal.GetExceptionForHR(unchecked((int)hr));
                }

                //result.AddRange(MarshalFilterInfo(buffer));
            }

            if (hDevice != IntPtr.Zero)
            {
                FilterFindClose(hDevice);
            }
            Console.WriteLine("Freeing memory...");
            Marshal.FreeHGlobal(buffer);
            //return result;
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
                FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION aggregateInfo = (FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION)Marshal.PtrToStructure(curPtr, typeof(FltUserStructures._FILTER_AGGREGATE_BASIC_INFORMATION));
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
                else
                {
                    throw new InvalidOperationException(string.Format("Invalid information type received: {0:X8}", aggregateInfo.Flags));
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


























        ////////////////////////////////
        #region pinvokes
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void RtlZeroMemory(IntPtr dest, int size);

        //https://github.com/NetSPI/MonkeyWorks/blob/d9b07315508318ac8069ff1028984c051f5c7ba4/MonkeyWorks/Unmanaged/Libraries/fltlib.cs
        [DllImport("FltLib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern UInt32 FilterDetach(String lpFilterName, String lpVolumeName, String lpInstanceName);

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterInstanceFindClose(IntPtr hFilterInstanceFind);

        [DllImport("FltLib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern UInt32 FilterInstanceFindFirst(
            String lpFilterName,
            FltUserStructures._INSTANCE_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            ref UInt32 lpBytesReturned,
            ref IntPtr lpFilterInstanceFind
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterInstanceFindNext(
            IntPtr hFilterInstanceFind,
            FltUserStructures._INSTANCE_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            ref UInt32 lpBytesReturned
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterFindClose(IntPtr hFilterFind);

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterFindFirst(
            FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            ref UInt32 lpBytesReturned,
            ref IntPtr lpFilterFind
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterFindNext(
            IntPtr hFilterFind,
            FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            out UInt32 lpBytesReturned
        );

        [DllImport("FltLib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern UInt32 FilterUnload(String lpFilterName);
        #endregion pinvokes

        /////////////////////////////////////////////

        #region structs
        //https://github.com/aleksk/LazyCopy/blob/a5334b0aeb7507e1fcc305fd9e3ac5a28fef9d7e/Driver/DriverClientLibrary/FilterInfo.cs
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1815:OverrideEqualsAndOperatorEqualsOnValueTypes", Justification = "Equality comparison is not needed for the current structure.")]
        public struct FilterInfo
        {
            public string Name { get; internal set; }
            public int Altitude { get; internal set; }
            public int? Instances { get; internal set; }
            public int? FrameId { get; internal set; }
        }

        //https://github.com/NetSPI/MonkeyWorks/blob/d9b07315508318ac8069ff1028984c051f5c7ba4/MonkeyWorks/Unmanaged/Headers/FltUserStructures.cs
        public class FltUserStructures
        {
            public enum _FILTER_INFORMATION_CLASS
            {
                FilterFullInformation,
                FilterAggregateBasicInformation,
                FilterAggregateStandardInformation
            }
            //FILTER_INFORMATION_CLASS, *PFILTER_INFORMATION_CLASS;

            [StructLayout(LayoutKind.Sequential)]
            public struct _FILTER_AGGREGATE_BASIC_INFORMATION
            {
                public UInt32 NextEntryOffset;
                public UInt32 Flags;
                public UInt32 FrameID;
                public UInt32 NumberOfInstances;
                public UInt16 FilterNameLength;
                public UInt16 FilterNameBufferOffset;
                public UInt16 FilterAltitudeLength;
                public UInt16 FilterAltitudeBufferOffset;
            }
            //FILTER_AGGREGATE_BASIC_INFORMATION, *PFILTER_AGGREGATE_BASIC_INFORMATION;

            [StructLayout(LayoutKind.Sequential)]
            public struct _FILTER_AGGREGATE_STANDARD_INFORMATION
            {
                public UInt32 NextEntryOffset;
                public UInt32 Flags;
                public UInt32 FrameID;
                public UInt32 NumberOfInstances;
                public UInt16 FilterNameLength;
                public UInt16 FilterNameBufferOffset;
                public UInt16 FilterAltitudeLength;
                public UInt16 FilterAltitudeBufferOffset;
            }
            // FILTER_AGGREGATE_STANDARD_INFORMATION, * PFILTER_AGGREGATE_STANDARD_INFORMATION;

            [StructLayout(LayoutKind.Sequential)]
            public struct _FILTER_FULL_INFORMATION
            {
                public UInt32 NextEntryOffset;
                public UInt32 FrameID;
                public UInt32 NumberOfInstances;
                public UInt16 FilterNameLength;
                public char[] FilterNameBuffer;
            }
            //FILTER_FULL_INFORMATION, *PFILTER_FULL_INFORMATION;

            [Flags]
            public enum _FLT_FILESYSTEM_TYPE
            {
                FLT_FSTYPE_UNKNOWN,
                FLT_FSTYPE_RAW,
                FLT_FSTYPE_NTFS,
                FLT_FSTYPE_FAT,
                FLT_FSTYPE_CDFS,
                FLT_FSTYPE_UDFS,
                FLT_FSTYPE_LANMAN,
                FLT_FSTYPE_WEBDAV,
                FLT_FSTYPE_RDPDR,
                FLT_FSTYPE_NFS,
                FLT_FSTYPE_MS_NETWARE,
                FLT_FSTYPE_NETWARE,
                FLT_FSTYPE_BSUDF,
                FLT_FSTYPE_MUP,
                FLT_FSTYPE_RSFX,
                FLT_FSTYPE_ROXIO_UDF1,
                FLT_FSTYPE_ROXIO_UDF2,
                FLT_FSTYPE_ROXIO_UDF3,
                FLT_FSTYPE_TACIT,
                FLT_FSTYPE_FS_REC,
                FLT_FSTYPE_INCD,
                FLT_FSTYPE_INCD_FAT,
                FLT_FSTYPE_EXFAT,
                FLT_FSTYPE_PSFS,
                FLT_FSTYPE_GPFS,
                FLT_FSTYPE_NPFS,
                FLT_FSTYPE_MSFS,
                FLT_FSTYPE_CSVFS,
                FLT_FSTYPE_REFS,
                FLT_FSTYPE_OPENAFS
            }
            //FLT_FILESYSTEM_TYPE, *PFLT_FILESYSTEM_TYPE;

            [StructLayout(LayoutKind.Sequential)]
            public struct _INSTANCE_AGGREGATE_STANDARD_INFORMATION
            {
                public UInt32 NextEntryOffset;
                public UInt32 Flags;
                public UInt32 FrameID;
                public _FLT_FILESYSTEM_TYPE VolumeFileSystemType;
                public UInt16 InstanceNameLength;
                public UInt16 InstanceNameBufferOffset;
                public UInt16 AltitudeLength;
                public UInt16 AltitudeBufferOffset;
                public UInt16 VolumeNameLength;
                public UInt16 VolumeNameBufferOffset;
                public UInt16 FilterNameLength;
                public UInt16 FilterNameBufferOffset;
                public UInt32 SupportedFeatures;
            }
            //INSTANCE_AGGREGATE_STANDARD_INFORMATION, * PINSTANCE_AGGREGATE_STANDARD_INFORMATION;

            [StructLayout(LayoutKind.Sequential)]
            public struct _INSTANCE_BASIC_INFORMATION
            {
                public UInt32 NextEntryOffset;
                public UInt16 InstanceNameLength;
                public UInt16 InstanceNameBufferOffset;
            }
            //INSTANCE_BASIC_INFORMATION, PINSTANCE_BASIC_INFORMATION;

            [Flags]
            public enum _INSTANCE_INFORMATION_CLASS
            {

                InstanceBasicInformation,
                InstancePartialInformation,
                InstanceFullInformation,
                InstanceAggregateStandardInformation

            }
            //INSTANCE_INFORMATION_CLASS, *PINSTANCE_INFORMATION_CLASS;

            [StructLayout(LayoutKind.Sequential)]
            public struct _INSTANCE_FULL_INFORMATION
            {
                public UInt32 NextEntryOffset;
                public UInt16 InstanceNameLength;
                public UInt16 InstanceNameBufferOffset;
                public UInt16 AltitudeLength;
                public UInt16 AltitudeBufferOffset;
                public UInt16 VolumeNameLength;
                public UInt16 VolumeNameBufferOffset;
                public UInt16 FilterNameLength;
                public UInt16 FilterNameBufferOffset;
            }
            //INSTANCE_FULL_INFORMATION, PINSTANCE_FULL_INFORMATION;

            [StructLayout(LayoutKind.Sequential)]
            public struct _INSTANCE_PARTIAL_INFORMATION
            {
                public UInt32 NextEntryOffset;
                public UInt16 InstanceNameLength;
                public UInt16 InstanceNameBufferOffset;
                public UInt16 AltitudeLength;
                public UInt16 AltitudeBufferOffset;
            }
            //INSTANCE_PARTIAL_INFORMATION, PINSTANCE_PARTIAL_INFORMATION;
            #endregion structs
        }
    }
}