using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Shhmon
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("yeet");
            List<FilterInfo> filterInfo = GetFiltersInformation();
            foreach (var filter in filterInfo)
            {
                Console.WriteLine("{0} is running at altitude {1}", filter.Name, filter.Altitude);
            }

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

                        // If the buffer allocated is not large enough to hold all data returned, resize it and try again.
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

        /// <summary>
        /// Marshals the filter info objects from the <paramref name="ptr"/> specified.
        /// </summary>
        /// <param name="ptr">Pointer to the buffer with the filter information structures to marshal.</param>
        /// <returns>List of filter information structures marshaled.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="ptr"/> is equal to the <see cref="IntPtr.Zero"/>.</exception>
        /// <exception cref="InvalidOperationException">Filter information structure contains invalid data.</exception>
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
    }

    public class ResizableBuffer : IDisposable
    {
        #region Fields

        /// <summary>
        /// Synchronization root.
        /// </summary>
        private readonly object syncRoot = new object();

        /// <summary>
        /// Maximum buffer size.
        /// </summary>
        /// <remarks>
        /// Current value is <c>5 Mb</c>.
        /// </remarks>
        private readonly int maxBufferSize = Math.Max(5 * 1024 * 1024, Environment.SystemPageSize);

        /// <summary>
        /// Pointer to the buffer allocated.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2006:UseSafeHandleToEncapsulateNativeResources", Justification = "This class manually manages this buffer.")]
        private IntPtr buffer = IntPtr.Zero;

        /// <summary>
        /// Size of the internal buffer, in bytes.
        /// </summary>
        private volatile int byteLength;

        /// <summary>
        /// Whether the current instance is already disposed.
        /// </summary>
        private volatile bool isDisposed;

        #endregion // Fields

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="ResizableBuffer"/> class.
        /// </summary>
        /// <exception cref="InvalidOperationException">Buffer was not allocated.</exception>
        /// <remarks>
        /// The <see cref="Environment.SystemPageSize"/> is passed as an initial size.
        /// </remarks>
        public ResizableBuffer()
            : this(Environment.SystemPageSize)
        {
            // Do nothing.
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ResizableBuffer"/> class.
        /// </summary>
        /// <param name="initialSize">Initial buffer size.</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="initialSize"/> is lesser or equal to zero or greater than the maximum size allowed.</exception>
        /// <exception cref="InvalidOperationException">Buffer was not allocated.</exception>
        public ResizableBuffer(int initialSize)
        {
            this.EnsureBufferIsOfTheRightSize(initialSize);
        }

        /// <summary>
        /// Finalizes an instance of the <see cref="ResizableBuffer"/> class.
        /// </summary>
        ~ResizableBuffer()
        {
            this.Dispose(false);
        }

        #endregion // Constructor

        #region Properties

        /// <summary>
        /// Gets the size of the allocated buffer.
        /// </summary>
        public int ByteLength
        {
            get
            {
                lock (this.syncRoot)
                {
                    if (this.isDisposed)
                    {
                        throw new ObjectDisposedException("Buffer is already disposed.");
                    }

                    return this.byteLength;
                }
            }
        }

        /// <summary>
        /// Gets a value indicating whether the buffer is already disposed.
        /// </summary>
        public bool Disposed
        {
            get
            {
                return this.isDisposed;
            }
        }

        #endregion // Properties

        #region Public methods

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Gets the pointer to the internal buffer.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Buffer is already disposed.</exception>
        /// <returns>Pointer to the internal buffer.</returns>
        /// <remarks>
        /// Be careful with the pointer returned, because it may become invalid after the next
        /// <see cref="Resize"/> function call and after the <see cref="ResizableBuffer"/>
        /// instance is disposed.
        /// </remarks>
        public IntPtr DangerousGetPointer()
        {
            lock (this.syncRoot)
            {
                if (this.isDisposed)
                {
                    throw new ObjectDisposedException("Buffer is already disposed.");
                }

                return this.buffer;
            }
        }

        /// <summary>
        /// Resizes the buffer.
        /// </summary>
        /// <param name="newSize">The desired buffer size.</param>
        /// <remarks>
        /// Be careful with the pointer returned, because it may become invalid after the next <see cref="Resize"/> function call and after the
        /// <see cref="ResizableBuffer"/> instance is disposed.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Buffer is already disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="newSize"/> is lesser or equal to zero or greater than the maximum size allowed.</exception>
        public void Resize(int newSize)
        {
            lock (this.syncRoot)
            {
                if (this.isDisposed)
                {
                    throw new ObjectDisposedException("Buffer is already disposed.");
                }

                this.EnsureBufferIsOfTheRightSize(newSize);
            }
        }

        #endregion // Public methods

        #region Protected methods

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources; <see langword="false"/> to release only unmanaged resources.
        /// </param>
        protected virtual void Dispose(bool disposing)
        {
            lock (this.syncRoot)
            {
                if (this.buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(this.buffer);

                    this.buffer = IntPtr.Zero;
                    this.byteLength = 0;
                }

                this.isDisposed = true;
            }
        }

        #endregion // Protected methods

        #region Private methods

        /// <summary>
        /// Ensures that the current buffer can store the <paramref name="newSize"/> bytes.
        /// If the current buffer is not large enough, it's extended.
        /// </summary>
        /// <param name="newSize">The desired buffer size.</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="newSize"/> is lesser or equal to zero or greater than the maximum size allowed.</exception>
        /// <exception cref="InvalidOperationException">Buffer was not allocated or extended.</exception>
        private void EnsureBufferIsOfTheRightSize(int newSize)
        {
            if (newSize <= 0 || newSize > this.maxBufferSize)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(newSize),
                    string.Format(CultureInfo.InvariantCulture, "Desired size should be greater than zero and lesser than {0}", this.maxBufferSize));
            }

            // Skip, if the buffer is already large enough.
            if (this.byteLength >= newSize)
            {
                return;
            }

            try
            {
                // Is it initial allocation or we need to extend the buffer?
                this.buffer = this.buffer == IntPtr.Zero
                              ? Marshal.AllocHGlobal(newSize)
                              : Marshal.ReAllocHGlobal(this.buffer, new IntPtr(newSize));

                this.byteLength = newSize;
                NativeMethods.ZeroMemory(this.buffer, (uint)this.byteLength);
            }
            catch (OutOfMemoryException oom)
            {
                this.buffer = IntPtr.Zero;
                this.byteLength = 0;

                throw new InvalidOperationException("Unable to allocate or extend the buffer.", oom);
            }
        }

        #endregion // Private methods
    }

    internal static class NativeMethods
    {
        #region Constants

        /// <summary>
        /// Windows return code for successful operations.
        /// </summary>
        public const uint Ok = 0;

        /// <summary>
        /// The I/O operation has been aborted because of either a thread exit or an application request.
        /// </summary>
        public const uint ErrorOperationAborted = 0x800703E3;

        /// <summary>
        /// Overlapped I/O operation is in progress.
        /// </summary>
        public const uint ErrorIoPending = 0x800703E5;

        /// <summary>
        /// The wait operation timed out.
        /// </summary>
        public const uint WaitTimeout = 0x80070102;

        /// <summary>
        /// Cannot create a file when that file already exists.
        /// </summary>
        public const uint ErrorAlreadyExists = 0x800700B7;

        /// <summary>
        /// The system cannot find the file specified.
        /// </summary>
        public const uint ErrorFileNotFound = 0x80070002;

        /// <summary>
        /// An instance of the service is already running.
        /// </summary>
        public const uint ErrorServiceAlreadyRunning = 0x80070420;

        /// <summary>
        /// Executable is not a valid Win32 application.
        /// </summary>
        public const uint ErrorBadExeFormat = 0x800700C1;

        /// <summary>
        /// The specified driver is invalid.
        /// </summary>
        public const uint ErrorBadDriver = 0x800707D1;

        /// <summary>
        /// The hash for the image cannot be found in the system catalogs.
        /// The image is likely corrupt or the victim of tampering.
        /// </summary>
        public const uint ErrorInvalidImageHash = 0x80070241;

        /// <summary>
        /// An instance already exists at this altitude on the volume specified.
        /// </summary>
        public const uint ErrorFltInstanceAltitudeCollision = 0x801F0011;

        /// <summary>
        /// An instance already exists with this name on the volume specified.
        /// </summary>
        public const uint ErrorFltInstanceNameCollision = 0x801F0012;

        /// <summary>
        /// The system could not find the filter specified.
        /// </summary>
        public const uint ErrorFltFilterNotFound = 0x801F0013;

        /// <summary>
        /// The system could not find the instance specified.
        /// </summary>
        public const uint ErrorFltInstanceNotFound = 0x801F0015;

        /// <summary>
        /// Element not found.
        /// </summary>
        public const uint ErrorNotFound = 0x80070490;

        /// <summary>
        /// No more data is available.
        /// </summary>
        public const uint ErrorNoMoreItems = 0x80070103;

        /// <summary>
        /// The data area passed to a system call is too small.
        /// </summary>
        public const uint ErrorInsufficientBuffer = 0x8007007A;

        #endregion //Constants

        #region Enums

        /// <summary>
        /// Type of filter driver information to be passed to the <see cref="NativeMethods.FilterFindFirst"/>
        /// and <see cref="NativeMethods.FilterFindNext"/> methods.
        /// </summary>
        internal enum FilterInformationClass
        {
            /// <summary>
            /// To return the FILTER_FULL_INFORMATION structure.
            /// </summary>
            FilterFullInformation = 0,

            /// <summary>
            /// To return the FILTER_AGGREGATE_BASIC_INFORMATION structure.
            /// </summary>
            FilterAggregateBasicInformation,

            /// <summary>
            /// To return the FILTER_AGGREGATE_STANDARD_INFORMATION structure.
            /// </summary>
            FilterAggregateStandardInformation
        }

        #endregion // Enums

        #region fltlib.dll
        [DllImport("fltlib.dll")]
        public static extern uint FilterLoad(
            /* [in] */ [MarshalAs(UnmanagedType.LPWStr)] string filterName);

        [DllImport("fltlib.dll")]
        public static extern uint FilterUnload(
            /* [in] */ [MarshalAs(UnmanagedType.LPWStr)] string filterName);

        [DllImport("fltlib.dll")]
        public static extern uint FilterDetach(
            /* [in] */ [MarshalAs(UnmanagedType.LPWStr)] string filterName,
            /* [in] */ [MarshalAs(UnmanagedType.LPWStr)] string volumeName,
            /* [in] */ [MarshalAs(UnmanagedType.LPWStr)] string instanceName);

        [DllImport("fltlib.dll")]
        public static extern uint FilterFindFirst(
            /* [in]  */ [MarshalAs(UnmanagedType.I4)] FilterInformationClass informationClass,
            /* [in]  */ IntPtr buffer,
            /* [in]  */ uint bufferSize,
            /* [out] */ out uint bytesReturned,
            /* [out] */ out IntPtr filterFind);

        [DllImport("fltlib.dll")]
        public static extern uint FilterFindNext(
            /* [in]  */ IntPtr filterFind,
            /* [in]  */ [MarshalAs(UnmanagedType.I4)] FilterInformationClass informationClass,
            /* [in]  */ IntPtr buffer,
            /* [in]  */ uint bufferSize,
            /* [out] */ out uint bytesReturned);

        [DllImport("fltlib.dll")]
        public static extern uint FilterFindClose(
            /* [in] */ IntPtr filterFind);

        #endregion // fltlib.dll

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void ZeroMemory(
            /* [in] */ IntPtr handle,
            /* [in] */ uint length);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FilterAggregateStandardInformation
    {
        /// <summary>
        /// The <see cref="Flags"/> value, if this structure contains the
        /// <see cref="FilterAggregateStandardMiniFilterInformation"/> structure.
        /// </summary>
        public const uint FltflAsiIsMinifilter = 0x00000001;

        /// <summary>
        /// The <see cref="Flags"/> value, if this structure contains the
        /// <see cref="FilterAggregateStandardLegacyFilterInformation"/> structure.
        /// </summary>
        public const uint FltflAsiIsLegacyfilter = 0x00000002;

        /// <summary>
        /// Byte offset of the next <see cref="FilterAggregateStandardInformation"/> entry,
        /// if multiple entries are present in a buffer.
        /// </summary>
        /// <remarks>
        /// This member is zero if no other entries follow this one.
        /// </remarks>
        [MarshalAs(UnmanagedType.U4)]
        public uint NextEntryOffset;

        /// <summary>
        /// Indicates whether the filter driver is a legacy filter or a MiniFilter.
        /// </summary>
        [MarshalAs(UnmanagedType.U4)]
        public uint Flags;

        /// <summary>
        /// ULONG field to get the union offset from.
        /// </summary>
        [MarshalAs(UnmanagedType.U4)]
        public uint StructureOffset;

        /// <summary>
        /// Gets the offset of the structure with the detailed filter information.
        /// </summary>
        /// <returns>Information structure offset within the current structure.</returns>
        public static int GetStructureOffset()
        {
            return Marshal.OffsetOf(typeof(FilterAggregateStandardInformation), nameof(StructureOffset)).ToInt32();
        }
    }

    /// <summary>
    /// Nested structure in the <see cref="FilterAggregateStandardInformation"/> for MiniFilters.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FilterAggregateStandardMiniFilterInformation
    {
        /// <summary>
        /// Reserved field.
        /// </summary>
        [MarshalAs(UnmanagedType.U4)]
        public uint Flags;

        /// <summary>
        /// Zero-based index used to identify the filter manager frame that the MiniFilter is in.
        /// </summary>
        [MarshalAs(UnmanagedType.U4)]
        public uint FrameId;

        /// <summary>
        /// Number of instances that currently exist for the MiniFilter.
        /// </summary>
        [MarshalAs(UnmanagedType.U4)]
        public uint NumberOfInstances;

        /// <summary>
        /// Length, in bytes, of the MiniFilter name string.
        /// </summary>
        [MarshalAs(UnmanagedType.U2)]
        public ushort FilterNameLength;

        /// <summary>
        /// Byte offset (relative to the beginning of the structure) of the first character
        /// of the Unicode MiniFilter name string.
        /// </summary>
        [MarshalAs(UnmanagedType.U2)]
        public ushort FilterNameBufferOffset;

        /// <summary>
        /// Length, in bytes, of the MiniFilter altitude string.
        /// </summary>
        [MarshalAs(UnmanagedType.U2)]
        public ushort FilterAltitudeLength;

        /// <summary>
        /// Byte offset (relative to the beginning of the structure) of the first character
        /// of the Unicode MiniFilter altitude string.
        /// </summary>
        [MarshalAs(UnmanagedType.U2)]
        public ushort FilterAltitudeBufferOffset;
    }

    /// <summary>
    /// Nested structure in the <see cref="FilterAggregateStandardInformation"/> for the legacy filters.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FilterAggregateStandardLegacyFilterInformation
    {
        /// <summary>
        /// Reserved field.
        /// </summary>
        [MarshalAs(UnmanagedType.U4)]
        public uint Flags;

        /// <summary>
        /// Length, in bytes, of the legacy filter name string.
        /// </summary>
        [MarshalAs(UnmanagedType.U2)]
        public ushort FilterNameLength;

        /// <summary>
        /// Byte offset (relative to the beginning of the structure) of the first character
        /// of the Unicode legacy filter name string.
        /// </summary>
        [MarshalAs(UnmanagedType.U2)]
        public ushort FilterNameBufferOffset;

        /// <summary>
        /// Length, in bytes, of the legacy filter altitude string.
        /// </summary>
        [MarshalAs(UnmanagedType.U2)]
        public ushort FilterAltitudeLength;

        /// <summary>
        /// Byte offset (relative to the beginning of the structure) of the first character
        /// of the Unicode legacy filter altitude string.
        /// </summary>
        [MarshalAs(UnmanagedType.U2)]
        public ushort FilterAltitudeBufferOffset;
    }
}
