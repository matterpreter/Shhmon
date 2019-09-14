using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Shhmon
{
    class FilterParser
    {
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

                        hr = Win32.FilterFindFirst(Win32.FilterInformationClass.FilterAggregateStandardInformation, buffer.DangerousGetPointer(), (uint)buffer.ByteLength, out bytesReturned, out filterFindHandle);

                        if (hr == Win32.ErrorInsufficientBuffer)
                        {
                            buffer.Resize(unchecked((int)bytesReturned));
                            hr = Win32.FilterFindFirst(Win32.FilterInformationClass.FilterAggregateStandardInformation, buffer.DangerousGetPointer(), (uint)buffer.ByteLength, out bytesReturned, out filterFindHandle);
                        }

                        if (hr != Win32.Ok)
                        {
                            // There are no filters available.
                            if (hr == Win32.ErrorNoMoreItems)
                            {
                                return result;
                            }

                            throw Marshal.GetExceptionForHR(unchecked((int)hr));
                        }

                        result.AddRange(MarshalFilterInfo(buffer.DangerousGetPointer()));

                        while (true)
                        {
                            hr = Win32.FilterFindNext(filterFindHandle, Win32.FilterInformationClass.FilterAggregateStandardInformation, buffer.DangerousGetPointer(), (uint)buffer.ByteLength, out bytesReturned);
                            if (hr == Win32.ErrorInsufficientBuffer)
                            {
                                buffer.Resize(unchecked((int)bytesReturned));
                                hr = Win32.FilterFindNext(filterFindHandle, Win32.FilterInformationClass.FilterAggregateStandardInformation, buffer.DangerousGetPointer(), (uint)buffer.ByteLength, out bytesReturned);
                            }

                            if (hr != Win32.Ok)
                            {
                                if (hr == Win32.ErrorNoMoreItems)
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
                        string message = string.Format("Unable to get the filter driver information: 0x{0:X8}", hr);

                        throw new InvalidOperationException(message, e);
                    }
                    finally
                    {
                        if (filterFindHandle != IntPtr.Zero)
                        {
                            Win32.FilterFindClose(filterFindHandle);
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
                Win32.FilterAggregateStandardInformation aggregateInfo = (Win32.FilterAggregateStandardInformation)Marshal.PtrToStructure(curPtr, typeof(Win32.FilterAggregateStandardInformation));
                IntPtr infoPtr = curPtr + Win32.FilterAggregateStandardInformation.GetStructureOffset();

                FilterInfo filterInfo = new FilterInfo();

                //// The following code is not very 'clear', but adding a separate method for parsing Name and Altitude fields is redundant.

                // Whether the structure contains legacy or minifilter information.
                if (aggregateInfo.Flags == Win32.FilterAggregateStandardInformation.FltflAsiIsMinifilter)
                {
                    Win32.FilterAggregateStandardMiniFilterInformation info = (Win32.FilterAggregateStandardMiniFilterInformation)Marshal.PtrToStructure(infoPtr, typeof(Win32.FilterAggregateStandardMiniFilterInformation));
                    filterInfo.FrameId = unchecked((int)info.FrameId);
                    filterInfo.Instances = unchecked((int)info.NumberOfInstances);

                    filterInfo.Name = Marshal.PtrToStringUni(curPtr + info.FilterNameBufferOffset, info.FilterNameLength / UnicodeEncoding.CharSize);
                    filterInfo.Altitude = int.Parse(Marshal.PtrToStringUni(curPtr + info.FilterAltitudeBufferOffset, info.FilterAltitudeLength / UnicodeEncoding.CharSize));
                }
                else if (aggregateInfo.Flags == Win32.FilterAggregateStandardInformation.FltflAsiIsLegacyfilter)
                {
                    Win32.FilterAggregateStandardLegacyFilterInformation info = (Win32.FilterAggregateStandardLegacyFilterInformation)Marshal.PtrToStructure(infoPtr, typeof(Win32.FilterAggregateStandardLegacyFilterInformation));
                    filterInfo.Name = Marshal.PtrToStringUni(curPtr + info.FilterNameBufferOffset, info.FilterNameLength / UnicodeEncoding.CharSize);
                    filterInfo.Altitude = int.Parse(Marshal.PtrToStringUni(curPtr + info.FilterAltitudeBufferOffset, info.FilterAltitudeLength / UnicodeEncoding.CharSize));
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
    }

}
