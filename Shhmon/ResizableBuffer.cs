using System;
using System.Runtime.InteropServices;

namespace Shhmon
{
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
                    string.Format("Desired size should be greater than zero and lesser than {0}", maxBufferSize));
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
                Win32.ZeroMemory(buffer, (uint)byteLength);
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
}
