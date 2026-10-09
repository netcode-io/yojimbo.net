/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2019, The Network Protocol Company, Inc.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
           in the documentation and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived 
           from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace networkprotocol
{
    /*
        C# port notes.

        Upstream allocators hand out raw blocks of memory (void*). Managed code can't do that, so a C# allocator hands out
        objects instead: every YOJIMBO_NEW / YOJIMBO_ALLOCATE passes the allocator a factory that builds the object (an array,
        a message, a channel...) plus the number of bytes it stands for. The allocator decides whether the allocation may
        proceed, builds the object, and tracks it. Freeing an object returns it to the allocator's accounting; the GC reclaims
        the memory.

        What carries over from upstream:

            - the error level (ALLOCATOR_ERROR_OUT_OF_MEMORY), which Connection turns into CONNECTION_ERROR_ALLOCATOR so a
              client that exhausts its allocator is disconnected
            - leak tracking (YOJIMBO_DEBUG_MEMORY_LEAKS, Debug builds): anything still allocated when an allocator is disposed
              is reported and asserts
            - allocation failure: an allocator may refuse an allocation and every library call site handles the null like upstream
            - TLSF_Allocator's contract: a fixed size heap per client, so one client can't exhaust the server's memory

        What stays C++ only:

            - the TLSF heap itself (cpp/tlsf). TLSF_Allocator here is a byte budget over the GC with TLSF-like per-block overhead,
              not a port of the TLSF algorithm.
            - the raw memory blocks backing the client and server allocators (m_clientMemory, m_globalMemory). They are still
              allocated from the parent allocator, reserving their size and failing like upstream, but are placeholders
              (see YOJIMBO_ALLOCATE_MEMORY).
            - the netcode and reliable allocate/free callbacks. Their packet buffers are managed arrays in the C# port.
            - the padded read buffer in Connection::ProcessPacket (the C# BitReader bounds checks its loads instead).
     */

    /// Allocator error level.
    public enum AllocatorErrorLevel
    {
        ALLOCATOR_ERROR_NONE = 0,                               ///< No error. All is well.
        ALLOCATOR_ERROR_OUT_OF_MEMORY                           ///< The allocator is out of memory!
    }

    public static partial class yojimbo
    {
        /// Helper function to convert an allocator error to a user friendly string.
        public static string GetAllocatorErrorString(AllocatorErrorLevel error)
        {
            switch (error)
            {
                case AllocatorErrorLevel.ALLOCATOR_ERROR_NONE: return "none";
                case AllocatorErrorLevel.ALLOCATOR_ERROR_OUT_OF_MEMORY: return "out of memory";
                default:
                    assert(false);
                    return "(unknown)";
            }
        }

        /**
            Macro for creating a new object instance with a yojimbo allocator.
            On failure it returns null without running the constructor, like upstream's yojimbo_new.
            Managed objects have no fixed size, so the allocation is accounted as 0 bytes (plus the allocator's per-block overhead).
            @param create Builds the object. Only called if the allocator lets the allocation proceed.
         */
        public static T YOJIMBO_NEW<T>(Allocator allocator, Func<T> create, [CallerFilePath] string file = null, [CallerLineNumber] int line = 0) where T : class =>
            allocator.Allocate(0, create, file, line);

        /// Macro for deleting an object created with a yojimbo allocator. Runs its destructor (Dispose), frees it and sets the reference to null.
        public static void YOJIMBO_DELETE<T>(Allocator allocator, ref T p, [CallerFilePath] string file = null, [CallerLineNumber] int line = 0) where T : class
        {
            if (p != null)
            {
                (p as IDisposable)?.Dispose();
                allocator.Free(p, file, line);
                p = null;
            }
        }

        /// Macro for allocating a block of memory with a yojimbo allocator. Returns null on failure.
        public static byte[] YOJIMBO_ALLOCATE(Allocator allocator, int bytes, [CallerFilePath] string file = null, [CallerLineNumber] int line = 0) =>
            allocator.Allocate(bytes, () => new byte[bytes], file, line);

        /// C#: typed form of YOJIMBO_ALLOCATE( allocator, sizeof( T ) * count ). Returns null on failure.
        public static T[] YOJIMBO_ALLOCATE<T>(Allocator allocator, int count, [CallerFilePath] string file = null, [CallerLineNumber] int line = 0) =>
            allocator.Allocate(count * Unsafe.SizeOf<T>(), () => new T[count], file, line);

        /**
            C#: YOJIMBO_ALLOCATE( allocator, bytes ) for the block of memory that backs a child allocator (BaseClient::m_clientMemory, BaseServer::m_globalMemory and m_clientMemory).
            The managed allocators draw from the GC, so the block is a placeholder: allocating it reserves bytes against the parent allocator, and can fail, exactly like upstream, without committing the memory.
         */
        public static object YOJIMBO_ALLOCATE_MEMORY(Allocator allocator, int bytes, [CallerFilePath] string file = null, [CallerLineNumber] int line = 0) =>
            allocator.Allocate(bytes, () => new object(), file, line);

        /// Macro for freeing a block of memory created with a yojimbo allocator. Sets the reference to null.
        public static void YOJIMBO_FREE<T>(Allocator allocator, ref T p, [CallerFilePath] string file = null, [CallerLineNumber] int line = 0) where T : class
        {
            if (p != null)
            {
                allocator.Free(p, file, line);
                p = null;
            }
        }
    }

    /**
        Leak tracking state for an Allocator. Only allocated when the library is built with YOJIMBO_DEBUG_MEMORY_LEAKS.
     */
    class AllocatorDebugState
    {
#if YOJIMBO_DEBUG_MEMORY_LEAKS
        public struct Entry
        {
            public int size;
            public string file;
            public int line;
        }

        public Dictionary<object, Entry> alloc_map = new Dictionary<object, Entry>(ReferenceEqualityComparer.Instance);
#endif
    }

    /**
        Functionality common to all allocators.
        Extend this class to hook up your own allocator to yojimbo.
        IMPORTANT: This allocator is not yet thread safe. Only call it from one thread!
     */
    public abstract class Allocator : IDisposable
    {
        /**
            Allocator constructor.
            Sets the error level to ALLOCATOR_ERROR_NONE.
         */
        public Allocator()
        {
            m_errorLevel = AllocatorErrorLevel.ALLOCATOR_ERROR_NONE;
#if YOJIMBO_DEBUG_MEMORY_LEAKS
            m_debug = new AllocatorDebugState();
#else
            m_debug = null;
#endif
        }

        /**
            Allocator destructor.
            Make sure all allocations made from this allocator are freed before you dispose this allocator.
            In debug build, any outstanding allocations are considered memory leaks: they are printed and the allocator asserts.
         */
        public virtual void Dispose()
        {
#if YOJIMBO_DEBUG_MEMORY_LEAKS
            if (m_debug != null && m_debug.alloc_map.Count != 0)
            {
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "you leaked memory!\n\n");
                foreach (var i in m_debug.alloc_map)
                {
                    var p = i.Key;
                    var entry = i.Value;
                    yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"leaked block {p.GetType().Name} ({entry.size} bytes) - {entry.file}:{entry.line}\n");
                }
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, "\n");
                yojimbo.assert(false, "Leaks detected, see log");
            }
#endif
            m_debug = null;
        }

        /**
            Allocate a block of memory.
            IMPORTANT: Don't call this directly. Use the YOJIMBO_NEW or YOJIMBO_ALLOCATE macros instead, because they automatically pass in the source filename and line number for you.
            C#: the block is the object built by create, which the allocator calls only if the allocation may proceed.
            @param size The size of the block of memory to allocate (bytes). Used for accounting and reporting leaks.
            @param create Builds the block.
            @param file The source code filename that is performing the allocation. Used for tracking allocations and reporting on memory leaks.
            @param line The line number in the source code file that is performing the allocation.
            @returns The block, or null if the allocation could not be performed. If null is returned, the error level is set to ALLOCATOR_ERROR_OUT_OF_MEMORY.
            @see Allocator::Free
            @see Allocator::ErrorLevel
         */
        public abstract T Allocate<T>(int size, Func<T> create, string file, int line) where T : class;

        /**
            Free a block of memory.
            IMPORTANT: Don't call this directly. Use the YOJIMBO_DELETE or YOJIMBO_FREE macros instead, because they automatically pass in the source filename and line number for you.
            @param p The block to free. Must be a block that was allocated with this allocator. null is ignored.
            @param file The source code filename that is performing the free. Used for tracking allocations and reporting on memory leaks.
            @param line The line number in the source code file that is performing the free.
         */
        public abstract void Free(object p, string file, int line);

        /**
            Get the allocator error level.
            Use this function to check if an allocation has failed. This is used in the client/server to disconnect a client with a failed allocation.
         */
        public AllocatorErrorLevel ErrorLevel => m_errorLevel;

        /**
            Clear the allocator error level back to default.
         */
        public void ClearError() => m_errorLevel = AllocatorErrorLevel.ALLOCATOR_ERROR_NONE;

        /**
            Set the error level.
            For correct client/server behavior when an allocation fails, please make sure you call this method to set the error level to ALLOCATOR_ERROR_OUT_OF_MEMORY.
         */
        protected void SetErrorLevel(AllocatorErrorLevel errorLevel)
        {
            if (m_errorLevel == AllocatorErrorLevel.ALLOCATOR_ERROR_NONE && errorLevel != AllocatorErrorLevel.ALLOCATOR_ERROR_NONE)
                yojimbo.printf(yojimbo.LOG_LEVEL_ERROR, $"allocator went into error state: {yojimbo.GetAllocatorErrorString(errorLevel)}\n");
            m_errorLevel = errorLevel;
        }

        /**
            Call this function to track an allocation made by your derived allocator class.
            In debug build, tracked allocations are automatically checked for leaks when the allocator is disposed.
         */
        protected void TrackAlloc(object p, int size, string file, int line)
        {
#if YOJIMBO_DEBUG_MEMORY_LEAKS
            yojimbo.assert(m_debug != null);
            yojimbo.assert(!m_debug.alloc_map.ContainsKey(p));
            m_debug.alloc_map[p] = new AllocatorDebugState.Entry { size = size, file = file, line = line };
#endif
        }

        /**
            Call this function to track a free made by your derived allocator class.
            In debug build, any allocation tracked without a corresponding free is considered a memory leak when the allocator is disposed.
         */
        protected void TrackFree(object p, string file, int line)
        {
#if YOJIMBO_DEBUG_MEMORY_LEAKS
            yojimbo.assert(m_debug != null);
            yojimbo.assert(m_debug.alloc_map.ContainsKey(p));
            m_debug.alloc_map.Remove(p);
#endif
        }

        protected AllocatorErrorLevel m_errorLevel;                                     ///< The allocator error level.

        AllocatorDebugState m_debug;                                                    ///< Leak tracking state, or null. Only allocated in a debug library build.
    }

    /**
        The default allocator implementation, based around the GC (malloc and free upstream).
     */
    public class DefaultAllocator : Allocator
    {
        public override T Allocate<T>(int size, Func<T> create, string file, int line)
        {
            T p;
            try
            {
                p = create();
            }
            catch (OutOfMemoryException)
            {
                p = null;
            }

            if (p == null)
            {
                SetErrorLevel(AllocatorErrorLevel.ALLOCATOR_ERROR_OUT_OF_MEMORY);
                return null;
            }

            TrackAlloc(p, size, file, line);

            return p;
        }

        public override void Free(object p, string file, int line)
        {
            if (p == null)
                return;

            TrackFree(p, file, line);
        }
    }

    /**
        The allocator used inside the yojimbo server and client to silo allocations for each client to their own heap.
        Upstream this is built on the TLSF allocator implementation by Matt Conte. The C# port keeps its contract rather than
        its algorithm: a heap of a fixed number of bytes, with a per-block overhead, that fails with ALLOCATOR_ERROR_OUT_OF_MEMORY
        once it is full. The blocks themselves come from the GC.
        If you want to integrate your own allocator with yojimbo for use with the client and server, this class is a good template to start from.
     */
    public class TLSF_Allocator : Allocator
    {
        const int AlignBytes = 8;                                                       ///< The memory block is aligned to this many bytes (upstream aligns the pointer).
        const int BlockAlignBytes = 16;                                                 ///< Allocations are aligned to this many bytes (tlsf_memalign( m_tlsf, 16, size )).
        const int BlockHeaderOverhead = 8;                                              ///< Bytes of header per allocated block (TLSF's block_header_overhead).
        const int PoolOverhead = 16;                                                    ///< Bytes the pool loses to its sentinel blocks (TLSF's tlsf_pool_overhead).

        /**
            TLSF allocator constructor.
            @param memory The block of memory in which the allocator will work. In C# this is a placeholder (see yojimbo.YOJIMBO_ALLOCATE_MEMORY) and may be null.
            @param bytes The size of the block of memory (bytes). The maximum amount of memory you can allocate will be less, due to allocator overhead.
         */
        public TLSF_Allocator(object memory, int bytes)
        {
            yojimbo.assert(bytes > 0);

            SetErrorLevel(AllocatorErrorLevel.ALLOCATOR_ERROR_NONE);

            m_capacity = (long)(bytes & ~(AlignBytes - 1)) - PoolOverhead;

            yojimbo.assert(m_capacity > 0);

            m_used = 0;
            m_blocks = new Dictionary<object, long>(ReferenceEqualityComparer.Instance);
        }

        /**
            TLSF allocator destructor.
            Checks for memory leaks in debug build. Free all memory allocated by this allocator before disposing.
         */
        public override void Dispose()
        {
            m_blocks?.Clear();
            m_used = 0;
            base.Dispose();
        }

        public override T Allocate<T>(int size, Func<T> create, string file, int line)
        {
            yojimbo.assert(size >= 0);

            var blockBytes = BlockHeaderOverhead + (((long)size + (BlockAlignBytes - 1)) & ~(long)(BlockAlignBytes - 1));

            if (m_used + blockBytes > m_capacity)
            {
                SetErrorLevel(AllocatorErrorLevel.ALLOCATOR_ERROR_OUT_OF_MEMORY);
                return null;
            }

            // reserve before building, so allocations made by the object's constructor are accounted after it, like upstream
            m_used += blockBytes;

            T p;
            try
            {
                p = create();
            }
            catch (OutOfMemoryException)
            {
                p = null;
            }
            catch
            {
                m_used -= blockBytes;
                throw;
            }

            if (p == null)
            {
                m_used -= blockBytes;
                SetErrorLevel(AllocatorErrorLevel.ALLOCATOR_ERROR_OUT_OF_MEMORY);
                return null;
            }

            m_blocks[p] = blockBytes;

            TrackAlloc(p, size, file, line);

            return p;
        }

        public override void Free(object p, string file, int line)
        {
            if (p == null)
                return;

            TrackFree(p, file, line);

            if (m_blocks.Remove(p, out var blockBytes))
                m_used -= blockBytes;
        }

        /// C#: the number of bytes currently allocated from this heap, including per-block overhead.
        public long BytesAllocated => m_used;

        /// C#: the number of bytes available to allocations once the pool overhead is taken out.
        public long Capacity => m_capacity;

        long m_capacity;                                                                ///< Bytes available for blocks.
        long m_used;                                                                    ///< Bytes used by live blocks, including their overhead.
        Dictionary<object, long> m_blocks;                                              ///< Live blocks and the bytes each one uses (TLSF stores this in the block header).
    }
}
