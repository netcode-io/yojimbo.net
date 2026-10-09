/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2026, Más Bandwidth LLC.

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

/*
    TypeScript port of include/yojimbo_allocator.h + source/yojimbo_allocator.cpp (yojimbo 1.13.5).

    In TypeScript memory is garbage collected, so an allocator here is the BOOKKEEPING of allocation, kept with
    upstream's semantics so the library behaves (and fails) the way it does in C++:

      - Allocate( size ) returns a fresh Uint8Array of `size` bytes, or null on failure, in which case the allocator
        error level is set to ALLOCATOR_ERROR_OUT_OF_MEMORY. Every caller handles null exactly where upstream handles
        NULL, so allocation failure can be injected (see the ArmableAllocator in test.ts) and the upstream
        allocation-failure tests port over.
      - Free( p ) must be given a block this allocator returned. With leak tracking on (YOJIMBO_DEBUG_MEMORY_LEAKS,
        the default) every live block is tracked, freeing an unknown block asserts, and Dispose() (the C++ destructor)
        reports and asserts on leaked blocks.
      - TLSF_Allocator models a fixed size heap: it charges each block (plus per-block overhead) against the memory
        budget it was created with and fails once the budget is used up, which is what silos each client's
        allocations on the server. Blocks are ordinary GC'd arrays; the backing memory is not carved up.
      - A block's byteOffset must be a multiple of 8 (upstream: malloc alignment), because the library makes
        Uint16/Uint32/Float64 views over blocks for the arrays upstream allocates as uint16_t / uint32_t / double.

    Objects: YOJIMBO_NEW( allocator, () => new T( ... ), bytes ) charges one block of `bytes` (default 0) to the
    allocator for the object and returns the object, or null when the allocation fails (the constructor is not
    run, as upstream's yojimbo_new). YOJIMBO_DELETE( allocator, object ) runs the object's Dispose() (the C++
    destructor), if it has one, and frees its block. Both return values make the C++ `p = NULL` explicit:
    `x = YOJIMBO_DELETE( allocator, x )`.

    The default allocator is created by InitializeYojimbo and destroyed by ShutdownYojimbo, which checks it for leaks.
*/

import { yojimbo_assert, yojimbo_printf, YOJIMBO_LOG_LEVEL_ERROR } from './yojimbo_platform.ts';

/** Debug memory leak tracking (upstream: on in YOJIMBO_DEBUG builds). */
export const YOJIMBO_DEBUG_MEMORY_LEAKS = true;

let g_defaultAllocator: Allocator | null = null;

/**
    Get the default allocator.
    Use this allocator when you just want to use plain allocation, but in the form of a yojimbo allocator.
    This allocator instance is created inside InitializeYojimbo and destroyed in ShutdownYojimbo.
    It automatically checks for memory leaks and prints them out for you when you shutdown the library.
    @returns The default allocator instance.
 */

export function GetDefaultAllocator(): Allocator
{
    yojimbo_assert( g_defaultAllocator, "g_defaultAllocator", "GetDefaultAllocator" );
    return g_defaultAllocator;
}

/** Internal: creates the default allocator. Called by InitializeYojimbo. */

export function yojimbo_create_default_allocator(): void
{
    yojimbo_assert( g_defaultAllocator == null, "g_defaultAllocator == NULL", "InitializeYojimbo" );
    g_defaultAllocator = new DefaultAllocator();
}

/** Internal: destroys the default allocator, checking it for leaks. Called by ShutdownYojimbo. */

export function yojimbo_destroy_default_allocator(): void
{
    yojimbo_assert( g_defaultAllocator, "g_defaultAllocator", "ShutdownYojimbo" );
    const allocator = g_defaultAllocator;
    g_defaultAllocator = null;
    allocator.Dispose();
}

// ---------------------------------------------------------------------------------------------

const object_blocks = new WeakMap<object, Uint8Array>();

/**
    Helper behind YOJIMBO_NEW. Allocates a block for the object and only then constructs it. On failure it returns
    null instead of running the constructor.
 */

export function yojimbo_new<T extends object>( allocator: Allocator, create: () => T, bytes: number = 0, file: string = "", line: number = 0 ): T | null
{
    const memory = allocator.Allocate( bytes, file, line );
    if ( !memory )
        return null;
    const object = create();
    object_blocks.set( object, memory );
    return object;
}

/** Create a new object instance with a yojimbo allocator. Returns null if the allocation fails. */

export function YOJIMBO_NEW<T extends object>( allocator: Allocator, create: () => T, bytes: number = 0 ): T | null
{
    return yojimbo_new( allocator, create, bytes );
}

/**
    Delete an object created with YOJIMBO_NEW: runs its Dispose() (the destructor), if any, then frees its block.
    Does nothing for null. Always returns null, so `p = YOJIMBO_DELETE( allocator, p )` mirrors upstream's `p = NULL`.
 */

export function YOJIMBO_DELETE( allocator: Allocator, object: object | null | undefined ): null
{
    if ( object )
    {
        const memory = object_blocks.get( object );
        yojimbo_assert( memory, "object was created with YOJIMBO_NEW", "YOJIMBO_DELETE" );
        const disposable = object as { Dispose?: () => void };
        if ( typeof disposable.Dispose === "function" )
            disposable.Dispose();
        object_blocks.delete( object );
        allocator.Free( memory );
    }
    return null;
}

/** Allocate a block of memory with a yojimbo allocator. Returns null if the allocation fails. */

export function YOJIMBO_ALLOCATE( allocator: Allocator, bytes: number ): Uint8Array | null
{
    return allocator.Allocate( bytes );
}

/** Free a block of memory allocated with a yojimbo allocator. Does nothing for null. Always returns null. */

export function YOJIMBO_FREE( allocator: Allocator, p: Uint8Array | null | undefined ): null
{
    if ( p )
        allocator.Free( p );
    return null;
}

// ---------------------------------------------------------------------------------------------

/// Allocator error level.
export const ALLOCATOR_ERROR_NONE = 0;                     ///< No error. All is well.
export const ALLOCATOR_ERROR_OUT_OF_MEMORY = 1;            ///< The allocator is out of memory!

export type AllocatorErrorLevel = typeof ALLOCATOR_ERROR_NONE | typeof ALLOCATOR_ERROR_OUT_OF_MEMORY;

/// Helper function to convert an allocator error to a user friendly string.
export function GetAllocatorErrorString( error: AllocatorErrorLevel ): string
{
    switch ( error )
    {
        case ALLOCATOR_ERROR_NONE:                  return "none";
        case ALLOCATOR_ERROR_OUT_OF_MEMORY:         return "out of memory";
        default:
            yojimbo_assert( false, "unknown allocator error", "GetAllocatorErrorString" );
            return "(unknown)";
    }
}

/** A tracked allocation (upstream AllocatorDebugState::Entry). */

class AllocatorDebugEntry
{
    size: number;
    file: string;
    line: number;

    constructor( size: number, file: string, line: number )
    {
        this.size = size;
        this.file = file;
        this.line = line;
    }
}

/**
    Functionality common to all allocators.
    Extend this class to hook up your own allocator to yojimbo: implement Allocate and Free, call SetErrorLevel on
    failure and TrackAlloc / TrackFree on success, exactly as upstream.
    IMPORTANT: This allocator is not thread safe.
 */

export abstract class Allocator
{
    protected m_errorLevel: AllocatorErrorLevel;                            ///< The allocator error level.

    private m_debug: Map<Uint8Array, AllocatorDebugEntry> | null;           ///< Leak tracking state, or null when leak tracking is off.

    /**
        Allocator constructor.
        Sets the error level to ALLOCATOR_ERROR_NONE.
     */

    constructor()
    {
        this.m_errorLevel = ALLOCATOR_ERROR_NONE;
        this.m_debug = YOJIMBO_DEBUG_MEMORY_LEAKS ? new Map<Uint8Array, AllocatorDebugEntry>() : null;
    }

    /**
        Allocator destructor.
        Make sure all allocations made from this allocator are freed before you destroy this allocator.
        With leak tracking on, any outstanding blocks are considered memory leaks: they are printed, then this asserts.
     */

    Dispose(): void
    {
        if ( this.m_debug && this.m_debug.size > 0 )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "you leaked memory!\n\n" );
            for ( const entry of this.m_debug.values() )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "leaked block (%d bytes) - %s:%d\n", entry.size, entry.file, entry.line );
            }
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "\n" );
            this.m_debug.clear();
            yojimbo_assert( false, "Leaks detected, see log", "Allocator::~Allocator" );
        }
    }

    /**
        Allocate a block of memory.
        @param size The size of the block of memory to allocate (bytes).
        @param file The source file performing the allocation, for leak reports. Optional.
        @param line The line performing the allocation, for leak reports. Optional.
        @returns A block of memory of the requested size, or null if the allocation could not be performed. If null is returned, the error level is set to ALLOCATOR_ERROR_OUT_OF_MEMORY.
     */

    abstract Allocate( size: number, file?: string, line?: number ): Uint8Array | null;

    /**
        Free a block of memory.
        @param p The block of memory to free. Must be a block that was allocated with this allocator (null is ignored).
        @param file The source file performing the free. Optional.
        @param line The line performing the free. Optional.
     */

    abstract Free( p: Uint8Array | null, file?: string, line?: number ): void;

    /**
        Get the allocator error level.
        Use this function to check if an allocation has failed. This is used in the client/server to disconnect a client with a failed allocation.
        @returns The allocator error level.
     */

    GetErrorLevel(): AllocatorErrorLevel
    {
        return this.m_errorLevel;
    }

    /**
        Clear the allocator error level back to default.
     */

    ClearError(): void
    {
        this.m_errorLevel = ALLOCATOR_ERROR_NONE;
    }

    /**
        Set the error level.
        For correct client/server behavior when an allocation fails, please make sure you call this method to set the error level to ALLOCATOR_ERROR_OUT_OF_MEMORY.
        @param errorLevel The allocator error level to set.
     */

    protected SetErrorLevel( errorLevel: AllocatorErrorLevel ): void
    {
        if ( this.m_errorLevel === ALLOCATOR_ERROR_NONE && errorLevel !== ALLOCATOR_ERROR_NONE )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "allocator went into error state: %s\n", GetAllocatorErrorString( errorLevel ) );
        }
        this.m_errorLevel = errorLevel;
    }

    /**
        Call this function to track an allocation made by your derived allocator class.
        Tracked allocations are automatically checked for leaks when the allocator is destroyed.
        @param p The memory that was allocated.
        @param size The size of the allocation in bytes.
        @param file The source code file that performed the allocation.
        @param line The line number in the source file where the allocation was performed.
     */

    protected TrackAlloc( p: Uint8Array, size: number, file: string = "", line: number = 0 ): void
    {
        if ( this.m_debug )
        {
            yojimbo_assert( !this.m_debug.has( p ), "block not already tracked", "Allocator::TrackAlloc" );
            this.m_debug.set( p, new AllocatorDebugEntry( size, file, line ) );
        }
    }

    /**
        Call this function to track a free made by your derived allocator class.
        Any allocation tracked without a corresponding free is considered a memory leak when the allocator is destroyed.
        @param p The memory being freed.
        @param file The source code file that is calling in to free the memory.
        @param line The line number in the source file where the free is being called from.
     */

    protected TrackFree( p: Uint8Array, _file: string = "", _line: number = 0 ): void
    {
        if ( this.m_debug )
        {
            yojimbo_assert( this.m_debug.has( p ), "block was allocated by this allocator", "Allocator::TrackFree" );
            this.m_debug.delete( p );
        }
    }

    /** Is this block currently allocated from this allocator? Only known with leak tracking on (otherwise true). */

    IsTracked( p: Uint8Array ): boolean
    {
        return this.m_debug ? this.m_debug.has( p ) : true;
    }
}

/**
    The default allocator implementation (upstream: malloc and free).
 */

export class DefaultAllocator extends Allocator
{
    /**
        Allocates a block of memory (a new Uint8Array).
        @param size The size of the block of memory to allocate (bytes).
        @returns A block of memory of the requested size, or null if the allocation could not be performed.
     */

    Allocate( size: number, file: string = "", line: number = 0 ): Uint8Array | null
    {
        let p: Uint8Array;
        try
        {
            p = new Uint8Array( size );
        }
        catch
        {
            this.SetErrorLevel( ALLOCATOR_ERROR_OUT_OF_MEMORY );
            return null;
        }

        this.TrackAlloc( p, size, file, line );

        return p;
    }

    /**
        Free a block of memory.
        @param p The block of memory to free. Must be a block that was allocated with this allocator (null is ignored).
     */

    Free( p: Uint8Array | null, file: string = "", line: number = 0 ): void
    {
        if ( !p )
            return;

        this.TrackFree( p, file, line );
    }
}

/** Per-block overhead charged by TLSF_Allocator (upstream TLSF: block header). */
const TLSF_BlockOverhead = 8;

/** Fixed overhead charged by TLSF_Allocator for the heap's control structure and pool sentinels (upstream: tlsf_size() + pool overhead, 64 bit). */
const TLSF_ControlOverhead = 6544;

/** Minimum block size charged by TLSF_Allocator (upstream TLSF: block_size_min). */
const TLSF_MinBlockSize = 24;

/**
    An allocator modelled on the TLSF allocator yojimbo uses for per-client heaps.
    It charges each allocation (rounded up to 8 bytes, at least TLSF_MinBlockSize, plus a block header) against a fixed
    budget of `bytes` and fails with ALLOCATOR_ERROR_OUT_OF_MEMORY when the budget would be exceeded. This keeps the
    containment model of the server (one client exhausting its heap cannot starve another) and makes allocation
    failure reachable the same way it is upstream. Fragmentation is not modelled.
 */

export class TLSF_Allocator extends Allocator
{
    private m_capacity: number;                                     ///< Bytes available to blocks.
    private m_used = 0;                                             ///< Bytes charged to live blocks (including overhead).
    private m_charges = new Map<Uint8Array, number>();              ///< What each live block was charged.

    /**
        TLSF allocator constructor.
        @param memory The memory the allocator works in. Not carved up in the TypeScript port (blocks are GC'd arrays), so it may be null; only `bytes` matters.
        @param bytes The size of the heap (bytes). The maximum amount of memory you can allocate will be less, due to allocator overhead.
     */

    constructor( memory: Uint8Array | null, bytes: number )
    {
        super();
        void memory;
        yojimbo_assert( bytes > 0, "size > 0", "TLSF_Allocator::TLSF_Allocator" );
        this.SetErrorLevel( ALLOCATOR_ERROR_NONE );
        const aligned = bytes - ( bytes % 8 );
        this.m_capacity = Math.max( 0, aligned - TLSF_ControlOverhead );
    }

    /**
        TLSF allocator destructor.
        Checks for memory leaks. Free all memory allocated by this allocator before destroying.
     */

    override Dispose(): void
    {
        super.Dispose();
    }

    /**
        Allocates a block of memory from the heap budget.
        @returns A block of memory of the requested size, or null if the heap budget is exhausted.
     */

    Allocate( size: number, file: string = "", line: number = 0 ): Uint8Array | null
    {
        const charge = Math.max( TLSF_MinBlockSize, ( size + 7 ) & ~7 ) + TLSF_BlockOverhead;

        if ( size < 0 || this.m_used + charge > this.m_capacity )
        {
            this.SetErrorLevel( ALLOCATOR_ERROR_OUT_OF_MEMORY );
            return null;
        }

        const p = new Uint8Array( size );

        this.m_used += charge;
        this.m_charges.set( p, charge );

        this.TrackAlloc( p, size, file, line );

        return p;
    }

    /**
        Free a block of memory back to the heap budget.
     */

    Free( p: Uint8Array | null, file: string = "", line: number = 0 ): void
    {
        if ( !p )
            return;

        this.TrackFree( p, file, line );

        const charge = this.m_charges.get( p );
        yojimbo_assert( charge !== undefined, "block was allocated by this allocator", "TLSF_Allocator::Free" );
        this.m_charges.delete( p );
        this.m_used -= charge;
    }

    /** Bytes currently charged against the heap (including per-block overhead). */

    GetUsedBytes(): number
    {
        return this.m_used;
    }

    /** Bytes available to blocks (the heap size less the control structure). */

    GetCapacityBytes(): number
    {
        return this.m_capacity;
    }
}
