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
    TypeScript port of include/yojimbo_network_simulator.h + source/yojimbo_network_simulator.cpp (yojimbo 1.13.5).

    Port notes:
      - Packet copies are allocated from the simulator's allocator (and dropped on allocation failure), as upstream.
        ReceivePackets hands ownership of each returned packet to the caller, who frees it with GetAllocator().
      - The packet entry array is charged to the allocator as one block, as upstream.
      - The latency, jitter, loss and duplicate settings are float32 upstream and are rounded with Math.fround.
*/

import { YOJIMBO_ALLOCATE, YOJIMBO_FREE, YOJIMBO_NEW, YOJIMBO_DELETE, type Allocator } from './yojimbo_allocator.ts';
import { yojimbo_assert } from './yojimbo_platform.ts';
import { yojimbo_random_float } from './yojimbo_utils.ts';

/// A packet buffered in the network simulator.
class PacketEntry
{
    to = 0;                                     ///< To index this packet should be sent to (for server -> client packets).
    deliveryTime = 0;                           ///< Delivery time for this packet (seconds).
    packetData: Uint8Array | null = null;       ///< Packet data (owns this block).
    packetBytes = 0;                            ///< Size of packet in bytes.

    Clear(): void
    {
        this.to = 0;
        this.deliveryTime = 0;
        this.packetData = null;
        this.packetBytes = 0;
    }
}

/**
    Simulates packet loss, latency, jitter and duplicate packets.
    This is useful during development, so your game is tested and played under real world conditions, instead of ideal LAN conditions.
    This simulator works on packet send. This means that if you want 125ms of latency (round trip), you must to add 125/2 = 62.5ms of latency to each side.
 */

export class NetworkSimulator
{
    private m_allocator: Allocator | null;                  ///< The allocator passed in to the constructor. It's used to allocate and free packet data.
    private m_latency: number;                              ///< Latency in milliseconds
    private m_jitter: number;                               ///< Jitter in milliseconds +/-
    private m_packetLoss: number;                           ///< Packet loss percentage.
    private m_duplicates: number;                           ///< Duplicate packet percentage
    private m_active: boolean;                              ///< True if network simulator is active, eg. if any of the network settings above are enabled.
    private m_time: number;                                 ///< Current time from last call to advance time.
    private m_currentIndex: number;                         ///< Current index in the packet entry array. New packets are inserted here.
    private m_numPacketEntries: number;                     ///< Number of elements in the packet entry array.
    private m_packetEntries: PacketEntry[] | null;          ///< The packet entries. This is where buffered packets are stored.

    /**
        Create a network simulator.
        Initial network conditions are set to:
            Latency: 0ms
            Jitter: 0ms
            Packet Loss: 0%
            Duplicates: 0%
        @param allocator The allocator to use.
        @param numPackets The maximum number of packets that can be stored in the simulator at any time.
        @param time The initial time value in seconds.
     */

    constructor( allocator: Allocator, numPackets: number, time: number )
    {
        yojimbo_assert( numPackets > 0, "numPackets > 0", "NetworkSimulator::NetworkSimulator" );
        this.m_allocator = allocator;
        this.m_currentIndex = 0;
        this.m_time = time;
        this.m_latency = 0.0;
        this.m_jitter = 0.0;
        this.m_packetLoss = 0.0;
        this.m_duplicates = 0.0;
        this.m_active = false;
        this.m_numPacketEntries = numPackets;
        this.m_packetEntries = YOJIMBO_NEW( allocator, () => { const entries = new Array<PacketEntry>( numPackets ); for ( let i = 0; i < numPackets; ++i ) entries[i] = new PacketEntry(); return entries; }, 24 * numPackets );
        yojimbo_assert( this.m_packetEntries, "m_packetEntries", "NetworkSimulator::NetworkSimulator" );
    }

    /**
        Network simulator destructor.
        Any packet data still in the network simulator is destroyed.
     */

    Dispose(): void
    {
        yojimbo_assert( this.m_allocator, "m_allocator", "NetworkSimulator::~NetworkSimulator" );
        yojimbo_assert( this.m_packetEntries, "m_packetEntries", "NetworkSimulator::~NetworkSimulator" );
        yojimbo_assert( this.m_numPacketEntries > 0, "m_numPacketEntries > 0", "NetworkSimulator::~NetworkSimulator" );
        this.DiscardPackets();
        this.m_packetEntries = YOJIMBO_DELETE( this.m_allocator, this.m_packetEntries );
        this.m_numPacketEntries = 0;
        this.m_allocator = null;
    }

    /**
        Set the latency in milliseconds.
        This latency is added on packet send. To simulate a round trip time of 100ms, add 50ms of latency to both sides of the connection.
     */

    SetLatency( milliseconds: number ): void
    {
        this.m_latency = Math.fround( milliseconds );
        this.UpdateActive();
    }

    /**
        Set the packet jitter in milliseconds.
        Jitter is applied +/- this amount in milliseconds. To be truly effective, jitter must be applied together with some latency.
     */

    SetJitter( milliseconds: number ): void
    {
        this.m_jitter = Math.fround( milliseconds );
        this.UpdateActive();
    }

    /**
        Set the amount of packet loss to apply on send.
        @param percent The packet loss percentage. 0% = no packet loss. 100% = all packets are dropped.
     */

    SetPacketLoss( percent: number ): void
    {
        this.m_packetLoss = Math.fround( percent );
        this.UpdateActive();
    }

    /**
        Set percentage chance of packet duplicates.
        If the duplicate chance succeeds, a duplicate packet is added to the queue with a random delay of up to 1 second.
     */

    SetDuplicates( percent: number ): void
    {
        this.m_duplicates = Math.fround( percent );
        this.UpdateActive();
    }

    /**
        Is the network simulator active?
        The network simulator is active when packet loss, latency, duplicates or jitter are non-zero values.
     */

    IsActive(): boolean
    {
        return this.m_active;
    }

    /**
        Queue a packet to send.
        IMPORTANT: Ownership of the packet data is *not* transferred to the network simulator. It makes a copy of the data instead.
        @param to The slot index the packet should be sent to.
        @param packetData The packet data.
        @param packetBytes The packet size (bytes).
     */

    SendPacket( to: number, packetData: Uint8Array, packetBytes: number ): void
    {
        yojimbo_assert( this.m_allocator, "m_allocator", "NetworkSimulator::SendPacket" );
        yojimbo_assert( packetData, "packetData", "NetworkSimulator::SendPacket" );
        yojimbo_assert( packetBytes > 0, "packetBytes > 0", "NetworkSimulator::SendPacket" );

        const allocator = this.m_allocator;
        const entries = this.m_packetEntries!;

        if ( yojimbo_random_float( 0.0, 100.0 ) <= this.m_packetLoss )
        {
            return;
        }

        const packetEntry = entries[this.m_currentIndex];

        if ( packetEntry.packetData )
        {
            YOJIMBO_FREE( allocator, packetEntry.packetData );
            packetEntry.Clear();
        }

        let delay = this.m_latency / 1000.0;

        if ( this.m_jitter > 0 )
            delay += yojimbo_random_float( -this.m_jitter, +this.m_jitter ) / 1000.0;

        packetEntry.to = to;
        packetEntry.packetData = YOJIMBO_ALLOCATE( allocator, packetBytes );
        if ( !packetEntry.packetData )
        {
            // The simulator is lossy by design, so on OOM just drop this packet (leaving an
            // empty slot, which ReceivePackets skips).
            packetEntry.Clear();
            return;
        }
        packetEntry.packetData.set( packetData.subarray( 0, packetBytes ) );
        packetEntry.packetBytes = packetBytes;
        packetEntry.deliveryTime = this.m_time + delay;
        this.m_currentIndex = ( this.m_currentIndex + 1 ) % this.m_numPacketEntries;

        if ( yojimbo_random_float( 0.0, 100.0 ) <= this.m_duplicates )
        {
            const nextPacketEntry = entries[this.m_currentIndex];
            if ( nextPacketEntry.packetData )
            {
                YOJIMBO_FREE( allocator, nextPacketEntry.packetData );
                nextPacketEntry.Clear();
            }
            nextPacketEntry.to = to;
            nextPacketEntry.packetData = YOJIMBO_ALLOCATE( allocator, packetBytes );
            if ( nextPacketEntry.packetData )
            {
                nextPacketEntry.packetData.set( packetData.subarray( 0, packetBytes ) );
                nextPacketEntry.packetBytes = packetBytes;
                nextPacketEntry.deliveryTime = this.m_time + delay + yojimbo_random_float( 0, +1.0 );
                this.m_currentIndex = ( this.m_currentIndex + 1 ) % this.m_numPacketEntries;
            }
            else
            {
                // OOM on the duplicate copy: just skip the duplicate (leave an empty slot).
                nextPacketEntry.Clear();
            }
        }
    }

    /**
        Receive packets sent to any address.
        IMPORTANT: You take ownership of the packet data you receive and are responsible for freeing it. See NetworkSimulator::GetAllocator.
        @param maxPackets The maximum number of packets to receive.
        @param packetData Array of packet data [out]. Must have at least maxPackets entries.
        @param packetBytes Array of packet sizes [out]. Must have at least maxPackets entries.
        @param to Array of to indices [out], or null.
        @returns The number of packets received.
     */

    ReceivePackets( maxPackets: number, packetData: Array<Uint8Array | null>, packetBytes: number[] | Int32Array, to: number[] | Int32Array | null ): number
    {
        if ( !this.IsActive() )
            return 0;

        const entries = this.m_packetEntries!;

        let numPackets = 0;

        // Scan the whole ring, but never return more than maxPackets. Packets are stored at
        // m_currentIndex across the entire buffer, so bounding the scan by maxPackets (rather
        // than the output count) would strand any packet held in a slot past that index.
        for ( let i = 0; i < this.m_numPacketEntries; ++i )
        {
            if ( numPackets >= maxPackets )
                break;

            const entry = entries[i];

            if ( !entry.packetData )
                continue;

            if ( entry.deliveryTime < this.m_time )
            {
                packetData[numPackets] = entry.packetData;
                packetBytes[numPackets] = entry.packetBytes;
                if ( to )
                {
                    to[numPackets] = entry.to;
                }
                entry.packetData = null;
                numPackets++;
            }
        }

        return numPackets;
    }

    /**
        Discard all packets in the network simulator.
        This is useful if the simulator needs to be reset and used for another purpose.
     */

    DiscardPackets(): void
    {
        const entries = this.m_packetEntries!;
        for ( let i = 0; i < this.m_numPacketEntries; ++i )
        {
            const packetEntry = entries[i];
            if ( !packetEntry.packetData )
                continue;
            YOJIMBO_FREE( this.m_allocator!, packetEntry.packetData );
            packetEntry.Clear();
        }
    }

    /**
        Discard packets sent to a particular client index.
        This is called when a client disconnects from the server.
     */

    DiscardClientPackets( clientIndex: number ): void
    {
        const entries = this.m_packetEntries!;
        for ( let i = 0; i < this.m_numPacketEntries; ++i )
        {
            const packetEntry = entries[i];
            if ( !packetEntry.packetData || packetEntry.to !== clientIndex )
                continue;
            YOJIMBO_FREE( this.m_allocator!, packetEntry.packetData );
            packetEntry.Clear();
        }
    }

    /**
        Advance network simulator time.
        You must pump this regularly otherwise the network simulator won't work.
        @param time The current time value. Please make sure you use double values for time so you retain sufficient precision as time increases.
     */

    AdvanceTime( time: number ): void
    {
        this.m_time = time;
    }

    /**
        Get the allocator to use to free packet data.
     */

    GetAllocator(): Allocator
    {
        yojimbo_assert( this.m_allocator, "m_allocator", "NetworkSimulator::GetAllocator" );
        return this.m_allocator;
    }

    /**
        Helper function to update the active flag whenever network settings are changed.
        Active is set to true if any of the network conditions are non-zero.
     */

    protected UpdateActive(): void
    {
        const previous = this.m_active;
        this.m_active = this.m_latency !== 0.0 || this.m_jitter !== 0.0 || this.m_packetLoss !== 0.0 || this.m_duplicates !== 0.0;
        if ( previous && !this.m_active )
        {
            this.DiscardPackets();
        }
    }
}
