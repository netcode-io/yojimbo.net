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
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;

namespace networkprotocol
{
    /**
        Simulates packet loss, latency, jitter and duplicate packets.
        This is useful during development, so your game is tested and played under real world conditions, instead of ideal LAN conditions.
        This simulator works on packet send. This means that if you want 125ms of latency (round trip), you must to add 125/2 = 62.5ms of latency to each side.
     */
    public class NetworkSimulator : IDisposable
    {
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
        public NetworkSimulator(Allocator allocator, int numPackets, double time)
        {
            yojimbo.assert(numPackets > 0);
            m_allocator = allocator;
            m_currentIndex = 0;
            m_time = time;
            m_latency = 0.0f;
            m_jitter = 0.0f;
            m_packetLoss = 0.0f;
            m_duplicates = 0.0f;
            m_active = false;
            m_numPacketEntries = numPackets;
            m_packetEntries = yojimbo.YOJIMBO_ALLOCATE<PacketEntry>(allocator, numPackets);
            yojimbo.assert(m_packetEntries != null);
            for (var i = 0; i < numPackets; ++i)
                m_packetEntries[i] = new PacketEntry();
        }

        /**
            Network simulator destructor.
            Any packet data still in the network simulator is destroyed.
         */
        public void Dispose()
        {
            yojimbo.assert(m_allocator != null);
            yojimbo.assert(m_packetEntries != null);
            yojimbo.assert(m_numPacketEntries > 0);
            DiscardPackets();
            yojimbo.YOJIMBO_FREE(m_allocator, ref m_packetEntries);
            m_numPacketEntries = 0;
            m_allocator = null;
        }

        /**
            Set the latency in milliseconds.
            This latency is added on packet send. To simulate a round trip time of 100ms, add 50ms of latency to both sides of the connection.
            @param milliseconds The latency to add in milliseconds.
         */
        public void SetLatency(float milliseconds)
        {
            m_latency = milliseconds;
            UpdateActive();
        }

        /**
            Set the packet jitter in milliseconds.
            Jitter is applied +/- this amount in milliseconds. To be truly effective, jitter must be applied together with some latency.
            @param milliseconds The amount of jitter to add in milliseconds (+/-).
         */
        public void SetJitter(float milliseconds)
        {
            m_jitter = milliseconds;
            UpdateActive();
        }

        /**
            Set the amount of packet loss to apply on send.
            @param percent The packet loss percentage. 0% = no packet loss. 100% = all packets are dropped.
         */
        public void SetPacketLoss(float percent)
        {
            m_packetLoss = percent;
            UpdateActive();
        }

        /**
            Set percentage chance of packet duplicates.
            If the duplicate chance succeeds, a duplicate packet is added to the queue with a random delay of up to 1 second.
            @param percent The percentage chance of a packet duplicate being sent. 0% = no duplicate packets. 100% = all packets have a duplicate sent.
         */
        public void SetDuplicates(float percent)
        {
            m_duplicates = percent;
            UpdateActive();
        }

        /**
            Is the network simulator active?
            The network simulator is active when packet loss, latency, duplicates or jitter are non-zero values.
            This is used by the transport to know whether it should shunt packets through the simulator, or send them directly to the network. This is a minor optimization.
         */
        public bool IsActive =>
            m_active;

        /**
            Queue a packet to send.
            IMPORTANT: Ownership of the packet data pointer is *not* transferred to the network simulator. It makes a copy of the data instead.
            @param to The slot index the packet should be sent to.
            @param packetData The packet data.
            @param packetBytes The packet size (bytes).
         */
        public void SendPacket(int to, byte[] packetData, int packetBytes)
        {
            yojimbo.assert(m_allocator != null);
            yojimbo.assert(packetData != null);
            yojimbo.assert(packetBytes > 0);

            if (yojimbo.random_float(0.0f, 100.0f) <= m_packetLoss)
            {
                return;
            }

            // reset the slot in place (the C++ code works through a PacketEntry reference). Assigning a new
            // PacketEntry to a local here used to orphan the new packet and lose both it and the old one.
            var packetEntry = m_packetEntries[m_currentIndex];
            if (packetEntry.packetData != null)
            {
                yojimbo.YOJIMBO_FREE(m_allocator, ref packetEntry.packetData);
                packetEntry.Clear();
            }

            var delay = m_latency / 1000.0;

            if (m_jitter > 0)
                delay += yojimbo.random_float(-m_jitter, +m_jitter) / 1000.0;

            packetEntry.to = to;
            packetEntry.packetData = yojimbo.YOJIMBO_ALLOCATE(m_allocator, packetBytes);
            if (packetEntry.packetData == null)
            {
                // The simulator is lossy by design, so on OOM just drop this packet (leaving an
                // empty slot, which ReceivePackets skips) rather than dereferencing null.
                packetEntry.Clear();
                return;
            }
            Buffer.BlockCopy(packetData, 0, packetEntry.packetData, 0, packetBytes);
            packetEntry.packetBytes = packetBytes;
            packetEntry.deliveryTime = m_time + delay;
            m_currentIndex = (m_currentIndex + 1) % m_numPacketEntries;

            if (yojimbo.random_float(0.0f, 100.0f) <= m_duplicates)
            {
                var nextPacketEntry = m_packetEntries[m_currentIndex];
                if (nextPacketEntry.packetData != null)
                {
                    yojimbo.YOJIMBO_FREE(m_allocator, ref nextPacketEntry.packetData);
                    nextPacketEntry.Clear();
                }
                nextPacketEntry.to = to;
                nextPacketEntry.packetData = yojimbo.YOJIMBO_ALLOCATE(m_allocator, packetBytes);
                if (nextPacketEntry.packetData != null)
                {
                    Buffer.BlockCopy(packetData, 0, nextPacketEntry.packetData, 0, packetBytes);
                    nextPacketEntry.packetBytes = packetBytes;
                    nextPacketEntry.deliveryTime = m_time + delay + yojimbo.random_float(0, +1.0f);
                    m_currentIndex = (m_currentIndex + 1) % m_numPacketEntries;
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
            @param packetData Array of packet data pointers to be filled [out].
            @param packetBytes Array of packet sizes to be filled [out].
            @param to Array of to indices to be filled [out].
            @returns The number of packets received.
         */
        public int ReceivePackets(int maxPackets, byte[][] packetData, int[] packetBytes, int[] to)
        {
            if (!IsActive)
                return 0;

            int numPackets = 0;
            // Scan the whole ring, but never return more than maxPackets. Packets are stored at
            // m_currentIndex across the entire buffer, so bounding the scan by maxPackets (rather
            // than the output count) would strand any packet held in a slot past that index (c27a0dd).
            for (var i = 0; i < m_numPacketEntries; ++i)
            {
                if (numPackets >= maxPackets)
                    break;
                if (m_packetEntries[i].packetData == null)
                    continue;

                if (m_packetEntries[i].deliveryTime < m_time)
                {
                    packetData[numPackets] = m_packetEntries[i].packetData;
                    packetBytes[numPackets] = m_packetEntries[i].packetBytes;
                    if (to != null)
                        to[numPackets] = m_packetEntries[i].to;
                    m_packetEntries[i].packetData = null;
                    numPackets++;
                }
            }

            return numPackets;
        }

        /**
            Discard all packets in the network simulator.
            This is useful if the simulator needs to be reset and used for another purpose.
         */
        public void DiscardPackets()
        {
            for (int i = 0; i < m_numPacketEntries; ++i)
            {
                var packetEntry = m_packetEntries[i];
                if (packetEntry.packetData == null)
                    continue;
                yojimbo.YOJIMBO_FREE(m_allocator, ref packetEntry.packetData);
                packetEntry.Clear();
            }
        }

        /**
            Discard packets sent to a particular client index.
            This is called when a client disconnects from the server.
         */
        public void DiscardClientPackets(int clientIndex)
        {
            for (var i = 0; i < m_numPacketEntries; ++i)
            {
                var packetEntry = m_packetEntries[i];
                if (packetEntry.packetData == null || packetEntry.to != clientIndex)
                    continue;
                yojimbo.YOJIMBO_FREE(m_allocator, ref packetEntry.packetData);
                packetEntry.Clear();
            }
        }

        /**
            Advance network simulator time.
            You must pump this regularly otherwise the network simulator won't work.
            @param time The current time value. Please make sure you use double values for time so you retain sufficient precision as time increases.
         */
        public void AdvanceTime(double time)
        {
            m_time = time;
        }

        /**
            Get the allocator to use to free packet data.
            @returns The allocator that packet data is allocated with.
         */
        public Allocator Allocator { get { yojimbo.assert(m_allocator != null); return m_allocator; } }

        /**
            Helper function to update the active flag whenever network settings are changed.
            Active is set to true if any of the network conditions are non-zero. This allows you to quickly check if the network simulator is active and would actually do something.
         */
        protected void UpdateActive()
        {
            bool previous = m_active;
            m_active = m_latency != 0.0f || m_jitter != 0.0f || m_packetLoss != 0.0f || m_duplicates != 0.0f;
            if (previous && !m_active)
            {
                DiscardPackets();
            }
        }

        Allocator m_allocator;                          ///< The allocator passed in to the constructor. It's used to allocate and free packet data.
        float m_latency;                                ///< Latency in milliseconds
        float m_jitter;                                 ///< Jitter in milliseconds +/-
        float m_packetLoss;                             ///< Packet loss percentage.
        float m_duplicates;                             ///< Duplicate packet percentage
        bool m_active;                                  ///< True if network simulator is active, eg. if any of the network settings above are enabled.

        /// A packet buffered in the network simulator.
        public class PacketEntry
        {
            public int to = 0;                          ///< To index this packet should be sent to (for server . client packets).
            public double deliveryTime = 0.0;           ///< Delivery time for this packet (seconds).
            public byte[] packetData = null;            ///< Packet data (owns this pointer).
            public int packetBytes = 0;                 ///< Size of packet in bytes.

            public void Clear()
            {
                to = 0;
                deliveryTime = 0.0;
                packetData = null;
                packetBytes = 0;
            }
        }

        double m_time;                                  ///< Current time from last call to advance time.
        int m_currentIndex;                             ///< Current index in the packet entry array. New packets are inserted here.
        int m_numPacketEntries;                         ///< Number of elements in the packet entry array.
        PacketEntry[] m_packetEntries;                  ///< Pointer to dynamically allocated packet entries. This is where buffered packets are stored.
    }
}
