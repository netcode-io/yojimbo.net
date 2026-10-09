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
    TypeScript port of include/yojimbo_network_info.h (yojimbo 1.13.5).

    The float fields are float32 upstream; the packet counters are uint64 upstream and plain numbers here, exact to
    2^53, like the reliable counters they are read from.
*/

/**
    Network information for a connection.
    Contains statistics like round trip time (RTT), packet loss %, bandwidth estimates, number of packets sent, received and acked.
 */

export class NetworkInfo
{
    RTT = 0;                                ///< Round trip time estimate (milliseconds).
    minRTT = 0;                             ///< Minimum RTT over the RTT history window (milliseconds).
    maxRTT = 0;                             ///< Maximum RTT over the RTT history window (milliseconds).
    averageRTT = 0;                         ///< Average RTT over the RTT history window (milliseconds).
    averageJitter = 0;                      ///< Average jitter relative to the minimum RTT (milliseconds).
    maxJitter = 0;                          ///< Maximum jitter relative to the minimum RTT (milliseconds).
    stddevJitter = 0;                       ///< Standard deviation of jitter relative to the average RTT (milliseconds).
    packetLoss = 0;                         ///< Packet loss percent.
    sentBandwidth = 0;                      ///< Sent bandwidth (kbps).
    receivedBandwidth = 0;                  ///< Received bandwidth (kbps).
    ackedBandwidth = 0;                     ///< Acked bandwidth (kbps).
    numPacketsSent = 0;                     ///< Number of packets sent.
    numPacketsReceived = 0;                 ///< Number of packets received.
    numPacketsAcked = 0;                    ///< Number of packets acked.
}
