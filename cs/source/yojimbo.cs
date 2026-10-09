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
    static partial class yojimbo
    {
        #region init / term

        /**
            Initialize the yojimbo library.
            Call this before calling any yojimbo library functions.
            @returns True if the library was successfully initialized, false otherwise.
         */
        public static bool InitializeYojimbo()
        {
            // Bring subsystems up in order and unwind anything already initialized if a later step
            // fails. Callers do not call ShutdownYojimbo when InitializeYojimbo returns false.
            if (netcode.init() != netcode.OK)
                return false;

            if (reliable.init() != reliable.OK)
            {
                netcode.term();
                return false;
            }

            return true;
        }

        /**
            Enable packet tagging.
            Enable before you create any client or servers, and DSCP packet tagging will be applied to all packets sent.
            Packet tagging can significantly reduce jitter on modern Wi-Fi 6+ routers, by marking your game traffic to be sent in the real-time queue.
         */
        public static void EnablePacketTagging() =>
            netcode.enable_packet_tagging();

        /**
            Shutdown the yojimbo library.
            Call this after you finish using the library and it will run some checks for you (for example, checking for memory leaks in debug build).
         */
        public static void ShutdownYojimbo()
        {
            reliable.term();
            netcode.term();
        }

        #endregion
    }

}
