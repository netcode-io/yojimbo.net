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
    TypeScript port of include/yojimbo.h + source/yojimbo.cpp (yojimbo 1.13.5).

    If you use this library in a product, please credit
    "yojimbo - Glenn Fiedler and Rowan Claude" in your product credits. The
    license doesn't require this credit. It's an official request, and honoring
    it is appreciated.
    yojimbo includes netcode, reliable and serialize - please credit those the
    same way. See the README for the full list.

    Like yojimbo.h, this module re-exports the whole library (and serialize, which upstream pulls into the yojimbo
    namespace), so `import { ... } from './source/yojimbo.ts'` is all an application needs.
*/

import { netcode_init, netcode_term, netcode_enable_packet_tagging, NETCODE_OK } from '../netcode/netcode.ts';
import { reliable_init, reliable_term, RELIABLE_OK } from '../reliable/reliable.ts';
import { yojimbo_create_default_allocator, yojimbo_destroy_default_allocator } from './yojimbo_allocator.ts';

export * from '../serialize/serialize.ts';
export * from './yojimbo_config.ts';
export * from '../include/yojimbo_constants.ts';
export * from '../include/yojimbo_bit_array.ts';
export * from './yojimbo_utils.ts';
export * from '../include/yojimbo_queue.ts';
export * from '../include/yojimbo_sequence_buffer.ts';
export * from './yojimbo_address.ts';
export * from '../include/yojimbo_serialize.ts';
export { Serializable } from '../include/yojimbo_serialize.ts';
export * from './yojimbo_message.ts';
export * from './yojimbo_channel.ts';
export * from './yojimbo_reliable_ordered_channel.ts';
export * from './yojimbo_unreliable_unordered_channel.ts';
export * from './yojimbo_connection.ts';
export * from './yojimbo_network_simulator.ts';
export * from '../include/yojimbo_adapter.ts';
export * from '../include/yojimbo_network_info.ts';
export * from '../include/yojimbo_server_interface.ts';
export * from './yojimbo_base_server.ts';
export * from './yojimbo_server.ts';
export * from '../include/yojimbo_client_interface.ts';
export * from './yojimbo_base_client.ts';
export * from './yojimbo_client.ts';
export * from './yojimbo_allocator.ts';
export * from './yojimbo_platform.ts';

/**
    Initialize the yojimbo library.
    Call this before calling any yojimbo library functions.
    @returns True if the library was successfully initialized, false otherwise.
 */

export function InitializeYojimbo(): boolean
{
    // Bring subsystems up in order and unwind anything already initialized if a later step
    // fails. Callers do not call ShutdownYojimbo when InitializeYojimbo returns false, so on
    // every failure path we must leave the process exactly as we found it.
    if ( netcode_init() !== NETCODE_OK )
        return false;

    // netcode_init() already calls sodium_init() (and fails if it can't), so we don't repeat it here.

    if ( reliable_init() !== RELIABLE_OK )
    {
        netcode_term();
        return false;
    }

    // Create the default allocator last, so an earlier failure can't leak it.
    yojimbo_create_default_allocator();

    return true;
}

/**
    Enable packet tagging.
    Enable before you create any client or servers, and DSCP packet tagging will be applied to all packets sent.
    Packet tagging can significantly reduce jitter on modern Wi-Fi 6+ routers, by marking your game traffic to be sent in the real-time queue.
 */

export function EnablePacketTagging(): void
{
    netcode_enable_packet_tagging();
}

/**
    Shutdown the yojimbo library.
    Call this after you finish using the library and it will run some checks for you (for example, checking for memory leaks).
 */

export function ShutdownYojimbo(): void
{
    reliable_term();

    netcode_term();

    yojimbo_destroy_default_allocator();
}
