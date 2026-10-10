// Type-checked against the packed yojimbo2 package by run.mjs: every entry point, as a consumer imports them.

import { Client, Server, Address, ClientServerConfig, GetDefaultAllocator, yojimbo_time, Message, BaseStream, serialize_int } from 'yojimbo2';
import { WebRTCClientAdapter } from 'yojimbo2/webrtc/client';
import { WebRTCServerAdapter } from 'yojimbo2/webrtc/server';
import { GenerateConnectToken } from 'yojimbo2/webrtc/token';
import * as netcode from 'yojimbo2/netcode';
import * as reliable from 'yojimbo2/reliable';
import * as serialize from 'yojimbo2/serialize';
import * as sodium from 'yojimbo2/sodium';

class ExampleMessage extends Message
{
    value = 0;
    Serialize( stream: BaseStream ): boolean { return serialize_int( stream, this, 'value', 0, 10 ); }
}

export const used = [ Client, Server, Address, ClientServerConfig, GetDefaultAllocator, yojimbo_time, ExampleMessage,
                      WebRTCClientAdapter, WebRTCServerAdapter, GenerateConnectToken, netcode, reliable, serialize, sodium ];
