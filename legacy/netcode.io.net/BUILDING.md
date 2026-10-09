How to build netcode.io.net
=======================

## Building on Windows

Download [premake 5](https://premake.github.io/download.html) and copy the **premake5** executable somewhere in your path. Please make sure you have at least premake5 alpha 14.

You need Visual Studio to build the source code. If you don't have Visual Studio 2017 you can [download the community edition for free](https://www.visualstudio.com/en-us/downloads/download-visual-studio-vs.aspx).

Once you have Visual Studio installed, go to the command line under the netcode.io.net/ directory and type:

    premake5 solution

This creates netcode.sln and opens it in Visual Studio for you.

Now you can build the library and run individual test programs as you would for any other Visual Studio solution.

## Building on MacOS and Linux

First, download and install [premake 5](https://premake.github.io/download.html) alpha 14 or greater.

Now go to the command line under the netcode.io.net directory and enter:

    premake5 solution

This creates netcode.sln for you.

Alternatively, you can use the following shortcuts to build and run test programs directly:

    premake5 test           // build and run unit tests

    premake5 server         // build run a netcode.io server on localhost on UDP port 40000

    premake5 client         // build and run a netcode.io client that connects to the server running on localhost 

    premake5 stress         // connect 256 netcode.io clients to a running server as a stress test

If you have questions please create an issue at https://github.com/netcode-io/netcode.io.net and I'll do my best to help you out.