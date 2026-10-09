Building yojimbo.net
================

## Building on Windows

Download [premake 5](https://premake.github.io/download.html) and copy the **premake5** executable somewhere in your path. Please make sure you have at least premake5 alpha 14.

You need Visual Studio to build the source code. If you don't have Visual Studio 2017 you can [download the community edition for free](https://www.visualstudio.com/en-us/downloads/download-visual-studio-vs.aspx).

Once you have Visual Studio installed, go to the command line under the yojimbo directory and type:

    premake5 solution

This creates Yojimbo.sln and opens it in Visual Studio for you.

You can now build the library and run individual test programs as you would for any other Visual Studio solution.

## Building on MacOS and Linux

First, download and install [premake 5](https://premake.github.io/download.html).

Now go to the command line under the yojimbo.net directory and enter:

    premake5 gmake

This creates yojimbo.sln for you.

Alternatively, you can use the following shortcuts to build and run test programs directly:

    premake5 test           // build and run unit tests

    premake5 server         // build run a yojimbo server on localhost on UDP port 40000

    premake5 client         // build and run a yojimbo client that connects to the server running on localhost 
   
## Run a yojimbo server inside Docker

**yojimbo.net** supports Docker on Windows, Mac and Linux.

First, install the latest version of Docker from <http://www.docker.com>

Now go to the command line at the yojimbo directory and enter:

    premake5 docker

This builds and runs a Docker container with a yojimbo server inside it (exactly the same as if you ran "premake5 server" on a Linux box). You can now connect to this server by running a client which connects to 127.0.0.0:40000. For example, "premake5 client" on Mac or Linux, or running the "client" project inside the Yojimbo.sln in Visual Studio.

IMPORTANT: The premake docker action takes a long time initially, because it has a lot of work to do:

1. Start a new docker image from an [ubuntu derived base image with .net core](https://github.com/netcode-io/docker.img)

2. `apt-get update, apt-get install wget`

3. Download, build and install premake5

4. Build release version of yojimbo, run tests

5. If all tests pass, clean everything and copy the yojimbo server to the /home dir

6. When the Docker container is run, start the yojimbo server /home/server on UDP port 40000.

For details see docker/Dockerfile and the premake5.lua file with commands that build and run the container instance.

What's most impressive is that if no dependencies have changed, the numbered steps above are precached as intermediate Docker instances are not rebuilt unless necessary. For example, if you have already downloaded and installed wget, g++, libsodium, premake5, mbedtls and you run "premake5 docker" again, these steps are skipped.

Try it yourself by running "premake5 docker" once (it should build everything), then run it again. It will go straight to the server running on port 40000. Similarly, if you change some yojimbo source it automatically rebuilds yojimbo server and runs tests before starting the server. Impressive!

## Run a yojimbo matcher inside Docker (not implemented)

In order to demonstrate authentication and a secure connection between client and server, yojimbo provides an example backend written in golang.

You can run this backend in Docker via this command:

    premake5 matcher

This builds and runs a linux docker instance with matcher.go running on port 8080.

You can verify the matcher instance is working correctly as follows:

    curl https://localhost:8080/match/12345/1 --insecure

Which should return a base64 encoded text response that represents a **connect token**. This is what a client passes to the server in order to establish a secure connection.

## Running a secure server

Up to this point we have been running insecure servers with "premake5 server". 

This mode is useful during development, but once you ship your game, but it gives clients access to the private key. 

This makes it possible for clients to connect to servers without authentication, which makes it possible to DDoS your servers.

To fix this, yojimbo provides support for secure authenticated servers. These servers only allow clients to connect who have authenticated through the matcher service, which is a stand-in for your own web backend that matches clients to dedicated server instances when they want to play a game.

You can run a secure server like this on MacOS and Linux:

    premake5 secure_server

Or, if you are building under Visual Studio, run the "secure_server" project from the IDE.

## Connect a secure client

First run the matcher service via:

    premake5 matcher
    
Next run the secure client:

    premake5 secure_client

If everything is working correctly you should see something like:

    connecting client (secure)
    client id is 12a485afe59b1c71
    requesting match from https://localhost:8080
    received connect token from matcher
    client started on port 65067
    client connecting to server 127.0.0.1:40000 [1/1]
    client connected to server
    
What just happened?

1. The secure client requested a **connect token** from the matcher over HTTPS. The connect token is a cryptographic token that grants the client a right to connect to a dedicated server for a short period of time (eg. 45 seconds).

2. The secure client passed the connect token to the dedicated server as part of its connection handshake over UDP.

3. The secure server validated the connect token, making sure it grants connection to that particular server, and has not expired, then accepted the client connection.

4. The server and client exchange signed and encrypted packets over UDP.

These steps ensure that clients can only connect to secure tokens if they go through the matcher first. This means that only clients authenticated with your web backend can connect to your dedicated servers, which is typically what you want!

## Documentation and Support

**yojimbo** now has reference documentation built from code comments with [doxygen](http://www.stack.nl/~dimitri/doxygen/).

To build the documentation first install doxygen on your platform.

Once you have doxygen installed and in your path, you can build and view the documentation with this command:

    premake5 docs
    
More documentation including getting started guide and usage documentation is coming shortly. 

Until then, if you have questions and you don't find the answer you need in the documentation, please create an issue at https://github.com/netcode-io/yojimbo.net and I'll do my best to help you out.
