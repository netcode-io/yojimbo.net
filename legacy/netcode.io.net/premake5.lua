debug_libs = { "System" }
release_libs = debug_libs

solution "netcode"
    kind "ConsoleApp"
    dotnetframework "4.6.1"
    language "C#"
    platforms { "x64" }
    nuget { "Portable.BouncyCastle:1.8.4" }
    configurations { "Debug", "Release" }
    flags { }
    configuration "Debug"
        symbols "On"
        defines { "DEBUG" }
        links { debug_libs }
    configuration "Release"
        symbols "Off"
        optimize "Speed"
        links { release_libs }

project "test"
    files { "test.cs", "netcode.cs", "netcode_test.cs" }

project "soak"
    files { "soak.cs", "netcode.cs" }

project "profile"
    files { "profile.cs", "netcode.cs" }

project "client"
    files { "client.cs", "netcode.cs" }

project "server"
    files { "server.cs", "netcode.cs" }

project "client_server"
    files { "client_server.cs", "netcode.cs" }

if os.ishost "windows" then

    -- Windows
    newaction
    {
        trigger     = "solution",
        description = "Create and open the netcode.io solution",
        execute = function ()
            os.execute "premake5 vs2015"
            os.execute "start netcode.sln"
        end
    }

    newaction
    {
        trigger     = "docker",
        description = "Build and run a netcode.io.net server inside a docker container",
        execute = function ()
            os.execute "docker run --rm --privileged alpine hwclock -s" -- workaround for clock getting out of sync on macos. see https://docs.docker.com/docker-for-mac/troubleshoot/#issues
            os.execute "rmdir /s/q docker\\netcode.io.net & mkdir docker\\netcode.io.net \z
&& copy *.cs docker\\netcode.io.net\\ \z
&& copy premake5.lua docker\\netcode.io.net\\ \z
&& cd docker \z
&& docker build -t \"netcodeio:netcode.io.net-server\" . \z
&& rmdir /s/q netcode.io.net \z
&& docker run -ti -p 40000:40000/udp netcodeio:netcode.io.net-server"
        end
    }

    -- todo: create shortcuts here too for windows for consistency

else

     -- MacOSX and Linux.
    
     newaction
     {
         trigger     = "solution",
         description = "Create and open the netcode.io solution",
         execute = function ()
             os.execute [[
dotnet new console --force -o _test -n test && rm _test/Program.cs
dotnet add _test package Portable.BouncyCastle
cp test.cs netcode.cs netcode_test.cs _test]]
             os.execute [[
dotnet new console --force -o _soak -n soak && rm _soak/Program.cs
dotnet add _soak package Portable.BouncyCastle
cp soak.cs netcode.cs _soak]]
             os.execute [[
dotnet new console --force -o _profile -n profile && rm _profile/Program.cs
dotnet add _profile package Portable.BouncyCastle
cp profile.cs netcode.cs _profile]]
             os.execute [[
dotnet new console --force -o _client -n client && rm _client/Program.cs
dotnet add _client package Portable.BouncyCastle
cp client.cs netcode.cs _client]]
             os.execute [[
dotnet new console --force -o _server -n server && rm _server/Program.cs
dotnet add _server package Portable.BouncyCastle
cp server.cs netcode.cs _server]]
             os.execute [[
dotnet new console --force -o _client_server -n client_server && rm _client_server/Program.cs
dotnet add _client_server package Portable.BouncyCastle
cp client_server.cs netcode.cs _client_server]]
             os.execute [[
dotnet new sln --force -n netcode
dotnet sln add _*/*.csproj]]
         end
     }

     newaction
     {
         trigger     = "test",
         description = "Build and run all unit tests",
         execute = function ()
            os.execute "test ! -d _test && premake5 solution"
            os.execute "dotnet build -o ../bin _test/test.csproj && dotnet ./bin/test.dll"
         end
     }
 
     newaction
     {
         trigger     = "soak",
         description = "Build and run soak test",
         execute = function ()
            os.execute "test ! -d _soak && premake5 solution"
            os.execute "dotnet build -o ../bin _soak/soak.csproj && dotnet ./bin/soak.dll"
         end
     }
 
     newaction
     {
         trigger     = "profile",
         description = "Build and run profile tet",
         execute = function ()
            os.execute "test ! -d _profile && premake5 solution"
            os.execute "dotnet build -o ../bin _profile/profile.csproj && dotnet ./bin/profile.dll"
         end
     }
 
     newaction
     {
         trigger     = "client",
         description = "Build and run the client",
         execute = function ()
            os.execute "test ! -d _client && premake5 solution"
            os.execute "dotnet build -o ../bin _client/client.csproj && dotnet ./bin/client.dll"
         end
     }
 
     newaction
     {
         trigger     = "server",
         description = "Build and run the server",
         execute = function ()
            os.execute "test ! -d _server && premake5 solution"
            os.execute "dotnet build -o ../bin _server/server.csproj && dotnet ./bin/server.dll"
         end
     }
 
     newaction
     {
         trigger     = "client_server",
         description = "Build and run the client/server testbed",
         execute = function ()
            os.execute "test ! -d _client_server && premake5 solution"
            os.execute "dotnet build -o ../bin _client_server/client_server.csproj && dotnet ./bin/client_server.dll"
         end
     }
 
     newaction
     {
         trigger     = "docker",
         description = "Build and run a netcode.io.net server inside a docker container",
         execute = function ()
             os.execute "docker run --rm --privileged alpine hwclock -s" -- workaround for clock getting out of sync on macos. see https://docs.docker.com/docker-for-mac/troubleshoot/#issues
             os.execute "rm -rf docker/netcode.io.net && mkdir -p docker/netcode.io.net \z
&& cp *.cs docker/netcode.io.net \z
&& cp premake5.lua docker/netcode.io.net \z
&& cd docker \z
&& docker build -t \"netcodeio:netcode.io.net-server\" . \z
&& rm -rf netcode.io.net \z
&& docker run -ti -p 40000:40000/udp netcodeio:netcode.io.net-server"
         end
     }
 
     newaction
     {
         trigger     = "stress",
         description = "Launch 256 client instances to stress test the server",
         execute = function ()
            os.execute "test ! -d _client && premake5 solution"
             if os.execute "dotnet build -o ../bin _client/client.csproj" == true then
                for i = 0, 255 do
                    os.execute "dotnet ./bin/client.dll &"
                end
             end
         end
     }
 
     newaction
     {
         trigger     = "loc",
         description = "Count lines of code",
         execute = function ()
             os.execute "wc -l *.cs"
         end
     }
     
end

newaction
{
    trigger     = "clean",
    description = "Clean all build files and output",
    execute = function ()
        files_to_delete = 
        {
            "Makefile",
            "app.config",
            "packages.config",
            "*.make",
            "*.txt",
            "*.zip",
            "*.tar.gz",
            "*.db",
            "*.opendb",
            "*.csproj",
            "*.csproj.user",
            "*.sln",
            "*.xcodeproj",
            "*.xcworkspace"
        }
        directories_to_delete = 
        {
            "_client",
            "_client_server",
            "_profile",
            "_server",
            "_soak",
            "_test",
            "obj",
            "ipch",
            "bin",
            ".vs",
            "Debug",
            "Release",
            "release",
            "packages",
            "cov-int",
            "docs",
            "xml",
            "docker/netcode.io.net"
        }
        for i,v in ipairs( directories_to_delete ) do
          os.rmdir( v )
        end
        if not os.ishost "windows" then
            os.execute "find . -name .DS_Store -delete"
            for i,v in ipairs( files_to_delete ) do
              os.execute( "rm -f " .. v )
            end
        else
            for i,v in ipairs( files_to_delete ) do
              os.execute( "del /F /Q  " .. v )
            end
        end

    end
}
