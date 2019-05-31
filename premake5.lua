
yojimbo_version = "1.0"

libs = { "System" }

solution "yojimbo"
    kind "ConsoleApp"
    dotnetframework "4.6.1"
    language "C#"
    platforms { "x64" }
    configurations { "Debug", "Release" }
    links { libs }
    configuration "Debug"
        symbols "On"
        defines { "DEBUG" }
    configuration "Release"
        optimize "Speed"
        
project "test"
    files { "test.cs", "shared_h.cs" }
    links { "yojimbo" }

project "yojimbo"
    kind "SharedLib"
    nuget { "Portable.BouncyCastle:1.8.4" }
    defines { "YOJIMBO", "NETCODE_ENABLE_TESTS", "RELIABLE_ENABLE_TESTS" }
    files { "yojimbo.cs", "netcode.io.net/netcode.cs", "netcode.io.net/netcode_test.cs", "reliable.io.net/reliable.cs", "reliable.io.net/reliable_test.cs" }

project "client"
    files { "client.cs", "shared_h.cs" }
    links { "yojimbo" }

project "server"
    files { "server.cs", "shared_h.cs" }
    links { "yojimbo" }

project "secure_client"
    files { "secure_client.cs", "shared_h.cs" }
    links { "yojimbo" }

project "secure_server"
    files { "secure_server.cs", "shared_h.cs" }
    links { "yojimbo" }

project "client_server"
    files { "client_server.cs", "shared_h.cs" }
    links { "yojimbo" }

project "loopback"
    files { "loopback.cs", "shared_h.cs" }
    links { "yojimbo" }

project "soak"
    files { "soak.cs", "shared_h.cs" }
    links { "yojimbo" }

if not os.ishost "windows" then

    -- MacOSX and Linux.

    newaction
    {
        trigger     = "solution",
        description = "Create and open the yojimbo.net solution",
        execute = function ()
            os.execute [[
dotnet new classlib --force -f netcoreapp2.2 -o _yojimbo -n yojimbo && rm _yojimbo/Class1.cs
sed -i 's/<\/TargetFramework>/<\/TargetFramework><DefineConstants>YOJIMBO;NETCODE_ENABLE_TESTS;RELIABLE_ENABLE_TESTS<\/DefineConstants>/' _yojimbo/yojimbo.csproj
dotnet add _yojimbo package Portable.BouncyCastle
cp yojimbo.cs _yojimbo
cp netcode.io.net/netcode.cs netcode.io.net/netcode_test.cs _yojimbo
cp reliable.io.net/reliable.cs reliable.io.net/reliable_test.cs _yojimbo]]
            os.execute [[
dotnet new console --force -o _test -n test && rm _test/Program.cs
dotnet add _test reference _yojimbo
cp test.cs shared_h.cs _test]]
            os.execute [[
dotnet new console --force -o _client -n client && rm _client/Program.cs
dotnet add _client reference _yojimbo
cp client.cs shared_h.cs _client]]
            os.execute [[
dotnet new console --force -o _server -n server && rm _server/Program.cs
dotnet add _server reference _yojimbo
cp server.cs shared_h.cs _server]]
            os.execute [[
dotnet new console --force -o _secure_client -n secure_client && rm _secure_client/Program.cs
dotnet add _secure_client reference _yojimbo
cp secure_client.cs shared_h.cs _secure_client]]
            os.execute [[
dotnet new console --force -o _secure_server -n secure_server && rm _secure_server/Program.cs
dotnet add _secure_server reference _yojimbo
cp secure_server.cs shared_h.cs _secure_server]]
            os.execute [[
dotnet new console --force -o _client_server -n client_server && rm _client_server/Program.cs
dotnet add _client_server reference _yojimbo
cp client_server.cs shared_h.cs _client_server]]
            os.execute [[
dotnet new console --force -o _loopback -n loopback && rm _loopback/Program.cs
dotnet add _loopback reference _yojimbo
cp loopback.cs shared_h.cs _loopback]]
            os.execute [[
dotnet new console --force -o _soak -n soak && rm _soak/Program.cs
dotnet add _soak reference _yojimbo
cp soak.cs shared_h.cs _soak]]
            os.execute [[
dotnet new sln --force -n yojimbo
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
        trigger     = "client_server",
        description = "Build and run client/server test",     
        execute = function ()
            os.execute "test ! -d _client_server && premake5 solution"
            os.execute "dotnet build -o ../bin _client_server/client_server.csproj && dotnet ./bin/client_server.dll"
        end
    }

    newaction
    {
        trigger     = "loopback",
        description = "Build and run loopback test",     
        execute = function ()
            os.execute "test ! -d _loopback && premake5 solution"
            os.execute "dotnet build -o ../bin _loopback/loopback.csproj && dotnet ./bin/loopback.dll"
        end
    }

    newoption 
    {
        trigger     = "serverAddress",
        value       = "IP[:port]",
        description = "Specify the server address that the client should connect to",
    }

    newaction
    {
        trigger     = "client",
        description = "Build and run client",
        execute = function ()
            os.execute "test ! -d _client && premake5 solution"
            if os.execute "dotnet build -o ../bin _client/client.csproj" then
                if _OPTIONS["serverAddress"] then
                    os.execute( "dotnet ./bin/client.dll " .. _OPTIONS["serverAddress"] )
                else
                    os.execute "dotnet ./bin/client.dll"
                end
            end
        end
    }

    newaction
    {
        trigger     = "server",
        description = "Build and run server",     
        execute = function ()
            os.execute "test ! -d _server && premake5 solution"
            os.execute "dotnet build -o ../bin _server/server.csproj && dotnet ./bin/server.dll"
        end
    }

    newaction
    {
        trigger     = "secure_server",
        description = "Build and run secure server",     
        execute = function ()
            os.execute "test ! -d _secure_server && premake5 solution"
            os.execute "dotnet build -o ../bin _secure_server/secure_server.csproj && dotnet ./bin/secure_server.dll"
        end
    }

    newaction
    {
        trigger     = "docker",
        description = "Build and run a yojimbo server inside a docker container",
        execute = function ()
            os.execute "docker run --rm --privileged alpine hwclock -s" -- workaround for clock getting out of sync on macos. see https://docs.docker.com/docker-for-mac/troubleshoot/#issues
            os.execute "rm -rf docker/yojimbo.net && mkdir -p docker/yojimbo.net \z
&& mkdir -p docker/yojimbo.net/tests \z
&& cp *.cs docker/yojimbo.net \z
&& cp premake5.lua docker/yojimbo.net \z
&& cp -R reliable.io.net docker/yojimbo.net \z
&& cp -R netcode.io.net docker/yojimbo.net \z
&& cd docker \z
&& docker build -t \"netcodeio:yojimbo.net-server\" . \z
&& rm -rf yojimbo.net \z
&& docker run -ti -p 40000:40000/udp netcodeio:yojimbo.net-server"
        end
    }

    newaction
    {
        trigger     = "matcher",
        description = "Build and run the matchmaker web service inside a docker container",
        execute = function ()
            os.execute "docker run --rm --privileged alpine hwclock -s" -- workaround for clock getting out of sync on macos. see https://docs.docker.com/docker-for-mac/troubleshoot/#issues
            os.execute "cd matcher \z
&& docker build -t netcodeio:yojimbo.net-matcher . \z
&& docker run -ti -p 8080:8080 netcodeio:yojimbo.net-matcher"
        end
    }

    newaction
    {
        trigger     = "secure_client",
        description = "Build and run secure client and connect to a server via the matcher",
        execute = function ()
            os.execute "test ! -d _secure_client && premake5 solution"
            os.execute "dotnet build -o ../bin _secure_client/secure_client.csproj && dotnet ./bin/secure_client.dll"
        end
    }

    newaction
    {
        trigger     = "stress",
        description = "Launch 64 secure client instances to stress the matcher and server",
        execute = function ()
            os.execute "test ! -d _secure_client && premake5 solution"
            if os.execute "dotnet build -o ../bin _secure_client/secure_client.csproj" then
                for i = 0, 63 do
                    os.execute "dotnet ./bin/secure_client.dll &"
                end
            end
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
        trigger     = "loc",
        description = "Count lines of code",
        execute = function ()
            os.execute "wc -l *.cs netcode.io.net/*.cs reliable.io.net/*.cs"
        end
    }

    newaction
    {
        trigger     = "release",
        description = "Create a release of this project",
        execute = function ()
            _ACTION = "clean"
            premake.action.call "clean"
            files_to_zip = "README.md BUILDING.md CHANGES.md ROADMAP.md *.cs premake5.lua docker tests"
            -- todo: need to update this so it works with netcode.io and reliable.io sub-projects
            os.execute( "rm -rf *.zip *.tar.gz" )
            os.execute( "rm -rf docker/yojimbo.net" )
            os.execute( "zip -9r yojimbo.net-" .. yojimbo_version .. ".zip " .. files_to_zip )
            os.execute( "unzip yojimbo.net-" .. yojimbo_version .. ".zip -d yojimbo.net-" .. yojimbo_version )
            os.execute( "tar -zcvf yojimbo.net-" .. yojimbo_version .. ".tar.gz yojimbo.net-" .. yojimbo_version )
            os.execute( "rm -rf yojimbo.net-" .. yojimbo_version )
            os.execute( "mkdir -p release" )
            os.execute( "mv yojimbo.net-" .. yojimbo_version .. ".zip release" )
            os.execute( "mv yojimbo.net-" .. yojimbo_version .. ".tar.gz release" )
            os.execute( "echo" )
            os.execute( "echo \"*** SUCCESSFULLY CREATED RELEASE - yojimbo.net-" .. yojimbo_version .. " *** \"" )
            os.execute( "echo" )
        end
    }

    newaction
    {
        trigger     = "sublime",
        description = "Create sublime project",
        execute = function ()
            os.execute "cp .sublime yojimbo.net.sublime-project"
        end
    }

    newaction
    {
        trigger     = "docs",
        description = "Build documentation",
        execute = function ()
            if os.get() == "macosx" then
                os.execute "doxygen doxygen.config && open docs/html/index.html"
            else
                os.execute "doxygen doxygen.config"
            end
        end
    }

    newaction
    {
        trigger     = "update_submodules",
        description = "Updates to latest code for netcode.io.net and reliable.io.net",
        execute = function ()
            os.execute [[
git pull
git submodule update --remote --merge
git add *
git commit -am "update submodules"
git push]]
        end
    }


else

    -- Windows

    newaction
    {
        trigger     = "solution",
        description = "Open yojimbo.sln",
        execute = function ()
            os.execute "premake5 vs2015"
            os.execute "start yojimbo.sln"
        end
    }

	newaction
	{
		trigger     = "docker",
		description = "Build and run a yojimbo server inside a docker container",
		execute = function ()
			os.execute "cd docker && copyFiles.cmd && buildServer.cmd && runServer.cmd"
		end
	}

    newaction
    {
        trigger     = "matcher",
        description = "Build and run the matchmaker web service inside a docker container",
        execute = function ()
            os.execute "cd matcher \z
&& docker build -t netcodeio:yojimbo.net-matcher . \z
&& docker run -ti -p 8080:8080 netcodeio:yojimbo.net-matcher"
        end
    }

    newaction
    {
        trigger     = "stress",
        description = "Launch 64 secure client instances to stress the matcher and server",
        execute = function ()
            for i = 0, 63 do
                os.execute "if exist bin\\secure_client.dll ( start /B dotnet bin\\secure_client.dll ) else ( echo could not find bin\\secure_client.dll )"
            end
        end
    }

    newaction
    {
        trigger     = "docs",
        description = "Build documentation",
        execute = function ()
            os.execute "doxygen doxygen.config && start docs\\html\\index.html"
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
            "_yojimbo",
            "_test",
            "_client",
            "_server",
            "_secure_client",
            "_secure_server",
            "_client_server",
            "_loopback",
            "_soak",
            "obj",
            "ipch",
            "bin",
            ".vs",
            "Debug",
            "Release",
            "release",
            "cov-int",
            "docs",
            "xml",
            "docker/yojimbo.net"
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
