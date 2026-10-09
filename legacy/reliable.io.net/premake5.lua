debug_libs = { "System" }
release_libs = debug_libs

solution "reliable"
    kind "ConsoleApp"
    language "C#"
    platforms { "x64" }
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
    files { "test.cs", "reliable.cs", "reliable_test.cs" }

project "soak"
    files { "soak.cs", "reliable.cs" }

project "stats"
    files { "stats.cs", "reliable.cs" }

project "fuzz"
    files { "fuzz.cs", "reliable.cs" }

if os.ishost "windows" then

    -- Windows

    newaction
    {
        trigger     = "solution",
        description = "Create and open the reliable.io solution",
        execute = function ()
            os.execute "premake5 vs2017"
            os.execute "start reliable.sln"
        end
    }

    newaction
    {
        trigger     = "docker",
        description = "Build and run reliable.io.net tests inside docker",
        execute = function ()
            os.execute "rmdir /s/q docker\\reliable.io.net & mkdir docker\\reliable.io.net \z
&& copy *.cs docker\\reliable.io.net\\ \z
&& copy premake5.lua docker\\reliable.io.net\\ \z
&& cd docker \z
&& docker build -t \"netcodeio:reliable.io.net-server\" . \z
&& rmdir /s/q reliable.io.net \z
&& docker run -ti -p 40000:40000/udp netcodeio:reliable.io.net-server"
        end
    }

else

  -- MacOSX and Linux.
    
  newaction
  {
      trigger     = "solution",
      description = "Create and open the reliable.io solution",
      execute = function ()
        os.execute [[
dotnet new console --force -o _test -n test && rm _test/Program.cs
cp test.cs reliable.cs reliable_test.cs _test]]
        os.execute [[
dotnet new console --force -o _soak -n soak && rm _soak/Program.cs
cp soak.cs reliable.cs _soak]]
        os.execute [[
dotnet new console --force -o _stats -n stats && rm _stats/Program.cs
cp stats.cs reliable.cs _stats]]
        os.execute [[
dotnet new console --force -o _fuzz -n fuzz && rm _fuzz/Program.cs
cp fuzz.cs reliable.cs _fuzz]]
        os.execute [[
dotnet new sln --force -n reliable
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
      trigger     = "stats",
      description = "Build and run stats example",
      execute = function ()
        os.execute "test ! -d _stats && premake5 solution"
        os.execute "dotnet build -o ../bin _stats/stats.csproj && dotnet ./bin/stats.dll"
      end
  }

  newaction
  {
      trigger     = "fuzz",
      description = "Build and run fuzz test",
      execute = function ()
        os.execute "test ! -d _fuzz && premake5 solution"
        os.execute "dotnet build -o ../bin _fuzz/fuzz.csproj && dotnet ./bin/fuzz.dll"
      end
  }

  newaction
  {
      trigger     = "docker",
      description = "Build and run reliable.io.net tests inside docker",
      execute = function ()
          os.execute "rm -rf docker/reliable.io.net && mkdir -p docker/reliable.io.net \z
&& cp *.cs docker/reliable.io.net \z
&& cp premake5.lua docker/reliable.io.net \z
&& cd docker \z
&& docker build -t \"netcodeio:reliable.io.net-server\" . \z
&& rm -rf reliable.io.net \z
&& docker run -ti -p 40000:40000/udp netcodeio:reliable.io.net-server"
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
            "_test",
            "_soak",
            "_stats",
            "_fuzz",
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
            "docker/reliable.io.net"
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
