@echo off
rmdir /s /q yojimbo.net
mkdir yojimbo.net
mkdir yojimbo.net\tests
copy ..\*.cs yojimbo.net
copy ..\premake5.lua yojimbo.net
robocopy /MIR /DCOPY:T ..\netcode.io.net yojimbo.net\netcode.io.net
robocopy /MIR /DCOPY:T ..\reliable.io.net yojimbo.net\reliable.io.net
REM because robocopy sometimes sets non-zero error codes on successful operation. what the actual fuck windows
cmd /c "exit /b 0"
