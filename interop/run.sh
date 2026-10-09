#!/bin/bash
# Runs every server/client pairing of the C++ and C# implementations against each other.
# usage: interop/run.sh [port]      (builds both sides first; exit code is the number of failed pairings)
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${1:-45000}
"$HERE/build_cpp.sh" > /dev/null || exit 1
dotnet build "$HERE/cs/interop.csproj" -c Release -v q -nologo > /dev/null || exit 1
CPP="$HERE/bin/cpp/interop"
CS="dotnet $HERE/cs/bin/Release/net10.0/interop.dll"
failed=0
run() {
    local name=$1 server=$2 client=$3
    $server server $PORT > /tmp/interop_server.$$ 2>&1 &
    local pid=$!
    sleep 1
    $client client $PORT > /tmp/interop_client.$$ 2>&1
    local client_result=$?
    wait $pid; local server_result=$?
    if [ $client_result -eq 0 ] && [ $server_result -eq 0 ]; then
        echo "PASS  $name   $(grep 'echoes verified' /tmp/interop_client.$$)"
    else
        echo "FAIL  $name"; sed 's/^/      client: /' /tmp/interop_client.$$; sed 's/^/      server: /' /tmp/interop_server.$$
        failed=$((failed + 1))
    fi
    rm -f /tmp/interop_server.$$ /tmp/interop_client.$$
}
run "c++ server <-> c++ client" "$CPP" "$CPP"
run "c#  server <-> c#  client" "$CS" "$CS"
run "c++ server <-> c#  client" "$CPP" "$CS"
run "c#  server <-> c++ client" "$CS" "$CPP"
exit $failed
