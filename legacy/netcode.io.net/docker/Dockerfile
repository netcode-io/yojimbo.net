FROM netcodeio/ubuntu-dotnet:latest

CMD ["/sbin/my_init"]

WORKDIR /app

RUN wget https://github.com/premake/premake-core/releases/download/v5.0.0-alpha14/premake-5.0.0-alpha14-linux.tar.gz \
    && tar -zxvf premake-*.tar.gz \
    && rm premake-*.tar.gz \
    && mv premake5 /usr/local/bin

ADD netcode.io.net /app/netcode.io.net

RUN cd netcode.io.net && find . -exec touch {} \; \
    && premake5 solution \
    && dotnet build -c Release -o ../.. _test \
    && dotnet build -c Release -o ../.. _client \
    && dotnet build -c Release -o ../.. _server \
    && dotnet build -c Release -o ../.. _client_server \
    && cd .. && rm -rf netcode.io.net

EXPOSE 40000

ENTRYPOINT dotnet server.dll

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*