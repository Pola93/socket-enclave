FROM docker-release.otlabs.fr/dbi/docker-generic-app/openjdk-17:2022-10-26v1.1.4

COPY target/sockets-1.0-SNAPSHOT.jar /opt/app/sock.jar
COPY target/lib /opt/app/lib
ENV HOME="/opt/app"
EXPOSE 6666
ENTRYPOINT ["java","-cp","sock.jar:lib/*","com.idemia.keyless.socket.ServerStart"]