FROM docker-release.otlabs.fr/dbi/docker-generic-app/openjdk-17:2022-10-26v1.1.4

COPY target/sockets-1.0-SNAPSHOT.jar /opt/app/sock.jar
COPY target/lib /opt/app/lib
ENV HOME="/opt/app"
EXPOSE 6666

COPY target/classes/code/my-first-enclave/secure-local-channel/server.py /opt/app/server.py
COPY target/classes/code/my-first-enclave/secure-local-channel/run.sh /opt/app/run.sh

RUN chmod +x /opt/app/run.sh

CMD ["/opt/app/run.sh"]

#ENTRYPOINT ["java","-cp","sock.jar:lib/*","com.idemia.keyless.socket.ServerStart"]