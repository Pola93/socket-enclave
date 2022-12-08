package com.idemia.keyless.socket;

public class ServerStart {
    public static void main(String[] args) {
        GreetServer server = new GreetServer();
        server.start(6666);
    }
}
