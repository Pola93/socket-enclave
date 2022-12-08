package com.idemia.keyless.socket;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ClientStart {

    public static void main(String[] args) {
        log.info("Start Java Client");
        GreetClient client = new GreetClient();
        client.startConnection("127.0.0.1", 6666);
        final String response = client.sendMessage("Wiadomosc z java clienta");
        log.info("Java response from server: " + response);
        client.stopConnection();
    }
}
