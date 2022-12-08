package com.idemia.keyless.socket;

import lombok.extern.slf4j.Slf4j;

import java.net.*;
import java.io.*;

@Slf4j
public class GreetServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;

    public void start(int port) {
        try {
            log.info("JAVA SERVER Started on port: " + port);
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String greeting = in.readLine();
            log.info("JAVA SERVER RECEIVED: " + greeting);
            out.println(greeting + " odpowiedz z servera");
        } catch (IOException e) {
            log.debug(e.getMessage());
        }
    }

    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            log.debug(e.getMessage());
        }
    }
}
