package Servidor;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class RodaServidor {
    
    public static void main(String[] args) throws Exception{
        
        ServerSocket socketServidor = new ServerSocket(12345);

        System.out.println("Servidor rodando na portaa "+ socketServidor.getLocalPort());
        System.out.println("HostAddress =  "+InetAddress.getLocalHost().getHostAddress());
        System.out.println("HostName =  "+InetAddress.getLocalHost().getHostName());

        System.out.println("Aguardando conexao do cliente...");

        while (true) {
            Socket cliente = socketServidor.accept();
            
            Servidor servidor = new Servidor(cliente);
            Thread t = new Thread(servidor);

            Servidor.cont++;
            t.start();
        }
    }
}