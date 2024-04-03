package Cliente;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class RodaCliente {
    
    public static void main(String[] args) throws UnknownHostException, IOException{
        
        Socket socket = new Socket("127.0.0.1",12345);
        InetAddress inet = socket.getInetAddress();

        System.out.println("HostAdress = "+inet.getHostAddress());
        System.out.println("HostName = "+inet.getHostName());


        
        Cliente c = new Cliente(socket);
        Thread t = new Thread(c);
        t.start();
    }
}