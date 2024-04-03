package Servidor;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.SecretKey;

import Criptografia.CriptoRSA;
import Criptografia.CriptografiaAES;

public class Servidor implements Runnable{


    public Socket socketCliente;
    public static int cont = 0;
    private boolean conexaoTrocaDeChavesRSA = true;
    private boolean conexaoTrocaDeMensagens = true;
    private boolean conexaoEnvioChaveAES = true;
    private PrintStream saida;
    private ObjectOutputStream out;
    private DataOutputStream outChave;

    private boolean mensagem1 = true;
    private boolean mensagemChave = true;
    private CriptoRSA cripto = new CriptoRSA();
    private String ChavePublicaCliente;

    private CriptografiaAES criptoAES;
    private SecretKey chaveAES;

    private BigInteger eChaveServidor;
    private BigInteger nChaveServidor;
    private BigInteger dChaveServidor;
    

    public Servidor(Socket cliente){
        socketCliente = cliente;
    }

    @Override
    public void run() {
        
        System.out.println("Conexao "+Servidor.cont+" com o cliente "+socketCliente.getInetAddress().getHostAddress() + "/"
        + socketCliente.getInetAddress().getHostName() );
        
        try {
            
            BigInteger eCliente = new BigInteger("123123");
            BigInteger nCliente = new BigInteger("123213");

            String mensagemRecebida;

            Scanner s = null;
            s = new Scanner(socketCliente.getInputStream());
            
            String chave = "chavepublicaservidor";
            saida = new PrintStream(socketCliente.getOutputStream());

            criptoAES = new CriptografiaAES();

            out = new ObjectOutputStream(socketCliente.getOutputStream());
            outChave = new DataOutputStream(socketCliente.getOutputStream());

            //armazena as partes da chave publica do cliente
            String letraE,LetraN, LetraEeLetraN;

            //troca de chaves RSA
            if (conexaoTrocaDeChavesRSA) {

                //gera chave do servidor
                //recebe os valores
                eChaveServidor = cripto.enviarE();
                nChaveServidor = cripto.enviarN();
                dChaveServidor = cripto.enviarD();

                //converte para string
                letraE = eChaveServidor.toString();
                LetraN = nChaveServidor.toString();
                
                //concateno ambos
                LetraEeLetraN = letraE+ " " +LetraN;

                //envia a chave publica do servidor ao cliente
                saida.println(LetraEeLetraN);
                saida.flush();


                //Pega chave do cliente
                //recebe a chave do servidor
                ChavePublicaCliente = s.nextLine();
                
                //tira a concatenação
                String[] array = ChavePublicaCliente.split(" ");

                String LetraECliente = array[0];
                String LetraNCliente = array[1];


                eCliente = new BigInteger(LetraECliente);
                nCliente = new BigInteger(LetraNCliente);
                    
                conexaoTrocaDeChavesRSA = false;

            }

            //envio(usando RSA) da chave AES para o cliente 
            if (conexaoEnvioChaveAES) {

                //gerar chave AES
                try {
                    chaveAES = criptoAES.gerarChave();
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                System.out.println("*******************");
                System.out.println(chaveAES);
                System.out.println("*******************");


                byte[] chaveemBytes = chaveAES.getEncoded();

                String chaveEmString = Base64.getEncoder().encodeToString(chaveemBytes);

                String ChaveCifrada = cripto.encriptar(chaveEmString, eCliente, nCliente);

                // outChave.writeInt(ChaveCifrada.length);
                // outChave.write(ChaveCifrada);
                // outChave.flush();

                // out.writeObject(chaveAES);
                // out.flush();

                saida.println(ChaveCifrada);
                

                conexaoEnvioChaveAES = false;
                
            }

            while (conexaoTrocaDeMensagens) {
                //saida.print(chaveAES);

                //recebe mensagem cifrada enviada pelo cliente
                mensagemRecebida = s.nextLine();

                System.out.println(mensagemRecebida);

                

                //fazer decifração usando a chave privada do servidor

                //transformar de string para bytes[]

                String mensagemoriginal;
                try {
                    mensagemoriginal = criptoAES.decifrar(mensagemRecebida,chaveAES);

                    System.out.println("******************");
                    System.out.println(mensagemoriginal);
                    System.out.println("******************");
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                

                //quando for enviar mensagem
                //cifra
            }
                
            saida.close();
            s.close();
            System.out.println("Fim do cliente "+socketCliente.getInetAddress());
            socketCliente.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
}