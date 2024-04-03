package Cliente;
import Criptografia.CriptoRSA;
import Criptografia.CriptografiaAES;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Cliente implements Runnable{

    private Socket cliente;
    private boolean conexao1 = true;
    private boolean conexaoTrocaDeChavesPublicaRSA = true;
    private boolean conexaoParaDistribuicaoChaveAES = true;
    private boolean conexaoParaTrocaDeMensagens = true;
    private PrintStream saida;
    private ObjectInputStream in;
    private DataInputStream inChaveAES;

    private CriptografiaAES criptoAES;

    private CriptoRSA criptoRSA = new CriptoRSA();
    private String ChavePublicaServidor;                    //armazena a chave publica do servidor
    private SecretKey chaveAESServidor;


    BigInteger eServidor = new BigInteger("123123");
    BigInteger nServidor = new BigInteger("123213");
    

    public Cliente(Socket c){
        this.cliente = c;
    }

    @Override
    public void run() {
        try {
            System.out.println("O cliente conectou ao servidor");

            Scanner teclado = new Scanner(System.in);

            //se o cliente for receber algo do servidor
            //ver video Mini Tutorial Servidor de Eco Multithread em Java
            //parte 7:48 ele fala como fazer

            

            BigInteger dServidor = new BigInteger("123");

            //canal de envio de mensagens
            saida = new PrintStream(cliente.getOutputStream());

            //canal de recebimento de mensagens
            Scanner s = null;
            s = new Scanner(cliente.getInputStream());         
            
            in = new ObjectInputStream(cliente.getInputStream());

            inChaveAES = new DataInputStream(cliente.getInputStream());

            //armazena temporariamente a mensagem que sera enviada ao servidor, antes de ser cifrada
            String MensagemTemporaria;

            //armazena mensagem que sera enviada ao servidor
            String MensagemEnviada;

            //apagar essa variavel dps
            String mensagem;

            //armazena as partes da chave publica do cliente
            String letraE,LetraN, LetraEeLetraN;
             
            
            //Troca de chaves publica do RSA entre cliente e servidor
            if (conexaoTrocaDeChavesPublicaRSA) {

                //Recebe chave publica do servidor
                //que será usada para cifrar a mensagem do cliente para o servidor
                //o servidor usará sua chave privada para decfifrar a mensagem
                ChavePublicaServidor = s.nextLine();

                //Pega chave do servidor
                //tira a concatenação, alterar 
                String[] array = ChavePublicaServidor.split(" ");

                String LetraEServidor = array[0];
                String LetraNServidor = array[1];

                eServidor = new BigInteger(LetraEServidor);
                nServidor = new BigInteger(LetraNServidor);

                

                //Gera chave publica do cliente
                //recebe os valores
                BigInteger e = criptoRSA.enviarE();
                BigInteger n = criptoRSA.enviarN();
                BigInteger d = criptoRSA.enviarD();



                dServidor = criptoRSA.enviarD();

                //converte para string
                letraE = e.toString();
                LetraN = n.toString();
                
                //concateno ambos
                LetraEeLetraN = letraE+ " " +LetraN;
                
                //Envia chave publica do cliente para o servidor
                saida.println(LetraEeLetraN);

                conexaoTrocaDeChavesPublicaRSA = false;
            }

            //recebimento de chave do AES enviada pelo servidor
            if (conexaoParaDistribuicaoChaveAES) {
                
                String m = s.nextLine();
                
                String chaveDecifrada = criptoRSA.desencriptar(m, criptoRSA.enviarD(), criptoRSA.enviarN());

                byte[] chaveFinal = Base64.getDecoder().decode(chaveDecifrada);

                chaveAESServidor = new SecretKeySpec(chaveFinal, "AES");

                conexaoParaDistribuicaoChaveAES = false;
                    
                };


            //troca de mensagens entre cliente e servidor
            while (conexaoParaTrocaDeMensagens) {
                //descifrar
            
                System.out.println("Escreva uma mensagem: ");
                MensagemTemporaria = teclado.nextLine();
                
                //cifrar
                String fim = "";
                try {
                    

                    String cifrado = criptoAES.cifrar(MensagemTemporaria, chaveAESServidor);
                    
                    fim = cifrado;
                    System.out.println("****************");
                    System.out.println(cifrado);
                    System.out.println("****************");
                    //saida.println(cifrado);
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                saida.println(fim);
                
            }

            saida.close();
            teclado.close();
            cliente.close();
            System.out.println("Cliente finaliza conexao");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    
}