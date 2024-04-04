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
import Criptografia.ImplSHA3;

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
    private CriptoRSA criptoRSA = new CriptoRSA();
    private String ChavePublicaCliente;


    private String algoritmoHash;

    private CriptografiaAES criptoAES;
    private SecretKey chaveAES;

    private BigInteger eChaveServidor;
    private BigInteger nChaveServidor;
    private BigInteger dChaveServidor;

    private SistemaBancario sistema;
    

    public Servidor(Socket cliente){
        socketCliente = cliente;
    }

    @Override
    public void run() {
        
        System.out.println("Conexao "+Servidor.cont+" com o cliente "+socketCliente.getInetAddress().getHostAddress() + "/"
        + socketCliente.getInetAddress().getHostName() );
        
        try {
            
            //sistema bancário
            sistema = new SistemaBancario();

            BigInteger eCliente = new BigInteger("123123");
            BigInteger nCliente = new BigInteger("123213");

            //variável que recebe a mensagem enviada pelo cliente, cifrada em AES
            String MensagemAES;
            //variável que receebe a mensagem enviada pelo cliente, o hash da mensagem AES cifrado com RSA
            String MensagemRSAComHash;
            //variável que armazena a mensagem aes enviada pelo servidor, decifrada.
            String decifraAESdaMensagem;

            //texto cifrado em AES
            String cifrado = "";

            //armazena o hash cifrado com RSA
            String hashCifradaComRSA;

            //armazena numero inteiro no formato texto
            String inteiroParaTexto;

            String doubleParaTexto;

            //variavel de confirmação
            //caso seja -1, entao 
            int confimacao = -1;

            //armazena número da conta do cliente
            String conta = "";

            //armazena senha da conta do cliente
            String senha = "";

            //array que armazena numero da conta e senha concatenados
            String[] contaESenha;

            //armazena o valor inteiro que foi convertido de um texto
            //vai comçar como -1, pois se for não for nenhum valor conhecido, irei retornar erro
            int entrada = -1;

            //armazena valor inteiro que foi convertido de um texto
            int escolha = -1;

            //armazena valor que sera usado nas operações
            double valor = 0;

            String decifraRSAdaMensagem;

            //Armazena os bytes do hash do texto cifrado do algoritmo AES
            byte[] hashDoTextoCifradoAES;
            //resultado no formado string do hash do texto cifrado AES
            String resultadoDoHash;

            //algoritmo hash usado
            algoritmoHash = "SHA-256";

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
                eChaveServidor = criptoRSA.enviarE();
                nChaveServidor = criptoRSA.enviarN();
                dChaveServidor = criptoRSA.enviarD();

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

                byte[] chaveemBytes = chaveAES.getEncoded();

                String chaveEmString = Base64.getEncoder().encodeToString(chaveemBytes);

                String ChaveCifrada = criptoRSA.encriptar(chaveEmString, eCliente, nCliente);

                saida.println(ChaveCifrada);
                

                conexaoEnvioChaveAES = false;
                
            }

            while (conexaoTrocaDeMensagens) {
                
                //Recebe a entrada (Qual operação ira fazer)
                
                    
                
                        //*******************************************************************************************************
                            //Código para receber mensagens do cliente
                        
                                //recebe mensagem AES
                                MensagemAES = s.nextLine();

                                //recebe mensagem hash do aes cifrada com RSA
                                MensagemRSAComHash = s.nextLine();

                    
                                
                                    //Decifra RSA
                                    //hash da mensagem
                                    decifraRSAdaMensagem = criptoRSA.desencriptar(MensagemRSAComHash, criptoRSA.enviarD(), nChaveServidor);
                                
                                    //faz o hash da mensagem recebida AES
                                    hashDoTextoCifradoAES = ImplSHA3.resumo(MensagemAES.getBytes(ImplSHA3.UTF_8), algoritmoHash);

                                    //armazena o resultado do hash no formato String
                                    resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                    //verifica se os hash são iguais
                                    if (resultadoDoHash.equals(decifraRSAdaMensagem)) {
                                        //como os hash bateram, entao agora eu posso decifrar a mensagem AES e usa-la
                                        
                                            //Decifra AES
                                                try {
                                                    decifraAESdaMensagem = criptoAES.decifrar(MensagemAES, chaveAES);
                                                    entrada = Integer.parseInt(decifraAESdaMensagem); 
                                                } catch (Exception e) {
                                                    
                                                    e.printStackTrace();
                                                }
                                        
                                    }

                        //******************************************************************************************************

                        //Faz login
                            if (entrada == 1) {
                                    //*******************************************************************************************************
                                        //Código para receber mensagens do cliente
                                        
                                            //recebe mensagem AES
                                            MensagemAES = s.nextLine();

                                            //recebe mensagem hash do aes cifrada com RSA
                                            MensagemRSAComHash = s.nextLine();

                                                //Decifra RSA
                                                    //hash da mensagem
                                                    decifraRSAdaMensagem = criptoRSA.desencriptar(MensagemRSAComHash, criptoRSA.enviarD(), nChaveServidor);
                                            
                                                //faz o hash da mensagem recebida AES
                                                hashDoTextoCifradoAES = ImplSHA3.resumo(MensagemAES.getBytes(ImplSHA3.UTF_8), algoritmoHash);

                                                //armazena o resultado do hash no formato String
                                                resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                //verifica se os hash são iguais
                                                if (resultadoDoHash.equals(decifraRSAdaMensagem)) {
                                                    //como os hash bateram, entao agora eu posso decifrar a mensagem AES e usa-la
                                                    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                                                        //Decifra AES
                                                            try {
                                                                decifraAESdaMensagem = criptoAES.decifrar(MensagemAES, chaveAES);
                                                                //separa a senha do numero da conta
                                                                contaESenha = decifraAESdaMensagem.split(" ");

                                                                conta = contaESenha[0];
                                                                senha = contaESenha[1];

                                                        

                                                            } catch (Exception e) {
                                                                
                                                                e.printStackTrace();
                                                            }
                                                    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                                                }

                                    //*******************************************************************************************************
                                    

                                    //caso o login seja bem sucedido
                                    if (sistema.autenticarMensagens(conta, senha)) {
                                    
                                    //altera o valor, para informar ao cliente que foi possivel autenticar
                                    confimacao = 0;

                                    //enviar pro cliente um número para confimar que o login foi bem sucedido.
                                        
                                        //-------------------------------------------------------------------------------------------------
                                            //Envia para cliente mensagem cifrada em AES
                                            inteiroParaTexto = confimacao+"";

                                            try {
                                                cifrado = criptoAES.cifrar(inteiroParaTexto, chaveAES);
                                            } catch (Exception e) {
                                                // TODO Auto-generated catch block
                                                e.printStackTrace();
                                            }

                                            saida.println(cifrado);
            
                                        
                                            //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                //faz o hash do texto cifrado em AES
                                                hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                //cifra o hash com RSA
                                                hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                saida.println(hashCifradaComRSA);
                                        //-------------------------------------------------------------------------------------------------

                                        escolha = -1;

                                        
                                        //vai ficar nesse laço vendo oque o usuário quer fazer
                                        while (escolha != 6) {
                                            
                                           
                                            //Recebe do cliente qual operação ele vai fazer
                                                //*******************************************************************************************************
                                                    //Código para receber mensagens do servidor
                                                
                                                        //recebe mensagem AES
                                                        MensagemAES = s.nextLine();

                                                        //recebe mensagem hash do aes cifrada com RSA
                                                        MensagemRSAComHash = s.nextLine();

                                            
                                                        
                                                            //Decifra RSA
                                                            //hash da mensagem
                                                            decifraRSAdaMensagem = criptoRSA.desencriptar(MensagemRSAComHash, criptoRSA.enviarD(), nChaveServidor);
                                                        
                                                            //faz o hash da mensagem recebida AES
                                                            hashDoTextoCifradoAES = ImplSHA3.resumo(MensagemAES.getBytes(ImplSHA3.UTF_8), algoritmoHash);

                                                            //armazena o resultado do hash no formato String
                                                            resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                            //verifica se os hash são iguais
                                                            if (resultadoDoHash.equals(decifraRSAdaMensagem)) {
                                                                //como os hash bateram, entao agora eu posso decifrar a mensagem AES e usa-la
                                                                
                                                                    //Decifra AES
                                                                        try {
                                                                            decifraAESdaMensagem = criptoAES.decifrar(MensagemAES, chaveAES);
                                                                            escolha = Integer.parseInt(decifraAESdaMensagem); 
                                                                        } catch (Exception e) {
                                                                            
                                                                            e.printStackTrace();
                                                                        }
                                                                
                                                            }

                                                //******************************************************************************************************


                                                //saque
                                            if (escolha == 1) {
                                            
                                            
                                                //*******************************************************************************************************
                                                    //Código para receber mensagens do servidor
                                                
                                                        //recebe mensagem AES
                                                        MensagemAES = s.nextLine();

                                                        //recebe mensagem hash do aes cifrada com RSA
                                                        MensagemRSAComHash = s.nextLine();

                                                            //Decifra RSA
                                                            //hash da mensagem
                                                            decifraRSAdaMensagem = criptoRSA.desencriptar(MensagemRSAComHash, criptoRSA.enviarD(), nChaveServidor);
                                                        
                                                            //faz o hash da mensagem recebida AES
                                                            hashDoTextoCifradoAES = ImplSHA3.resumo(MensagemAES.getBytes(ImplSHA3.UTF_8), algoritmoHash);

                                                            //armazena o resultado do hash no formato String
                                                            resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                            //verifica se os hash são iguais
                                                            if (resultadoDoHash.equals(decifraRSAdaMensagem)) {
                                                                //como os hash bateram, entao agora eu posso decifrar a mensagem AES e usa-la
                                                                
                                                                    //Decifra AES
                                                                        try {
                                                                            decifraAESdaMensagem = criptoAES.decifrar(MensagemAES, chaveAES);
                                                                            valor = Double.parseDouble(decifraAESdaMensagem); 
                                                                        } catch (Exception e) {
                                                                            
                                                                            e.printStackTrace();
                                                                        }
                                                                
                                                            }

                                                //******************************************************************************************************

                                            //verifica se o valor é menor que o saldo atual
                                            if (valor <= sistema.saldo(conta)) {
                                                sistema.saque(conta, valor);

                                                //retornar saldo atual para servidor
                                                //-------------------------------------------------------------------------------------------------
                                                    //Envia para cliente mensagem cifrada em AES
                                                    doubleParaTexto = " Saque realizado com sucesso.\n Saldo atual após saque: "+sistema.saldo(conta);

                                                    try {
                                                        cifrado = criptoAES.cifrar(doubleParaTexto, chaveAES);
                                                    } catch (Exception e) {
                                                        // TODO Auto-generated catch block
                                                        e.printStackTrace();
                                                    }

                                                    saida.println(cifrado);
                    
                                                
                                                    //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                        //faz o hash do texto cifrado em AES
                                                        hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                        resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                        //cifra o hash com RSA
                                                        hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                        saida.println(hashCifradaComRSA);
                                                //-------------------------------------------------------------------------------------------------
                                            
                                                }else if (valor > sistema.saldo(conta)) {
                                                    //-------------------------------------------------------------------------------------------------
                                                        //Envia para cliente mensagem cifrada em AES
                                                        doubleParaTexto = " Saldo insuficiente.\n Saldo atual: "+sistema.saldo(conta);

                                                        try {
                                                            cifrado = criptoAES.cifrar(doubleParaTexto, chaveAES);
                                                        } catch (Exception e) {
                                                            // TODO Auto-generated catch block
                                                            e.printStackTrace();
                                                        }

                                                        saida.println(cifrado);
                        
                                                    
                                                        //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                            //faz o hash do texto cifrado em AES
                                                            hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                            resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                            //cifra o hash com RSA
                                                            hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                            saida.println(hashCifradaComRSA);
                                                    //-------------------------------------------------------------------------------------------------
                                                }
                                            }

                                            //depósito
                                            if (escolha == 2) {
                                            //*******************************************************************************************************
                                                //Código para receber mensagens do servidor
                                            
                                                    //recebe mensagem AES
                                                    MensagemAES = s.nextLine();

                                                    //recebe mensagem hash do aes cifrada com RSA
                                                    MensagemRSAComHash = s.nextLine();

                                                        //Decifra RSA
                                                        //hash da mensagem
                                                        decifraRSAdaMensagem = criptoRSA.desencriptar(MensagemRSAComHash, criptoRSA.enviarD(), nChaveServidor);
                                                    
                                                        //faz o hash da mensagem recebida AES
                                                        hashDoTextoCifradoAES = ImplSHA3.resumo(MensagemAES.getBytes(ImplSHA3.UTF_8), algoritmoHash);

                                                        //armazena o resultado do hash no formato String
                                                        resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                        //verifica se os hash são iguais
                                                        if (resultadoDoHash.equals(decifraRSAdaMensagem)) {
                                                            //como os hash bateram, entao agora eu posso decifrar a mensagem AES e usa-la
                                                            
                                                                //Decifra AES
                                                                    try {
                                                                        decifraAESdaMensagem = criptoAES.decifrar(MensagemAES, chaveAES);
                                                                        valor = Double.parseDouble(decifraAESdaMensagem); 
                                                                    } catch (Exception e) {
                                                                        
                                                                        e.printStackTrace();
                                                                    }
                                                            
                                                        }

                                            //******************************************************************************************************

                                            if (valor > 0) {
                                                //realiza depósito
                                                sistema.deposito(conta, valor);

                                                
                                                //retornar saldo atual para servidor
                                                //-------------------------------------------------------------------------------------------------
                                                    //Envia para cliente mensagem cifrada em AES
                                                    doubleParaTexto = sistema.saldo(conta)+"";

                                                    try {
                                                        cifrado = criptoAES.cifrar(doubleParaTexto, chaveAES);
                                                    } catch (Exception e) {
                                                        // TODO Auto-generated catch block
                                                        e.printStackTrace();
                                                    }

                                                    saida.println(cifrado);
                    
                                                
                                                    //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                        //faz o hash do texto cifrado em AES
                                                        hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                        resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                        //cifra o hash com RSA
                                                        hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                        saida.println(hashCifradaComRSA);
                                                //-------------------------------------------------------------------------------------------------
                                            }
                                            
                                            else if (valor <= 0) {
                                                //-------------------------------------------------------------------------------------------------
                                                    //Envia para cliente mensagem cifrada em AES
                                                    doubleParaTexto = sistema.saldo(conta)+"";

                                                    try {
                                                        cifrado = criptoAES.cifrar(doubleParaTexto, chaveAES);
                                                    } catch (Exception e) {
                                                        // TODO Auto-generated catch block
                                                        e.printStackTrace();
                                                    }

                                                    saida.println(cifrado);
                    
                                                
                                                    //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                        //faz o hash do texto cifrado em AES
                                                        hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                        resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                        //cifra o hash com RSA
                                                        hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                        saida.println(hashCifradaComRSA);
                                                //-------------------------------------------------------------------------------------------------
                                            
                                            }
                                            }

                                            //transferencia
                                            if (escolha == 3) {
                                                    //*******************************************************************************************************
                                                        //Código para receber mensagens do servidor
                                                            String numContaDestino = "";
                                                            String[] contaEValor;
                                                            //recebe mensagem AES
                                                            MensagemAES = s.nextLine();

                                                            //recebe mensagem hash do aes cifrada com RSA
                                                            MensagemRSAComHash = s.nextLine();

                                                                //Decifra RSA
                                                                //hash da mensagem
                                                                decifraRSAdaMensagem = criptoRSA.desencriptar(MensagemRSAComHash, criptoRSA.enviarD(), nChaveServidor);
                                                            
                                                                //faz o hash da mensagem recebida AES
                                                                hashDoTextoCifradoAES = ImplSHA3.resumo(MensagemAES.getBytes(ImplSHA3.UTF_8), algoritmoHash);

                                                                //armazena o resultado do hash no formato String
                                                                resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                                //verifica se os hash são iguais
                                                                if (resultadoDoHash.equals(decifraRSAdaMensagem)) {
                                                                    //como os hash bateram, entao agora eu posso decifrar a mensagem AES e usa-la
                                                                    
                                                                        //Decifra AES
                                                                            try {
                                                                                decifraAESdaMensagem = criptoAES.decifrar(MensagemAES, chaveAES);

                                                                                contaEValor = decifraAESdaMensagem.split(" ");

                                                                                numContaDestino = contaEValor[0];
                                                                                valor = Double.parseDouble(contaEValor[1]);
                                                                            } catch (Exception e) {
                                                                                
                                                                                e.printStackTrace();
                                                                            }
                                                                    
                                                                }

                                                    //******************************************************************************************************
                                        
                                                //se o valor da transferencia for menor ou igual ao saldo da conta de origem
                                                if (sistema.saldo(conta) >= valor) {
                                                    //-------------------------------------------------------------------------------------------------
                                                        //Envia para cliente mensagem cifrada em AES
                                                        doubleParaTexto = sistema.transferência(conta, numContaDestino, valor);

                                                        try {
                                                            cifrado = criptoAES.cifrar(doubleParaTexto, chaveAES);
                                                        } catch (Exception e) {
                                                            // TODO Auto-generated catch block
                                                            e.printStackTrace();
                                                        }

                                                        saida.println(cifrado);
                        
                                                    
                                                        //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                            //faz o hash do texto cifrado em AES
                                                            hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                            resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                            //cifra o hash com RSA
                                                            hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                            saida.println(hashCifradaComRSA);
                                                    //-------------------------------------------------------------------------------------------------
                                                }
                                                else{
                                                    //-------------------------------------------------------------------------------------------------
                                                        //Envia para cliente mensagem cifrada em AES
                                                        doubleParaTexto = " ##Saldo insuficiente##";

                                                        try {
                                                            cifrado = criptoAES.cifrar(doubleParaTexto, chaveAES);
                                                        } catch (Exception e) {
                                                            // TODO Auto-generated catch block
                                                            e.printStackTrace();
                                                        }

                                                        saida.println(cifrado);
                        
                                                    
                                                        //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                            //faz o hash do texto cifrado em AES
                                                            hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                            resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                            //cifra o hash com RSA
                                                            hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                            saida.println(hashCifradaComRSA);
                                                    //-------------------------------------------------------------------------------------------------
                                                    }   
                                            }

                                            //saldo
                                            if (escolha == 4) {

                                                
                                                    //-------------------------------------------------------------------------------------------------
                                                        //Envia para cliente mensagem cifrada em AES
                                                        doubleParaTexto = sistema.saldo(conta)+"";

                                                        try {
                                                            cifrado = criptoAES.cifrar(doubleParaTexto, chaveAES);
                                                        } catch (Exception e) {
                                                            // TODO Auto-generated catch block
                                                            e.printStackTrace();
                                                        }

                                                        saida.println(cifrado);
                        
                                                    
                                                        //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                            //faz o hash do texto cifrado em AES
                                                            hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                            resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                            //cifra o hash com RSA
                                                            hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                            saida.println(hashCifradaComRSA);
                                                    //-------------------------------------------------------------------------------------------------
                                            }

                                            //investimentos
                                            if (escolha == 5) {
                                                //*******************************************************************************************************
                                                        
                                                        int escolhaInvestimento = 0;
                                                        //recebe mensagem AES
                                                        MensagemAES = s.nextLine();

                                                        //recebe mensagem hash do aes cifrada com RSA
                                                        MensagemRSAComHash = s.nextLine();

                                                            //Decifra RSA
                                                            //hash da mensagem
                                                            decifraRSAdaMensagem = criptoRSA.desencriptar(MensagemRSAComHash, criptoRSA.enviarD(), nChaveServidor);
                                                        
                                                            //faz o hash da mensagem recebida AES
                                                            hashDoTextoCifradoAES = ImplSHA3.resumo(MensagemAES.getBytes(ImplSHA3.UTF_8), algoritmoHash);

                                                            //armazena o resultado do hash no formato String
                                                            resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                            //verifica se os hash são iguais
                                                            if (resultadoDoHash.equals(decifraRSAdaMensagem)) {
                                                                //como os hash bateram, entao agora eu posso decifrar a mensagem AES e usa-la
                                                                
                                                                    //Decifra AES
                                                                        try {
                                                                            decifraAESdaMensagem = criptoAES.decifrar(MensagemAES, chaveAES);

                                                                            escolhaInvestimento = Integer.parseInt(decifraAESdaMensagem);
                                                                            
                                                                        } catch (Exception e) {
                                                                            
                                                                            e.printStackTrace();
                                                                        }
                                                                
                                                            }

                                                //******************************************************************************************************

                                                
                                                //-------------------------------------------------------------------------------------------------
                                                        //Envia para cliente mensagem cifrada em AES
                                                        doubleParaTexto = sistema.investimentos(conta, escolhaInvestimento);

                                                        try {
                                                            cifrado = criptoAES.cifrar(doubleParaTexto, chaveAES);
                                                        } catch (Exception e) {
                                                            // TODO Auto-generated catch block
                                                            e.printStackTrace();
                                                        }

                                                        saida.println(cifrado);
                        
                                                    
                                                        //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                            //faz o hash do texto cifrado em AES
                                                            hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                            resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                            //cifra o hash com RSA
                                                            hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                            saida.println(hashCifradaComRSA);
                                                    //-------------------------------------------------------------------------------------------------

                                            }

                                            //sair
                                            if (escolha == 6) {
                                                
                                            }

                                        }

                                        
                                    }

                                    //caso o login falhe
                                    else{

                                        
                                        //enviar pro cliente um número para confimar que o login foi bem sucedido.
                                        confimacao = 1;
                                        //-------------------------------------------------------------------------------------------------
                                            //Envia para cliente mensagem cifrada em AES
                                            inteiroParaTexto = confimacao+"";

                                            try {
                                                cifrado = criptoAES.cifrar(inteiroParaTexto, chaveAES);
                                            } catch (Exception e) {
                                                // TODO Auto-generated catch block
                                                e.printStackTrace();
                                            }

                                            saida.println(cifrado);
            
                                        
                                            //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                //faz o hash do texto cifrado em AES
                                                hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                //cifra o hash com RSA
                                                hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                saida.println(hashCifradaComRSA);
                                        //-------------------------------------------------------------------------------------------------


                                    }

                                    
                                    
                            }

                            //cria conta
                            if (entrada == 2) {

                                    //*******************************************************************************************************
                                        //Código para receber mensagens do cliente
                                    
                                            String[] nomeCpfEnderecoTelefoneSenhaCriada;
                                            String nome = "";
                                            String cpf = "";
                                            String endereco = "";
                                            String telefone = "";
                                            String senhaCriada = "";

                                            //recebe mensagem AES
                                            MensagemAES = s.nextLine();

                                            //recebe mensagem hash do aes cifrada com RSA
                                            MensagemRSAComHash = s.nextLine();
                                                //Decifra RSA
                                                //hash da mensagem
                                                decifraRSAdaMensagem = criptoRSA.desencriptar(MensagemRSAComHash, criptoRSA.enviarD(), nChaveServidor);
                                            
                                                //faz o hash da mensagem recebida AES
                                                hashDoTextoCifradoAES = ImplSHA3.resumo(MensagemAES.getBytes(ImplSHA3.UTF_8), algoritmoHash);

                                                //armazena o resultado do hash no formato String
                                                resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                //verifica se os hash são iguais
                                                if (resultadoDoHash.equals(decifraRSAdaMensagem)) {
                                                    //como os hash bateram, entao agora eu posso decifrar a mensagem AES e usa-la
                                                    
                                                        //Decifra AES
                                                            try {
                                                                decifraAESdaMensagem = criptoAES.decifrar(MensagemAES, chaveAES);

                                                                nomeCpfEnderecoTelefoneSenhaCriada = decifraAESdaMensagem.split(";");
                                                                nome = nomeCpfEnderecoTelefoneSenhaCriada[0];
                                                                cpf = nomeCpfEnderecoTelefoneSenhaCriada[1];
                                                                endereco = nomeCpfEnderecoTelefoneSenhaCriada[2];
                                                                telefone = nomeCpfEnderecoTelefoneSenhaCriada[3];
                                                                senhaCriada = nomeCpfEnderecoTelefoneSenhaCriada[4];
                                                                
                                                            } catch (Exception e) {
                                                                
                                                                e.printStackTrace();
                                                            }
                                                    
                                                }

                                    //******************************************************************************************************

                                    
                                   

                                    //-------------------------------------------------------------------------------------------------
                                            //Envia para cliente mensagem cifrada em AES
                                            inteiroParaTexto =  sistema.criarContaCorrente(nome, cpf, endereco, telefone, senhaCriada);

                                            try {
                                                cifrado = criptoAES.cifrar(inteiroParaTexto, chaveAES);
                                            } catch (Exception e) {
                                                // TODO Auto-generated catch block
                                                e.printStackTrace();
                                            }

                                            saida.println(cifrado);
            
                                        
                                            //Envia para cliente o hash cifrado em RSA, da mensagem cifrada em AES

                                                //faz o hash do texto cifrado em AES
                                                hashDoTextoCifradoAES = ImplSHA3.resumo(cifrado.getBytes(ImplSHA3.UTF_8), algoritmoHash);
                                                resultadoDoHash = ImplSHA3.bytes2Hex(hashDoTextoCifradoAES);

                                                //cifra o hash com RSA
                                                hashCifradaComRSA = criptoRSA.encriptar(resultadoDoHash, eCliente, nCliente);
                                                saida.println(hashCifradaComRSA);
                                        //-------------------------------------------------------------------------------------------------


                            }

                            //finaliza sessão
                            if (entrada == 3) {
                                    conexaoTrocaDeMensagens = false;
                            }
                

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