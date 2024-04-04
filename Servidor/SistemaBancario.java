package Servidor;

import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.text.DecimalFormat;

public class SistemaBancario {
    
    private Map<String, ContaCorrente> listaContas;
    private double taxaPoupança;
    private double taxaRendaFixa;

    public SistemaBancario() {
        
        taxaPoupança = 0.5;
        taxaRendaFixa = 1.5;

        this.listaContas = new HashMap<>();

        listaContas.put("1234", new ContaCorrente("Fernando da Silva", "12233344456", "Rua do tedio", "78675654", "EuAmo"));
        listaContas.put("0987", new ContaCorrente("Ricardo Souza", "11100099987", "Rua da paixao", "00909909", "Seguranca"));
        listaContas.put("312", new ContaCorrente("Maria Eduarda", "33377787878", "Rua sem nome", "11123434", "Computacional"));
    }
    
    //Autenticar usuários (User Story 1)
    public boolean autenticarUser(String numConta, String senha){

        if (listaContas.containsKey(numConta)) {
            return listaContas.get(numConta).autenticar(senha);
        }
        else{
            return false;
        }
        
    }

    //Criar conta corrente (User Story 2)
    public String criarContaCorrente(String nome, String cpf, String endereco, String telefone, String senha){
        ContaCorrente contaNova = new ContaCorrente(nome, cpf, endereco, telefone, senha);
        String numeroConta = contaNova.getNumConta();
        listaContas.put(numeroConta, contaNova);
       
        String retorno = " O numero da sua conta é: "+numeroConta;

        return retorno;
    }

    //Saque (User Story 3)
    public void saque(String numConta, double valor){
       if (listaContas.containsKey(numConta)) {
        listaContas.get(numConta).saque(valor);
       }
    } 

    //Depósito (User Story 4)
    public void deposito(String numConta, double valor){
        if (listaContas.containsKey(numConta)) {
            listaContas.get(numConta).deposito(valor);
        }
    }

    //Transferência (User Story 5)
    public String transferência(String numContaOrigem, String numContaDestino, double valor){
        String retorno;
        if (listaContas.containsKey(numContaOrigem) && listaContas.containsKey(numContaDestino)) {
           listaContas.get(numContaOrigem).remove(valor);
           listaContas.get(numContaDestino).add(valor);
           retorno = " ##Transferencia realizada##";
        }else{
            retorno = " ###Conta destino inválida###";
        }
        return retorno;
    }

    //Saldo (User Story 6)
    public double saldo(String numConta){
        if (listaContas.containsKey(numConta)) {
           return listaContas.get(numConta).saldo();
        }else{
            return 0.0;
        }
    }

    //Investimentos (User Story 7)
    public String investimentos(String numeroConta, int tipoInvestimento){
        //poupança = 1
        //renda fixa = 2

        String retorno = "";
        DecimalFormat formato = new DecimalFormat("#.##");

        if (tipoInvestimento == 1) {
            double tresmeses = listaContas.get(numeroConta).saldo(); 
            double seismeses = listaContas.get(numeroConta).saldo();
            double dozemeses = listaContas.get(numeroConta).saldo(); 
            //Calcular rendimento para tres meses
            for(int q = 0; q<3;q++){
                double temp = tresmeses * taxaPoupança;
                tresmeses += temp;
            }
            //Calcular rendimento para seis meses
            for(int q = 0; q<6;q++){
                double temp = seismeses * taxaPoupança;
                seismeses += temp;
            }
            //Calcular rendimento para doze meses
            for(int q = 0; q<12;q++){
                double temp = dozemeses * taxaPoupança;
                dozemeses += temp;
            }

            String numeroFormatado = formato.format(tresmeses);
            String numeroFormatado2 = formato.format(seismeses);
            String numeroFormatado3 = formato.format(dozemeses);

            

            retorno = "|Valor aplicado: "+listaContas.get(numeroConta).saldo()+"\n|Rendimento em 3 meses: "+ numeroFormatado+"\n|Rendimento em 6 meses: "+ numeroFormatado2+"\n|Rendimento em 12 meses: "+ numeroFormatado3+"\n";
        }
        else if (tipoInvestimento == 2) {
            double tresmesesRenda = listaContas.get(numeroConta).saldo(); 
            double seismesesRenda = listaContas.get(numeroConta).saldo();
            double dozemesesRenda = listaContas.get(numeroConta).saldo(); 
            //Calcular rendimento para tres meses
            for(int q = 0; q<3;q++){
                double temp = tresmesesRenda * taxaRendaFixa;
                tresmesesRenda += temp;
            }
            //Calcular rendimento para seis meses
            for(int q = 0; q<6;q++){
                double temp = seismesesRenda * taxaRendaFixa;
                seismesesRenda += temp;
            }
            //Calcular rendimento para doze meses
            for(int q = 0; q<12;q++){
                double temp = dozemesesRenda * taxaRendaFixa;
                dozemesesRenda += temp;
            }

            String numeroFormatado = formato.format(tresmesesRenda);
            String numeroFormatado2 = formato.format(seismesesRenda);
            String numeroFormatado3 = formato.format(dozemesesRenda);

            

            retorno = "|Valor aplicado: "+listaContas.get(numeroConta).saldo()+"\n|Rendimento em 3 meses: "+ numeroFormatado+"\n|Rendimento em 6 meses: "+ numeroFormatado2+"\n|Rendimento em 12 meses: "+ numeroFormatado3+"\n";
        }
        return retorno;
    }

    //Autenticação de mensagens (User Story 8)
    public boolean autenticarMensagens(String conta, String senha){
        return autenticarUser(conta, senha);
    }
    
    
}
