package Servidor;

public class ContaCorrente {
    
    private static int quantContas;
    private String numConta;
    private String senha;
    private String cpf;
    private String nome;
    private String endereco;
    private String telefone;
    private double saldo;

    public ContaCorrente(String nome, String cpf, String endereco, String telefone, String senha) {
    
        quantContas+=20;
        this.numConta =  String.valueOf(quantContas);
        this.senha = senha;
        this.cpf = cpf;
        this.nome = nome;
        this.endereco = endereco;
        this.telefone = telefone;
        this.saldo = 0.0;
    }

    public String getNumConta() {
        return numConta;
    }

    public boolean autenticar(String senha) {
        return this.senha.equals(senha);
    }

    public void saque(double valor){
        if ((saldo >= valor) && (valor >0)) {
            remove(valor);
        }else{
            
        }
    }

    public void deposito(double valor) {
        if (valor > 0) {
           add(valor);
            System.out.println(" Depósito realizado com sucesso.");
            System.out.println(" saldo Atual: " + saldo);
        } else {
            System.out.println(" Valor inválido.");
        }
    }

    public double saldo(){
        return this.saldo;
    }

    public void add(double valor){
        saldo+= valor;
    }

    public void remove(double valor){
        saldo -= valor;
    }
}
