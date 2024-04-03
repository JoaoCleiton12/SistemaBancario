package Criptografia;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class CriptoRSA {

    private BigInteger p;
    private BigInteger q;
    private BigInteger n;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;
    private int bitLength = 1024;
    private Random tam;

     public CriptoRSA(){
        tam = new Random();
        p = BigInteger.probablePrime(bitLength, tam);
        q = BigInteger.probablePrime(bitLength, tam);
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitLength / 2, tam);

        d = e.modInverse(phi);   
    }

    public BigInteger enviarN(){
        return n;
    }

    public BigInteger enviarE(){
        return e;
    }

    public BigInteger enviarD(){
        return d;
    }

    public String encriptar(String m, BigInteger eRecebido, BigInteger nRecebido){
        byte[] bytes = m.getBytes(StandardCharsets.UTF_8);
        BigInteger temp = new BigInteger(bytes);
        BigInteger tempCifrado = temp.modPow(eRecebido, nRecebido);
        return tempCifrado.toString();
    }

    public String desencriptar(String m, BigInteger dRecebido, BigInteger nRecebido){
        BigInteger tempCifrado = new BigInteger(m);
        BigInteger temp = tempCifrado.modPow(dRecebido, nRecebido);
        byte[] bytes = temp.toByteArray();
        return new String(bytes, StandardCharsets.UTF_8);
    }

}