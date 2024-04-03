import Criptografia.ImplSHA3;

public class testes {
    public static void main(String[] args) {
    //String algoritmo = "SHA-256";
    String algoritmo = "SHA-256";
    String texto = "Funções dfasdasdfe hash";
    System.out.println("Entrada (string): " + texto);
    System.out.println("Entrada (tamanho): " + texto.length());

    byte[] bytesTextoSHA = ImplSHA3.resumo(texto.getBytes(ImplSHA3.UTF_8), algoritmo);


    System.out.println("Hexa: " + ImplSHA3.bytes2Hex(bytesTextoSHA));
    System.out.println("Tamanho: " + bytesTextoSHA.length);
    }
}
