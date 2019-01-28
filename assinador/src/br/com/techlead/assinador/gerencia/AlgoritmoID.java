package br.com.techlead.assinador.gerencia;

public class AlgoritmoID {
    private String id;
    private String nome;

    AlgoritmoID(String _id, String _nome) {
        this.id = _id;
        this.nome = _nome;
    }

    public String getId() {
        return this.id;
    }

    public String getNome() {
        return this.nome;
    }

    public String toString() {
        return this.getNome();
    }
}

