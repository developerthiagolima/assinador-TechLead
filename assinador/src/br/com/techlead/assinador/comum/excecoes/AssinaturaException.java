package br.com.techlead.assinador.comum.excecoes;

public class AssinaturaException
extends Exception {
    public AssinaturaException() {
    }

    public AssinaturaException(String mensagem) {
        super(mensagem);
    }

    public AssinaturaException(String mensagem, Throwable throwable) {
        super(mensagem, throwable);
    }
}

