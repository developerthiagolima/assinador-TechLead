package br.com.techlead.assinador.comum.excecoes;

public class AssinadorException
extends Exception {
    protected AssinadorException() {
    }

    protected AssinadorException(String mensagem) {
        super(mensagem);
    }

    protected AssinadorException(String mensagem, Throwable throwable) {
        super(mensagem, throwable);
    }
}

