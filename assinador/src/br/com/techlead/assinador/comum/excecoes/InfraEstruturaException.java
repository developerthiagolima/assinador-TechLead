package br.com.techlead.assinador.comum.excecoes;

public class InfraEstruturaException
extends RuntimeException {
    public InfraEstruturaException() {
    }

    public InfraEstruturaException(String mensagem) {
        super(mensagem);
    }

    public InfraEstruturaException(String mensagem, Throwable throwable) {
        super(mensagem, throwable);
    }
}

