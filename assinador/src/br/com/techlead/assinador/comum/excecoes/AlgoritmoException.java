package br.com.techlead.assinador.comum.excecoes;

public class AlgoritmoException
extends InfraEstruturaException {
    public AlgoritmoException() {
    }

    public AlgoritmoException(String mensagem) {
        super(mensagem);
    }

    public AlgoritmoException(String mensagem, Throwable throwable) {
        super(mensagem, throwable);
    }
}

