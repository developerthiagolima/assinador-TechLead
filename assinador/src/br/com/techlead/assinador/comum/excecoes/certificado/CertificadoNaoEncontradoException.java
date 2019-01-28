package br.com.techlead.assinador.comum.excecoes.certificado;

import java.security.cert.CertificateException;

public class CertificadoNaoEncontradoException
extends CertificateException {
    public CertificadoNaoEncontradoException() {
    }

    public CertificadoNaoEncontradoException(String mensagem) {
        super(mensagem);
    }

    public CertificadoNaoEncontradoException(String mensagem, Throwable throwable) {
        super(mensagem, throwable);
    }
}

