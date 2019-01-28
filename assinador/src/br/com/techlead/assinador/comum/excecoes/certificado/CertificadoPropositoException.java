package br.com.techlead.assinador.comum.excecoes.certificado;

import java.security.cert.CertificateException;

public class CertificadoPropositoException
extends CertificateException {
    public CertificadoPropositoException() {
    }

    public CertificadoPropositoException(String mensagem) {
        super(mensagem);
    }

    public CertificadoPropositoException(String mensagem, Throwable throwable) {
        super(mensagem, throwable);
    }
}

