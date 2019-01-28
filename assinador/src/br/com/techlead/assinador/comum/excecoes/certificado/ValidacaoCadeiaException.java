package br.com.techlead.assinador.comum.excecoes.certificado;

import java.security.cert.CertificateException;

public class ValidacaoCadeiaException
extends CertificateException {
    public ValidacaoCadeiaException() {
    }

    public ValidacaoCadeiaException(String mensagem) {
        super(mensagem);
    }

    public ValidacaoCadeiaException(String mensagem, Throwable throwable) {
        super(mensagem, throwable);
    }
}

