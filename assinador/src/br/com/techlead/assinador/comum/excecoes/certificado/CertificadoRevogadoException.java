package br.com.techlead.assinador.comum.excecoes.certificado;

import java.security.cert.CertificateException;
import java.security.cert.X509CRLEntry;

public class CertificadoRevogadoException
extends CertificateException {
    private X509CRLEntry informacoes;

    public CertificadoRevogadoException() {
    }

    public CertificadoRevogadoException(String mensagem) {
        super(mensagem);
    }

    public CertificadoRevogadoException(String mensagem, X509CRLEntry _informacoes) {
        super(mensagem);
        this.informacoes = _informacoes;
    }

    public CertificadoRevogadoException(String mensagem, Throwable throwable) {
        super(mensagem, throwable);
    }

    public X509CRLEntry getInformacoes() {
        return this.informacoes;
    }
}

