package br.com.techlead.assinador.assinatura;

import java.security.PrivateKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import br.com.techlead.assinador.comum.excecoes.AssinaturaException;
import br.com.techlead.assinador.comum.excecoes.certificado.CertificadoPropositoException;

public final class AssinaturaFachada {
    private static AssinaturaFachada fachada;

    private AssinaturaFachada() {
    }

    public static AssinaturaFachada getInstancia() {
        if (fachada == null) {
            fachada = new AssinaturaFachada();
        }
        return fachada;
    }

    public Assinatura assinarConteudoDetached(PrivateKey privateKey, X509Certificate certificate, byte[] conteudo) throws CertificadoPropositoException, CertificateParsingException, AssinaturaException {
        return new Assinador(privateKey, certificate).assinarConteudoDetached(conteudo);
    }

    public Assinatura assinarConteudoAttached(PrivateKey privateKey, X509Certificate certificate, byte[] conteudo) throws CertificadoPropositoException, CertificateParsingException, AssinaturaException {
        return new Assinador(privateKey, certificate).assinarConteudoAttached(conteudo);
    }
}

