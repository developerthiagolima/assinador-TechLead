package br.com.techlead.assinador.validacao;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import br.com.techlead.assinador.comum.excecoes.certificado.CertificadoPropositoException;
import br.com.techlead.assinador.gerencia.Assinatura;

public final class ValidacaoFachada {
    private static ValidacaoFachada fachada;

    private ValidacaoFachada() {
    }

    public static ValidacaoFachada getInstancia() {
        if (fachada == null) {
            fachada = new ValidacaoFachada();
        }
        return fachada;
    }

    public void validarAssinaturaConteudo(Assinatura assinatura, PublicKey chave, byte[] conteudo, String idTipoConteudo) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        new ValidadorAssinatura(assinatura).validarConteudo(chave, conteudo, idTipoConteudo);
    }

    public void validarPropositoAssinatura(X509Certificate certificado) throws CertificadoPropositoException {
        ValidadorAssinatura.validarProposito(certificado);
    }
}

