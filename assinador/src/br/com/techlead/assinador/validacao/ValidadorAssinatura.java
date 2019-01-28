package br.com.techlead.assinador.validacao;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

import br.com.techlead.assinador.comum.excecoes.certificado.CertificadoPropositoException;
import br.com.techlead.assinador.comum.util.GeradorHashUtil;
import br.com.techlead.assinador.gerencia.Assinatura;

class ValidadorAssinatura {
    private Assinatura assinatura;

    protected ValidadorAssinatura(Assinatura _assinatura) {
        if (_assinatura == null) {
            throw new NullPointerException("Assinatura obrigatoria");
        }
        this.assinatura = _assinatura;
    }

    public void validarConteudo(PublicKey chave, byte[] conteudoAssinado, String idTipoConteudo) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        try {
            String algoritmo = this.configurarAlgoritmo();
            Signature signature = Signature.getInstance(algoritmo);
            signature.initVerify(chave);
            byte[] encodeAttAss = this.assinatura.getEncodeAtributosAssinados();
            if (encodeAttAss == null) {
                signature.update(conteudoAssinado);
            } else {
                String algHash = this.assinatura.getAlgoritmoHash().getNome();
                byte[] hash = GeradorHashUtil.gerarHash(conteudoAssinado, algHash);
                this.validarAtributosAssinatura(hash, idTipoConteudo);
                signature.update(encodeAttAss);
            }
            if (!signature.verify(this.assinatura.getAssinatura())) {
                throw new SignatureException("Assinatura invalida");
            }
        }
        catch (InvalidKeyException e) {
            throw new InvalidKeyException("Chave invalida");
        }
    }
    
    public static void validarProposito(X509Certificate cert) throws CertificadoPropositoException {
        boolean[] keys = cert.getKeyUsage();
        int a = 0;
        int b = 1;
        if (keys == null || !keys[a] || !keys[b]) {
            throw new CertificadoPropositoException("Proposito Invalido");
        }
    }

    private String configurarAlgoritmo() {
        String com = "with";
        String nomeAlgCripto = this.assinatura.getAlgoritmoCripto().getNome();
        if (nomeAlgCripto.indexOf("with") < 0) {
            StringBuilder algoritmo = new StringBuilder().append(this.assinatura.getAlgoritmoHash().getNome()).append("with").append(nomeAlgCripto);
            return algoritmo.toString();
        }
        return nomeAlgCripto;
    }

    private void validarAtributosAssinatura(byte[] hash, String idTipoConteudo) throws SignatureException, NoSuchAlgorithmException {
        Hashtable attributeTable = this.assinatura.getAtributosAssinados();
        byte[] signedHash = (byte[])attributeTable.get("1.2.840.113549.1.9.4");
        if (signedHash == null) {
            throw new SignatureException("Hash não encontrado");
        }
        if (!MessageDigest.isEqual(hash, signedHash)) {
            throw new SignatureException("Hash encontrado é diferente");
        }
        String typeOID = (String)attributeTable.get("1.2.840.113549.1.9.3");
        if (typeOID == null) {
            throw new SignatureException("Tipo OID não encontrado");
        }
        if (!typeOID.equals(idTipoConteudo)) {
            throw new SignatureException("Tipo OID é diferente");
        }
    }
}

