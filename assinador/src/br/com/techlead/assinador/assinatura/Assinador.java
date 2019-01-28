package br.com.techlead.assinador.assinatura;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;

import br.com.techlead.assinador.comum.excecoes.AssinaturaException;
import br.com.techlead.assinador.comum.excecoes.InfraEstruturaException;
import br.com.techlead.assinador.comum.excecoes.certificado.CertificadoPropositoException;
import br.com.techlead.assinador.comum.util.ConversorUtil;
import br.com.techlead.assinador.validacao.ValidacaoFachada;

class Assinador {
    private static final AlgorithmIdentifier ALGORITMO_PADRAO_HASH = new AlgorithmIdentifier(CMSSignedGenerator.DIGEST_SHA1);
    private PrivateKey chavePrivada;
    private X509Certificate certificado;
    private CertStore certStore;

    public Assinador(PrivateKey privateKey, X509Certificate certificate) throws CertificadoPropositoException, CertificateParsingException {
        this.certificado = certificate;
        this.chavePrivada = privateKey;
        ValidacaoFachada.getInstancia().validarPropositoAssinatura(this.certificado);
        this.inicializar();
    }

    private void inicializar() {
        ArrayList<X509Certificate> certificados = new ArrayList<X509Certificate>();
        certificados.add(this.certificado);
        try {
            CollectionCertStoreParameters cert = new CollectionCertStoreParameters(certificados);
            this.certStore = CertStore.getInstance("Collection", cert);
        }
        catch (NoSuchAlgorithmException ex) {
        	ex.printStackTrace();
        }
        catch (InvalidAlgorithmParameterException ex) {
        	ex.printStackTrace();
        }
    }

    private Assinatura assinarConteudo(byte[] arquivo, String algoritmo, boolean attach) throws NoSuchAlgorithmException, AssinaturaException {
        try {
            CMSProcessableByteArray dado = new CMSProcessableByteArray(arquivo);
            CMSSignedDataGenerator gerador = new CMSSignedDataGenerator();
            gerador.addCertificatesAndCRLs(this.certStore);
            gerador.addSigner(this.chavePrivada, this.certificado, algoritmo);
            CMSSignedData envelope = gerador.generate((CMSProcessable)dado, attach, null);
            SignerInformation info = this.getSignerInformation(envelope);
            ValidacaoFachada.getInstancia().validarAssinaturaConteudo(new br.com.techlead.assinador.gerencia.Assinatura(info), this.certificado.getPublicKey(), arquivo, envelope.getSignedContentTypeOID());
            return new Assinatura(info.getSignature(), envelope.getEncoded());
        }
        catch (NoSuchAlgorithmException ex) {
            throw new NoSuchAlgorithmException(ex.getMessage());
        }
        catch (NoSuchProviderException ex) {
            throw new InfraEstruturaException(ex.getMessage());
        }
        catch (InvalidKeyException ex) {
        	ex.printStackTrace();
            throw new AssinaturaException(ex.getMessage());
        }
        catch (SignatureException ex) {
        	ex.printStackTrace();
            throw new AssinaturaException(ex.getMessage());
        }
        catch (CMSException ex) {
            throw new InfraEstruturaException(ex.getMessage());
        }
        catch (IOException ex) {
            throw new InfraEstruturaException(ex.getMessage());
        }
        catch (CertStoreException ex) {
            throw new InfraEstruturaException(ex.getMessage());
        }
    }

    private SignerInformation getSignerInformation(CMSSignedData envelope) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, AssinaturaException {
        SignerId id = new SignerId();
        id.setIssuer(this.certificado.getIssuerX500Principal());
        id.setSubject(this.certificado.getSubjectX500Principal());
        id.setSerialNumber(this.certificado.getSerialNumber());
        id.setCertificate(this.certificado);
        SignerInformation info = envelope.getSignerInfos().get(id);
        return info;
    }

    public Assinatura assinarConteudoAttached(byte[] arquivo) throws AssinaturaException {
        try {
            return this.assinarConteudo(arquivo, ALGORITMO_PADRAO_HASH.getObjectId().getId(), true);
        }
        catch (NoSuchAlgorithmException e) {
        	e.printStackTrace();
            return null;
        }
    }

    public Assinatura assinarConteudoAttached(InputStream arquivo) throws IOException, AssinaturaException {
        try {
            return this.assinarConteudo(ConversorUtil.streamToBytes(arquivo), ALGORITMO_PADRAO_HASH.getObjectId().getId(), true);
        }
        catch (NoSuchAlgorithmException e) {
        	e.printStackTrace();
            return null;
        }
    }

    public Assinatura assinarConteudoAttached(byte[] arquivo, String algoritmoOID) throws NoSuchAlgorithmException, AssinaturaException {
        return this.assinarConteudo(arquivo, algoritmoOID, true);
    }

    public Assinatura assinarConteudoAttached(InputStream arquivo, String algoritmoOID) throws NoSuchAlgorithmException, IOException, AssinaturaException {
        return this.assinarConteudo(ConversorUtil.streamToBytes(arquivo), algoritmoOID, true);
    }

    public Assinatura assinarConteudoDetached(byte[] arquivo) throws AssinaturaException {
        try {
            return this.assinarConteudo(arquivo, ALGORITMO_PADRAO_HASH.getObjectId().getId(), false);
        }
        catch (NoSuchAlgorithmException e) {
        	e.printStackTrace();
            return null;
        }
    }

    public Assinatura assinarConteudoDetached(InputStream arquivo) throws NoSuchAlgorithmException, IOException, AssinaturaException {
        try {
            return this.assinarConteudo(ConversorUtil.streamToBytes(arquivo), ALGORITMO_PADRAO_HASH.getObjectId().getId(), false);
        }
        catch (NoSuchAlgorithmException e) {
        	e.printStackTrace();
            return null;
        }
    }

    public Assinatura assinarConteudoDetached(byte[] arquivo, String algoritmoOID) throws NoSuchAlgorithmException, AssinaturaException {
        return this.assinarConteudo(arquivo, algoritmoOID, false);
    }

    public Assinatura assinarConteudoDetached(InputStream arquivo, String algoritmoOID) throws NoSuchAlgorithmException, IOException, AssinaturaException {
        return this.assinarConteudo(ConversorUtil.streamToBytes(arquivo), algoritmoOID, false);
    }
}

