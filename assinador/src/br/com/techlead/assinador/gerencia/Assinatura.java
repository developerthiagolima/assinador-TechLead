package br.com.techlead.assinador.gerencia;

import java.io.IOException;
import java.security.cert.CertSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.SignerInformation;

import br.com.techlead.assinador.comum.util.AlgoritmoCriptograficoUtil;

public class Assinatura {
    public static final String ID_HASH_CONTEUDO = "1.2.840.113549.1.9.4";
    public static final String ID_TIPO_CONTEUDO = "1.2.840.113549.1.9.3";
    public static final String ID_DATAHORA = "1.2.840.113549.1.9.5";
    public static final String ID_CONTADOR = "1.2.840.113549.1.9.6";
    private byte[] assinatura;
    private byte[] encodeAtributosAssinados;
    private Hashtable atributosAssinados;
    private Hashtable atributosNaoAssinados;
    private CertSelector seletorCertificado;
    private int versao;
    private AlgoritmoID algoritmoHash;
    private AlgoritmoID algoritmoCripto;

    public Assinatura(SignerInformation _assinatura) {
        this.assinatura = _assinatura.getSignature();
        try {
            this.encodeAtributosAssinados = _assinatura.getEncodedSignedAttributes();
        }
        catch (IOException e) {
        	e.printStackTrace();
        }
        if (_assinatura.getSignedAttributes() != null) {
            this.configurarAtributosAssinados(_assinatura);
        }
        if (_assinatura.getUnsignedAttributes() != null) {
            this.configurarAtributosNaoAssinados(_assinatura);
        }
        this.seletorCertificado = _assinatura.getSID();
        this.versao = _assinatura.getVersion();
        String id = _assinatura.getDigestAlgOID();
        String nome = AlgoritmoCriptograficoUtil.recuperarNomeHash(id);
        this.algoritmoHash = new AlgoritmoID(id, nome);
        id = _assinatura.getEncryptionAlgOID();
        nome = AlgoritmoCriptograficoUtil.recuperarNomeEncriptacao(id);
        this.algoritmoCripto = new AlgoritmoID(id, nome);
    }

    public AlgoritmoID getAlgoritmoCripto() {
        return this.algoritmoCripto;
    }

    public AlgoritmoID getAlgoritmoHash() {
        return this.algoritmoHash;
    }

    public byte[] getAssinatura() {
        return this.assinatura;
    }

    public byte[] getEncodeAtributosAssinados() {
        return this.encodeAtributosAssinados;
    }

    public Hashtable getAtributosAssinados() {
        return this.atributosAssinados;
    }

    public Hashtable getAtributosNaoAssinados() {
        return this.atributosNaoAssinados;
    }

    public CertSelector getSeletorCertificado() {
        return this.seletorCertificado;
    }

    public int getVersao() {
        return this.versao;
    }

    private void configurarAtributosAssinados(SignerInformation _assinatura) {
        Hashtable hashtable = _assinatura.getSignedAttributes().toHashtable();
        this.atributosAssinados = new Hashtable();
        for (Object obj : hashtable.keySet()) {
        	DERObjectIdentifier objId = (DERObjectIdentifier) obj;
            Attribute att = this.gerarAtributo(hashtable, objId);
            if (att == null) continue;
            if (ID_HASH_CONTEUDO.equals(objId.getId())) {
                this.atributosAssinados.put(ID_HASH_CONTEUDO, this.recuperarHashConteudoAssinado(att));
                continue;
            }
            if (ID_TIPO_CONTEUDO.equals(objId.getId())) {
                this.atributosAssinados.put(ID_TIPO_CONTEUDO, this.recuperarIdTipoConteudo(att));
                continue;
            }
            if (ID_DATAHORA.equals(objId.getId())) {
                this.atributosAssinados.put(ID_DATAHORA, this.recuperarDataAssinatura(att));
                continue;
            }
            this.atributosAssinados.put(objId.getId(), att.getDEREncoded());
        }
    }

    private byte[] recuperarHashConteudoAssinado(Attribute atributo) {
        try {
            DERObject der = atributo.getAttrValues().getObjectAt(0).getDERObject();
            ASN1OctetString octeto = ASN1OctetString.getInstance((Object)der);
            return octeto.getOctets();
        }
        catch (Exception e) {
        	e.printStackTrace();
            return null;
        }
    }

    private String recuperarIdTipoConteudo(Attribute atributo) {
        try {
            DERObject der = atributo.getAttrValues().getObjectAt(0).getDERObject();
            DERObjectIdentifier id = DERObjectIdentifier.getInstance((Object)der);
            return id.getId();
        }
        catch (Exception e) {
        	e.printStackTrace();
            return null;
        }
    }

    private Date recuperarDataAssinatura(Attribute atributo) {
        try {
            DERObject der = atributo.getAttrValues().getObjectAt(0).getDERObject();
            Time time = Time.getInstance((Object)der);
            return time.getDate();
        }
        catch (Exception e) {
        	e.printStackTrace();
            return null;
        }
    }

    private void configurarAtributosNaoAssinados(SignerInformation _assinatura) {
        Hashtable hashtable = _assinatura.getSignedAttributes().toHashtable();
        this.atributosNaoAssinados = new Hashtable();
        for (Object obj : hashtable.keySet()) {
        	DERObjectIdentifier objId = (DERObjectIdentifier) obj;
            Attribute att = this.gerarAtributo(hashtable, objId);
            if (att == null) continue;
            this.atributosNaoAssinados.put(objId.getId(), att.getDEREncoded());
        }
    }

    private Attribute gerarAtributo(Hashtable hashtable, DERObjectIdentifier objId) {
        Object objeto = hashtable.get((Object)objId);
        if (objeto instanceof Attribute) {
            return (Attribute)objeto;
        }
        if (objeto instanceof List) {
            List lista = (List)objeto;
            try {
                return (Attribute)lista.get(0);
            }
            catch (ClassCastException e) {
                return null;
            }
        }
        return null;
    }

    static Collection<Assinatura> parseLista(Collection<SignerInformation> assinatura) {
        ArrayList<Assinatura> colecao = new ArrayList<Assinatura>();
        for (SignerInformation signerInformation : assinatura) {
            colecao.add(new Assinatura(signerInformation));
        }
        return colecao;
    }
}

