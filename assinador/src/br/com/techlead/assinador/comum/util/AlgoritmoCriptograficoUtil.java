package br.com.techlead.assinador.comum.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedDataGenerator;

public final class AlgoritmoCriptograficoUtil {
    private static Map nomeHashTable = new HashMap();
    private static Map nomeEncryptionTable = new HashMap();

    static {
        nomeHashTable.put(PKCSObjectIdentifiers.md5.getId(), "MD5");
        nomeHashTable.put(OIWObjectIdentifiers.idSHA1.getId(), "SHA1");
        nomeHashTable.put(NISTObjectIdentifiers.id_sha224.getId(), "SHA224");
        nomeHashTable.put(NISTObjectIdentifiers.id_sha256.getId(), "SHA256");
        nomeHashTable.put(NISTObjectIdentifiers.id_sha384.getId(), "SHA384");
        nomeHashTable.put(NISTObjectIdentifiers.id_sha512.getId(), "SHA512");
        nomeHashTable.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1");
        nomeHashTable.put(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(), "SHA224");
        nomeHashTable.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256");
        nomeHashTable.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384");
        nomeHashTable.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512");
        nomeHashTable.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), "RIPEMD128");
        nomeHashTable.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), "RIPEMD160");
        nomeHashTable.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), "RIPEMD256");
        nomeHashTable.put(CryptoProObjectIdentifiers.gostR3411.getId(), "GOST3411");
        nomeEncryptionTable.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "DSA");
        nomeEncryptionTable.put(X9ObjectIdentifiers.id_dsa.getId(), "DSA");
        nomeEncryptionTable.put(OIWObjectIdentifiers.dsaWithSHA1.getId(), "DSA");
        nomeEncryptionTable.put(PKCSObjectIdentifiers.rsaEncryption.getId(), "RSA");
        nomeEncryptionTable.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "RSA");
        nomeEncryptionTable.put("1.3.36.3.3.1", "RSA");
        nomeEncryptionTable.put(CMSSignedDataGenerator.ENCRYPTION_ECDSA, "ECDSA");
        nomeEncryptionTable.put(CMSSignedDataGenerator.ENCRYPTION_RSA_PSS, "RSAandMGF1");
        nomeEncryptionTable.put(CryptoProObjectIdentifiers.gostR3410_94.getId(), "GOST3410");
        nomeEncryptionTable.put(CryptoProObjectIdentifiers.gostR3410_2001.getId(), "ECGOST3410");
    }

    private AlgoritmoCriptograficoUtil() {
    }

    public static String recuperarNomeHash(String id) {
        return (String)nomeHashTable.get(id);
    }

    public static String recuperarNomeEncriptacao(String id) {
        return (String)nomeEncryptionTable.get(id);
    }

    public static void registrarAlgoritmoHash(String id, String nome) {
        nomeHashTable.put(id, nome);
    }

    public static void registrarAlgoritmoCripto(String id, String nome) {
        nomeEncryptionTable.put(id, nome);
    }
}

