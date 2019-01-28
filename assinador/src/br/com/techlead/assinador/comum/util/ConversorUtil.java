package br.com.techlead.assinador.comum.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.x509.X509NameTokenizer;
import org.bouncycastle.util.encoders.Hex;

public final class ConversorUtil {
    private static final char[] HEXC = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private ConversorUtil() {
    }

    public static String toHexadecimal(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder(bytes.length * 2);
        int i = 0;
        while (i < bytes.length) {
            stringBuilder.append(HEXC[bytes[i] >> 4 & 15]);
            stringBuilder.append(HEXC[bytes[i] & 15]);
            ++i;
        }
        return stringBuilder.toString().toLowerCase().trim();
    }

    public static byte[] encodeToHex(byte[] conteudo) {
        return Hex.encode((byte[])conteudo);
    }

    public static byte[] decodeHex(byte[] conteudoHex) {
        return Hex.decode((byte[])conteudoHex);
    }

    public static byte[] streamToBytes(InputStream stream) throws IOException {
        FilterOutputStream bufferedOutput = null;
        BufferedInputStream bufferedInput = new BufferedInputStream(stream);
        try {
            int leitor;
            byte[] array;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            bufferedOutput = new BufferedOutputStream(output);
            while ((leitor = bufferedInput.read()) != -1) {
                output.write(leitor);
            }
            byte[] arrby = array = output.toByteArray();
            return arrby;
        }
        finally {
            bufferedOutput.close();
        }
    }

    public static Collection getDominioNome(String dn) {
        ArrayList<String> nomes = new ArrayList<String>();
        X509NameTokenizer tokenizer = new X509NameTokenizer(dn);
        while (tokenizer.hasMoreTokens()) {
            nomes.add(tokenizer.nextToken());
        }
        return nomes;
    }
}

