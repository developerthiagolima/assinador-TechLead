package br.com.techlead.assinador.comum.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import br.com.techlead.assinador.comum.excecoes.AlgoritmoException;

public final class GeradorHashUtil {
	private static final String ALGORITMO_PADRAO = "SHA1";

	private GeradorHashUtil() {
	}

	public static byte[] gerarHash(String conteudo) {
		return GeradorHashUtil.gerarHash(conteudo.getBytes());
	}

	public static byte[] gerarHash(InputStream input) throws NoSuchAlgorithmException {
		return GeradorHashUtil.gerarHash(input, ALGORITMO_PADRAO);
	}

	public static byte[] gerarHash(InputStream input, String algoritmo) throws NoSuchAlgorithmException {
		try {
			MessageDigest digest = MessageDigest.getInstance(algoritmo);
			DigestInputStream dis = new DigestInputStream(input, digest);
			byte[] buffer = new byte[1024];
			while (dis.read(buffer) != -1) {
			}
			return digest.digest();
		} catch (NoSuchAlgorithmException e) {
			throw e;
		} catch (IOException e) {
			return "MSG059".getBytes();
		}
	}

	public static byte[] gerarHash(byte[] conteudo) {
		try {
			return GeradorHashUtil.gerarHash(conteudo, ALGORITMO_PADRAO);
		} catch (NoSuchAlgorithmException e) {
			throw new AlgoritmoException(e.getMessage(), e);
		}
	}

	public static byte[] gerarHash(String conteudo, String algoritmo) {
		return GeradorHashUtil.gerarHash(conteudo, algoritmo);
	}

	public static byte[] gerarHash(byte[] conteudo, String algoritmo) throws NoSuchAlgorithmException {
		try {
			MessageDigest digest = MessageDigest.getInstance(algoritmo);
			return digest.digest(conteudo);
		} catch (NoSuchAlgorithmException e) {
			throw e;
		}
	}
}
