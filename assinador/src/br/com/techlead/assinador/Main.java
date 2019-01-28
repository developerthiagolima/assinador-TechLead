package br.com.techlead.assinador;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.io.IOUtils;

import br.com.techlead.assinador.assinatura.Assinatura;
import br.com.techlead.assinador.assinatura.AssinaturaFachada;

public class Main {
	
	private String currentDirectory = new File("").getAbsolutePath();
	private String certificadoName = "/13015516_out.pfx";
	public File certificadoFile = new File(currentDirectory+certificadoName);
	private String alias = "";
	private char[] senha = "1234".toCharArray();
	
	private KeyStore store;
	private X509Certificate cert;
	private PrivateKey priKey;
	private PublicKey pubKey;
	private Certificate[] chain;
	private AssinaturaFachada assinaturaFachada = AssinaturaFachada.getInstancia();

	public static void main(String[] args) {		
		try {
			File pdf = new File("/Users/presto/Documents/workspace_201812/assinador/file.pdf");
			File p7s = new File("/Users/presto/Documents/workspace_201812/assinador/file.p7s");
			p7s.createNewFile();
			
			Main m = new Main();
			m.carregaCertificado();
			m.assinar(pdf, p7s);
			
			System.out.println("#### ----->> FIM");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void carregaCertificado() {
		try{
			System.out.println("#### ----->> Caminho diretório para o certificado digital: "+currentDirectory);
			if(certificadoFile.exists()){
				InputStream dado = new FileInputStream(certificadoFile);
				store = KeyStore.getInstance("PKCS12");
				store.load(dado, senha);
				
				Enumeration enumeration = store.aliases();
		        while(enumeration.hasMoreElements()) {
		            alias = (String)enumeration.nextElement();
		        }
				
				cert = (X509Certificate) store.getCertificate(alias);
				String retorno = getValidade(cert);
				System.out.println(retorno);
				priKey = getChavePrivada();
				pubKey = getChavePublica();
				chain = store.getCertificateChain(alias);
			}else{
				System.out.println("Certificado Não Localizado!");
			}
		}catch(Exception e){
			System.out.println("Certificado Não Carregado!");
			e.printStackTrace();
		}
    }
	
	public String getValidade(X509Certificate cert) {
        try {
            cert.checkValidity();
            return "Certificado válido!";
        } catch (CertificateExpiredException e) {
            return "Certificado expirado!";
        } catch (CertificateNotYetValidException e) {
            return "Certificado inválido!";
        }
    }
	
	public PrivateKey getChavePrivada() throws Exception {
        Key chavePrivada = (Key) store.getKey(alias, senha);
        if (chavePrivada instanceof PrivateKey) {
        	System.out.println("Chave Privada encontrada!");
            return (PrivateKey) chavePrivada;
        }
        return null;
    }
	
	public PublicKey getChavePublica() throws Exception {
        PublicKey chavePublica = cert.getPublicKey();
        System.out.println("Chave Pública encontrada!");
        return chavePublica;
    }
	
	public File assinar(File pdf, File p7s) throws Exception {
		byte[] dataToSign = IOUtils.toByteArray(new FileInputStream(pdf));
		Assinatura assinatura = assinaturaFachada.assinarConteudoAttached(priKey, cert, dataToSign);
		
		FileOutputStream outputStream = new FileOutputStream(p7s);
		outputStream.write(assinatura.getEnvelope());
        outputStream.flush();
        outputStream.close();
        
		return p7s;
	}

}
