import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;


public class FileServerCertificateGenerator {
	public static void main(String[] args) throws IOException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair keyPair;
		KeyPairGenerator keyPairGen = null;
		X509Certificate cert = null;
		
		try {
			keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGen.initialize(new RSAKeyGenParameterSpec(4096, BigInteger.valueOf(65537)), new SecureRandom());
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Generate the key pair
		keyPair = keyPairGen.generateKeyPair();
		
		// yesterday
	    Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
	    // in 2 years
	    Date validityEndDate = new Date(System.currentTimeMillis() + (2l * 365l * 24l * 60l* 60l * 1000l));

	    // GENERATE THE X509 CERTIFICATE
	    X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
	    X500Principal dnName = new X500Principal("CN=File Server");

	    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	    certGen.setSubjectDN(dnName);
	    certGen.setIssuerDN(dnName); // use the same
	    certGen.setNotBefore(validityBeginDate);
	    certGen.setNotAfter(validityEndDate);
	    certGen.setPublicKey(keyPair.getPublic());
	    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

	    try {
			cert = certGen.generate(keyPair.getPrivate(), "BC");
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
	    PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
	    
	    FileWriter certFileWriter = new FileWriter(new File("public-certFS.pem"));
	    FileWriter privateFileWriter = new FileWriter(new File("private-keyFS.pem"));
	    
	    PEMWriter certPEMWriter = new PEMWriter(certFileWriter);
	    PEMWriter privatePEMWriter = new PEMWriter(privateFileWriter);
	    

	    System.out.println(new String(new char[80]).replace('\0', '='));
	    System.out.println("PRIVATE KEY PEM (stored in private-keyFS.pem)");
	    System.out.println(new String(new char[80]).replace('\0', '='));
	    System.out.println();
	    pemWriter.writeObject(keyPair.getPrivate());
	    pemWriter.flush();
	    privatePEMWriter.writeObject(keyPair.getPrivate());
	    privatePEMWriter.flush();
	    System.out.println();
		
	    System.out.println(new String(new char[80]).replace('\0', '='));
	    System.out.println("CERT PEM (stored in public-certFS.pem)");
	    System.out.println(new String(new char[80]).replace('\0', '='));
	    System.out.println();
	    pemWriter.writeObject(cert);
	    pemWriter.flush();
	    certPEMWriter.writeObject(cert);
	    certPEMWriter.flush();
	    System.out.println();
	}
}
