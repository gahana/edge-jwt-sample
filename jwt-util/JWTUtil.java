import java.io.File;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;

public class JWTUtil {

	private static String payload = getSamplePayload();
	private static Key signKey = new SecretKeySpec("4UKCBxUePF5Ni2lY".getBytes(), "HmacSHA512");
	private static KeyPair rsaKeyPair = getRSAKeyPair();

	public static void main(String[] args) throws Exception {
		System.out.println("Starting...");
		// generateKeys();
		// testJWS(payload);
		// testJWE(payload);
		// testJWEJWS(payload);
		testJWEJWSWithKeyFiles(payload);
		System.out.println("Done.");
	}

	private static void generateKeys() {
		System.out.println(keyToString(getAES128Key()));
		System.out.println(keyToString(getAES192Key()));
		System.out.println(keyToString(getAES256Key()));
		System.out.println(keyToString(getHmacSHA512Key()));
	}

	private static String getSamplePayload() {
	    JwtClaims claims = new JwtClaims();
	    claims.setIssuer("issue-idp-1");
	    claims.setAudience("aud-1", "aud-2");
	    claims.setExpirationTimeMinutesInTheFuture(299);
	    claims.setGeneratedJwtId();
	    claims.setIssuedAtToNow();
	    claims.setNotBeforeMinutesInThePast(2);
	    claims.setSubject("johndoe");
	    claims.setClaim("email","johndoe@example.com");
	    return claims.toJson();
	}

	private static KeyPair getRSAKeyPair() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			return keyGen.generateKeyPair();
		} catch (Exception e) {
			System.out.println("Unable to initialize RSA key pair.");
			e.printStackTrace();
			return null;
		}
	}

	private static void testJWS(String payload) throws Exception {
		System.out.println("Signing payload: " + payload);
		String jwt = jwsSign(signKey, payload);
		System.out.println("JWT: " + jwt);

		String content = jwsVerify(signKey, jwt);
		System.out.println("Extracted content: " + content);
		System.out.println("payload == content: " + payload.equals(content));
	}

	private static String jwsSign(Key key, String payload) throws Exception {
		JsonWebSignature jws = new JsonWebSignature();
		jws.setPayload(payload);
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA512);
		jws.setKey(key);
		jws.setDoKeyValidation(false);
		return jws.getCompactSerialization();
	}

	private static String jwsVerify(Key key, String jwt) throws Exception {
		JsonWebSignature jws = new JsonWebSignature();
		jws.setCompactSerialization(jwt);
		jws.setKey(key);
		jws.setDoKeyValidation(false);
		boolean signatureVerified = jws.verifySignature();

		System.out.println("JWS signature verification: " + signatureVerified);
		System.out.println("JWT Headers: " + jws.getHeaders().getFullHeaderAsJsonString() );

		return jws.getPayload();
	}

	private static void testJWE(String payload) throws Exception {
		System.out.println("Encrypting payload: " + payload);
		String jwt = jweEncrypt(rsaKeyPair.getPublic(), payload, false);
		System.out.println("JWT: " + jwt);

		String content = jweDecrypt(rsaKeyPair.getPrivate(), jwt);
		System.out.println("Decrypted content: " + content);
		System.out.println("payload == content: " + payload.equals(content));
	}

	private static String jweEncrypt(Key key, String payload, boolean isPayloadJWT) throws Exception {
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setAlgorithmHeaderValue(
			KeyManagementAlgorithmIdentifiers.RSA_OAEP);
		jwe.setEncryptionMethodHeaderParameter(
			ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
		jwe.setKey(key);
		if (isPayloadJWT) jwe.setContentTypeHeaderValue("JWT");
		jwe.setPayload(payload);
		return jwe.getCompactSerialization();
	}

	private static String jweDecrypt(Key key, String jwt) throws Exception {
	    JsonWebEncryption jwe = new JsonWebEncryption();
	    jwe.setAlgorithmConstraints(
	    	new AlgorithmConstraints(
	    		ConstraintType.WHITELIST, 
	    		KeyManagementAlgorithmIdentifiers.RSA_OAEP));
	    jwe.setContentEncryptionAlgorithmConstraints(
	    	new AlgorithmConstraints(
	    		ConstraintType.WHITELIST, 
	    		ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512));
	    jwe.setCompactSerialization(jwt);
	    jwe.setKey(key);
	    return jwe.getPlaintextString();
	}

	private static void testJWEJWS(String payload) throws Exception {
		System.out.println("Signing payload: " + payload);
		String innerJWT = jwsSign(signKey, payload);
		System.out.println("Encrypting signed JWT: " + innerJWT);
		String jwt = jweEncrypt(rsaKeyPair.getPublic(), innerJWT, true);
		System.out.println("Signed and Encrypted JWT: " + jwt);

		String plaintext = jwtProcess(rsaKeyPair.getPrivate(), signKey, jwt);
		System.out.println("Decrypted content: " + plaintext);
		System.out.println("payload == content: " + payload.equals(plaintext));
	}

	private static String jwtProcess(Key jweKey, Key jwsKey, String jwt) throws Exception {
	    AlgorithmConstraints jwsAlgConstraints = 
		    new AlgorithmConstraints(
		    	ConstraintType.WHITELIST,
		    	AlgorithmIdentifiers.HMAC_SHA512);

	    AlgorithmConstraints jweAlgConstraints = 
		    new AlgorithmConstraints(
		    	ConstraintType.WHITELIST,
		    	KeyManagementAlgorithmIdentifiers.RSA_OAEP);

	    AlgorithmConstraints jweEncConstraints = 
	    	new AlgorithmConstraints(
	    		ConstraintType.WHITELIST,
	            ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);

	    JwtConsumer jwtConsumer = 
	    	new JwtConsumerBuilder()
	            .setRequireExpirationTime()
	            .setMaxFutureValidityInMinutes(300)
	            .setRequireSubject()
	            .setExpectedIssuer("issue-idp-1")
	            .setExpectedAudience("aud-1", "aud-2")
	            .setDecryptionKey(jweKey)
	            .setVerificationKey(jwsKey)
	            .setRelaxVerificationKeyValidation()
	            .setJwsAlgorithmConstraints(jwsAlgConstraints)
	            .setJweAlgorithmConstraints(jweAlgConstraints)
	            .setJweContentEncryptionAlgorithmConstraints(jweEncConstraints)
	            .build();

	    try {
	        return jwtConsumer.processToClaims(jwt).toJson();
	    } catch (InvalidJwtException e) {
	        System.out.println("Invalid JWT! " + e);
	        return null;
	    }
	}

	private static void testJWEJWSWithKeyFiles(String payload) throws Exception {
		// For generating key files see
		// https://adangel.org/2016/08/29/openssl-rsa-java/ 
		
		System.out.println("Signing payload: " + payload);
		String innerJWT = jwsSign(signKey, payload);
		System.out.println("Encrypting signed JWT: " + innerJWT);
		String jwt = jweEncrypt(loadPublicKey(), innerJWT, true);
		System.out.println("Signed and Encrypted JWT: " + jwt);

		String plaintext = jwtProcess(loadPrivateKey(), signKey, jwt);
		System.out.println("Decrypted content: " + plaintext);
		System.out.println("payload == content: " + payload.equals(plaintext));
	}

	private static String getKeyFromFile(String filename) throws Exception {
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];
		dis.readFully(keyBytes);
		dis.close();
		fis.close();
		return new String(keyBytes);
	}

	public static PublicKey loadPublicKey() throws Exception {
	    String publicKeyPEM = getKeyFromFile("./keys/publickey.pem");

	    // strip of header, footer, newlines, whitespaces
	    publicKeyPEM = publicKeyPEM
	            .replace("-----BEGIN PUBLIC KEY-----", "")
	            .replace("-----END PUBLIC KEY-----", "")
	            .replaceAll("\\s", "");

	    // decode to get the binary DER representation
	    byte[] publicKeyDER = Base64.getDecoder().decode(publicKeyPEM);

	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDER));
	    return publicKey;
	}

	public static PrivateKey loadPrivateKey() throws Exception {
	    String privateKeyPEM = getKeyFromFile("./keys/privatekey-pkcs8.pem");
	    PKCS8EncodedKeySpec p8eks = null;
		if (isEncrypted(privateKeyPEM)) {
			p8eks = getEncodedPrivateKeySpec(privateKeyPEM, "123");
		} else {
			p8eks = getUnencodedPrivateKeySpec(privateKeyPEM);
		}
		return KeyFactory.getInstance("RSA").generatePrivate(p8eks);
	}

	public static PKCS8EncodedKeySpec getEncodedPrivateKeySpec(String key, String password) throws Exception {
	    String privateKeyPEM = key
	            .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
	            .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
	            .replaceAll("\\s", "");

	    // decode to get the binary DER representation
	    byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

	    EncryptedPrivateKeyInfo epkInfo = new EncryptedPrivateKeyInfo(privateKeyDER);
	    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(epkInfo.getAlgName());
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
	    SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

	    Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
	    cipher.init(Cipher.DECRYPT_MODE, pbeKey, epkInfo.getAlgParameters());

	    return epkInfo.getKeySpec(cipher);
	}

	public static PKCS8EncodedKeySpec getUnencodedPrivateKeySpec(String key) throws Exception {
	    // strip of header, footer, newlines, whitespaces
	    String privateKeyPEM = key
	            .replace("-----BEGIN PRIVATE KEY-----", "")
	            .replace("-----END PRIVATE KEY-----", "")
	            .replaceAll("\\s", "");

	    // decode to get the binary DER representation
	    byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

	    return new PKCS8EncodedKeySpec(privateKeyDER);
	}

	private static boolean isEncrypted(String key) {
		return key.indexOf("-----BEGIN ENCRYPTED PRIVATE KEY-----") != -1;
	}

	public static PrivateKey loadPrivateKey_old() throws Exception {
	    String privateKeyPEM = getKeyFromFile("./keys/privatekey-pkcs8.pem");

	    // strip of header, footer, newlines, whitespaces
	    privateKeyPEM = privateKeyPEM
	            .replace("-----BEGIN PRIVATE KEY-----", "")
	            .replace("-----END PRIVATE KEY-----", "")
	            .replaceAll("\\s", "");

	    // decode to get the binary DER representation
	    byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDER));
	    return privateKey;
	}


	private static byte[] getKeyFromFile2(String filename) throws Exception {
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];
		dis.readFully(keyBytes);
		dis.close();
		fis.close();
		return keyBytes;
	}

	private static PrivateKey loadPrivateKey2() throws Exception {

	    String privateKeyPEM = getKeyFromFile("./keys/privatekey-pkcs8.pem");
	    // strip of header, footer, newlines, whitespaces
	    privateKeyPEM = privateKeyPEM
	            .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
	            .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
	            .replaceAll("\\s", "");

	    // decode to get the binary DER representation
	    byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);


	    EncryptedPrivateKeyInfo epkInfo = new EncryptedPrivateKeyInfo(privateKeyDER);
	    System.out.println("Algo: ");
	    System.out.println(epkInfo.getAlgName());
	    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(epkInfo.getAlgName());
	    PBEKeySpec pbeKeySpec = new PBEKeySpec("123".toCharArray());
	    SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

	    Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
	    cipher.init(Cipher.DECRYPT_MODE, pbeKey, epkInfo.getAlgParameters());

	    // return epkInfo.getKeySpec(cipher);


	    KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
	    PrivateKey privateKey = keyFactory2.generatePrivate(epkInfo.getKeySpec(cipher));
	    return privateKey;
	}


	private static SecretKey getHMACKey(String algo) {
		try {
			return KeyGenerator.getInstance(algo).generateKey();
		} catch (Exception e) {
			return null;
		}
	}

	private static SecretKey getHmacSHA256Key() {
		return getHMACKey("HmacSHA256");
	}

	private static SecretKey getHmacSHA384Key() {
		return getHMACKey("HmacSHA384");
	}

	private static SecretKey getHmacSHA512Key() {
		return getHMACKey("HmacSHA512");
	}

	private static String keyToString(SecretKey key) {
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}

	private static SecretKey getAES128Key() {
		return getAESKey(128);
	}

	private static SecretKey getAES192Key() {
		return getAESKey(192);
	}

	private static SecretKey getAES256Key() {
		return getAESKey(256);
	}

	private static SecretKey getAESKey(int bits) {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(bits);
			return keyGen.generateKey();
		} catch (Exception e) {
			return null;
		}
	}

}

