package com.apigeecs.jwt;

import java.util.Map;
import java.util.HashMap;
import java.util.Base64;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;


import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;

public class JWTGenerator implements Execution {

	private static String RESULT = "JWTGeneratorResult";
	private static String RESULT_SUCCESS = "Success";
	private static String RESULT_FAILURE = "Failure";

	private static String REASON = "JWTGeneratorReason";
	private static String REASON_VALID = "ValidToken";


	private static String DEBUG_MESSAGE = "JWTGeneratorDebugMessage";

	private static String JWT = "JWTGeneratorJWT";
	private static String JWT_NA = "NA";

	private static Map<String, String> ALGORITHMS = supportedAlgos();

	private Map<String, String> properties;
	private boolean jws;
	private String jwsKey;
	private String jwsKeyPassword;
	private String jwsAlgo;

	private boolean jwe;
	private String jweKey;
	private String jweKeyPassword;
	private String jweKeyAlgo;
	private String jweAlgo;

	private JwtClaims claims;
	
	private String issuer;
	private String audience;
	private String expiry;
	
	private MessageContext msgContext;
	private ExecutionContext execContext;

	public JWTGenerator(Map<String, String> properties) {
		this.properties = properties;
	}

	public String toString() {
		return "jws=" + this.jws + ":" + 
		       "jwsKey=" + this.jwsKey + ":" + 
		       "jwsKeyPassword=" + this.jwsKeyPassword + ":" + 
			   "jwsAlgo=" + this.jwsAlgo + ":" + 
			   "jwe=" + this.jwe + ":" + 
			   "jweKey=" + this.jweKey + ":" + 
			   "jweKeyPassword=" + this.jweKeyPassword + ":" + 
			   "jweKeyAlgo=" + this.jweKeyAlgo + ":" + 
			   "jweAlgo=" + this.jweAlgo + ":" + 
			   "claims=" + this.claims.toJson() + ":" + 
			   "iss=" + this.issuer + ":" + 
			   "aud=" + this.audience + ":" + 
			   "expiry=" + this.expiry;
	}

	public ExecutionResult execute(MessageContext msgContext, ExecutionContext execContext) {
		try {
			this.init(msgContext, execContext);
			this.validateProperties();
			this.setupClaims();
			String jwt = this.generate();
			this.setResult(RESULT_SUCCESS, REASON_VALID, jwt);
			return ExecutionResult.SUCCESS;
		} catch (InvalidConfig e) {
			this.setResult(RESULT_FAILURE, e.getMessage(), JWT_NA);
			return ExecutionResult.ABORT;
		} catch (Exception e) {
			this.setResult(RESULT_FAILURE, e.getMessage(), JWT_NA);
			return ExecutionResult.ABORT;
		}
	}

	private void init(MessageContext msgContext, ExecutionContext execContext) throws Exception {
		this.msgContext = msgContext;
		this.execContext = execContext;

		this.jws = "true".equals(this.resolveVariable(this.properties.get("jws")));
		this.jwsAlgo = this.resolveVariable(this.properties.get("jws-algo"));
		this.jwsKey = this.resolveVariable(this.properties.get("jws-key"));
		this.jwsKeyPassword = this.resolveVariable(this.properties.get("jws-key-pass"));

		this.jwe = "true".equals(this.resolveVariable(this.properties.get("jwe")));
		this.jweKey = this.resolveVariable(this.properties.get("jwe-key"));
		this.jweKeyPassword = this.resolveVariable(this.properties.get("jwe-key-pass"));
		this.jweKeyAlgo = this.resolveVariable(this.properties.get("jwe-key-algo"));
		this.jweAlgo = this.resolveVariable(this.properties.get("jwe-algo"));
		
		this.claims = JwtClaims.parse(this.resolveVariable(this.properties.get("claims-json")));
		this.issuer = this.resolveVariable(this.properties.get("iss"));
		this.audience = this.resolveVariable(this.properties.get("aud"));
		this.expiry = this.resolveVariable(this.properties.get("expiry"));

		this.debugMessage("Properties", this.printMap(this.properties));
		this.debugMessage("PropertiesValue", this.toString());
	}

	private String resolveVariable(String variable) {
		if (isEmpty(variable)) return variable;
		if (variable.startsWith("{") && variable.endsWith("}")) {
			String value = this.msgContext.getVariable(variable.substring(1, variable.length() - 1));
			this.debugMessage("VariableValue" + variable, value);
			if (isEmpty(value)) {
				return variable;	// A JSON string that starts with '{' and ends with '}'
			} else {
				return value;
			}
		} else {
			return variable;
		}
	}

	private void validateProperties() throws Exception {
		if (!this.jws && !this.jwe) {
			throw new InvalidConfig("Either jws or jwe property should be set to true");
		}
		if (this.jws) {
			if (! ALGORITHMS.containsKey(this.jwsAlgo)) {
				throw new InvalidConfig("Invalid JWS Algorithm");
			}
			if (isEmpty(this.jwsKey)) {
				throw new InvalidConfig("Empty JWS Key");
			}
		}
		if (this.jwe) {
			if (! ALGORITHMS.containsKey(this.jweKeyAlgo)) {
				throw new InvalidConfig("Invalid JWE Key Algorithm");
			}
			if (! ALGORITHMS.containsKey(this.jweAlgo)) {
				throw new InvalidConfig("Invalid JWE Algorithm");
			}
			if (isEmpty(this.jweKey)) {
				throw new InvalidConfig("Empty JWE Key");
			}
		}
	}

	private String generate() throws Exception {
		if (this.jws && this.jwe) {
			return jweEncrypt(jwsSign(), true);
		} else if (this.jws) {
			return jwsSign();
		} else if (this.jwe) {
			return jweEncrypt(this.claims.toJson(), false);
		}
		return JWT_NA;
	}

	private void setupClaims() throws Exception {
		NumericDate now = NumericDate.now();
		NumericDate expiry = NumericDate.now();
		expiry.addSeconds(Integer.parseInt(this.expiry) * 60);

	    this.claims.setIssuer(this.issuer);
	    this.claims.setAudience(this.audience);
	    this.claims.setGeneratedJwtId();
	    this.claims.setIssuedAt(now);
	    this.claims.setExpirationTime(expiry);
	    this.debugMessage("Claims", this.claims.toJson());
	}

	private static Map<String, String> supportedAlgos() {
		// https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.1
		// See jose4j javadoc http://static.javadoc.io/org.bitbucket.b_c/jose4j/0.5.6/org/jose4j/jws/AlgorithmIdentifiers.html
		HashMap<String, String> algos = new HashMap<String, String>();

		// Sign algos
		algos.put("ECDSA_USING_P256_CURVE_AND_SHA256", AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
		algos.put("ECDSA_USING_P384_CURVE_AND_SHA384", AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384);
		algos.put("ECDSA_USING_P521_CURVE_AND_SHA512", AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512);
		algos.put("HMAC_SHA256", AlgorithmIdentifiers.HMAC_SHA256);
		algos.put("HMAC_SHA384", AlgorithmIdentifiers.HMAC_SHA384);
		algos.put("HMAC_SHA512", AlgorithmIdentifiers.HMAC_SHA512);
		algos.put("NONE", AlgorithmIdentifiers.NONE);
		algos.put("RSA_PSS_USING_SHA256", AlgorithmIdentifiers.RSA_PSS_USING_SHA256);
		algos.put("RSA_PSS_USING_SHA384", AlgorithmIdentifiers.RSA_PSS_USING_SHA384);
		algos.put("RSA_PSS_USING_SHA512", AlgorithmIdentifiers.RSA_PSS_USING_SHA512);
		algos.put("RSA_USING_SHA256", AlgorithmIdentifiers.RSA_USING_SHA256);
		algos.put("RSA_USING_SHA384", AlgorithmIdentifiers.RSA_USING_SHA384);
		algos.put("RSA_USING_SHA512", AlgorithmIdentifiers.RSA_USING_SHA512);

		// Key Management Algos
		algos.put("A128GCMKW", KeyManagementAlgorithmIdentifiers.A128GCMKW);
		algos.put("A128KW", KeyManagementAlgorithmIdentifiers.A128KW);
		algos.put("A192GCMKW", KeyManagementAlgorithmIdentifiers.A192GCMKW);
		algos.put("A192KW", KeyManagementAlgorithmIdentifiers.A192KW);
		algos.put("A256GCMKW", KeyManagementAlgorithmIdentifiers.A256GCMKW);
		algos.put("A256KW", KeyManagementAlgorithmIdentifiers.A256KW);
		algos.put("DIRECT", KeyManagementAlgorithmIdentifiers.DIRECT);
		algos.put("ECDH_ES", KeyManagementAlgorithmIdentifiers.ECDH_ES);
		algos.put("ECDH_ES_A128KW", KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
		algos.put("ECDH_ES_A192KW", KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW);
		algos.put("ECDH_ES_A256KW", KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW);
		algos.put("PBES2_HS256_A128KW", KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW);
		algos.put("PBES2_HS384_A192KW", KeyManagementAlgorithmIdentifiers.PBES2_HS384_A192KW);
		algos.put("PBES2_HS512_A256KW", KeyManagementAlgorithmIdentifiers.PBES2_HS512_A256KW);
		algos.put("RSA_OAEP", KeyManagementAlgorithmIdentifiers.RSA_OAEP);
		algos.put("RSA_OAEP_256", KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
		algos.put("RSA1_5", KeyManagementAlgorithmIdentifiers.RSA1_5);

		// Content encryption algos
		algos.put("AES_128_CBC_HMAC_SHA_256", ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
		algos.put("AES_128_GCM", ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
		algos.put("AES_192_CBC_HMAC_SHA_384", ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384);
		algos.put("AES_192_GCM", ContentEncryptionAlgorithmIdentifiers.AES_192_GCM);
		algos.put("AES_256_CBC_HMAC_SHA_512", ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
		algos.put("AES_256_GCM", ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);

		return algos;
	}

	private String jwsSign() throws Exception {
		JsonWebSignature jws = new JsonWebSignature();
		jws.setPayload(this.claims.toJson());
		jws.setAlgorithmHeaderValue(ALGORITHMS.get(this.jwsAlgo));
		jws.setKey(this.getJWSKey(this.jwsKey, this.jwsAlgo, this.jwsKeyPassword));
		return jws.getCompactSerialization();
	}

	private String jweEncrypt(String payload, boolean isPayloadJWT) throws Exception {
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setAlgorithmHeaderValue(
			ALGORITHMS.get(this.jweKeyAlgo));
		jwe.setEncryptionMethodHeaderParameter(
			ALGORITHMS.get(this.jweAlgo));
		jwe.setKey(this.getJWEKey(this.jweKey, this.jweKeyAlgo));
		if (isPayloadJWT) jwe.setContentTypeHeaderValue("JWT");
		jwe.setPayload(payload);
		return jwe.getCompactSerialization();
	}

	private Key getJWSKey(String key, String algo, String password) throws Exception {
		if ("HMAC_SHA256".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA256");
		} else if ("HMAC_SHA384".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA384");
		} else if ("HMAC_SHA512".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA512");
		} else if ("RSA_USING_SHA256".equals(algo)) {
			return getDERPrivateKeyFromPEM(key, password);
		} else if ("RSA_USING_SHA384".equals(algo)) {
			return getDERPrivateKeyFromPEM(key, password);
		} else if ("RSA_USING_SHA512".equals(algo)) {
			return getDERPrivateKeyFromPEM(key, password);
		}
		// TODO RSA with PSS, Elliptic curve, etc.
		
		return null;
	}

	private Key getJWEKey(String key, String algo) throws Exception {
		if ("A128GCMKW".equals(algo) || "A192GCMKW".equals(algo) || "A256GCMKW".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
		} else if ("A128KW".equals(algo) || "A192KW".equals(algo) || "A256KW".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
		} else if ("RSA_OAEP".equals(algo) || "RSA1_5".equals(algo)) {
			return getDERPublicKeyFromPEM(key);
		}
		// TODO other AES, RSA and EC variants
		
		return null;
	}

	// https://adangel.org/2016/08/29/openssl-rsa-java/
	private PublicKey getDERPublicKeyFromPEM(String key) throws Exception {
		try {
		    // strip of header, footer, newlines, whitespaces
		    String publicKeyPEM = key
		            .replace("-----BEGIN PUBLIC KEY-----", "")
		            .replace("-----END PUBLIC KEY-----", "")
		            .replaceAll("\\s", "");

		    // decode to get the binary DER representation
		    byte[] publicKeyDER = Base64.getDecoder().decode(publicKeyPEM);

		    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDER));
		    return publicKey;
		} catch (Exception e) {
			throw new InvalidConfig("Invalid JWE public key");
		}
	}

	private PrivateKey getDERPrivateKeyFromPEM(String key, String password) throws Exception {
		try {
		    PKCS8EncodedKeySpec p8eks = null;
			if (isEncrypted(key)) {
				p8eks = getEncodedPrivateKeySpec(key, password);
			} else {
				p8eks = getUnencodedPrivateKeySpec(key);
			}
			return KeyFactory.getInstance("RSA").generatePrivate(p8eks);
		} catch (Exception e) {
			throw new InvalidConfig("Invalid JWS private key");
		}
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

	private void setResult(String result, String reason, String jwt) {
		this.msgContext.setVariable(RESULT, result);
		this.msgContext.setVariable(REASON, reason);
		this.msgContext.setVariable(JWT, jwt);
	}

	private void debugMessage(String key, String message) {
		this.msgContext.setVariable(DEBUG_MESSAGE + key, key + "____" + message);
		this.msgContext.setVariable(DEBUG_MESSAGE, key + "____" + message);
	}

	private boolean isEmpty(String str) {
		return (str == null) || (str.length() == 0);
	}

	private String printMap(Map<String, String> map) {
		String result = "";
		for (Map.Entry entry : map.entrySet()) {
			result += entry.getKey() + "=" + entry.getValue() + "&";
		}
		return result;
	}

	private class InvalidConfig extends Exception { public InvalidConfig(String message) { super(message); } }

}

