package com.apigeecs.jwt;

import java.util.Map;
import java.util.HashMap;
import java.util.Base64;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;


public class JWTValidator implements Execution {

	private static String RESULT = "JWTValidatorResult";
	private static String RESULT_SUCCESS = "Success";
	private static String RESULT_FAILURE = "Failure";

	private static String REASON = "JWTValidatorReason";
	private static String REASON_VALID = "ValidToken";

	private static String DEBUG_MESSAGE = "JWTValidatorDebugMessage";

	private static String CLAIMS = "JWTValidatorClaims";
	private static String CLAIMS_NA = "NA";

	private static Map<String, String> ALGORITHMS = supportedAlgos();

	private Map<String, String> properties;
	private boolean jws;
	private String jwsKey;
	private String jwsAlgo;

	private boolean jwe;
	private String jweKey;
	private String jweKeyPassword;
	private String jweKeyAlgo;
	private String jweAlgo;

	private String jwt;
	private String issuer;
	private String audience;
	
	private MessageContext msgContext;
	private ExecutionContext execContext;

	public JWTValidator(Map<String, String> properties) {
		this.properties = properties;
	}

	public String toString() {
		return "jws=" + this.jws + ":" + 
		       "jwsKey=" + this.jwsKey + ":" + 
			   "jwsAlgo=" + this.jwsAlgo + ":" + 
			   "jwe=" + this.jwe + ":" + 
			   "jweKey=" + this.jweKey + ":" + 
			   "jweKeyPassowrd=" + this.jweKeyPassword + ":" + 
			   "jweKeyAlgo=" + this.jweKeyAlgo + ":" + 
			   "jweAlgo=" + this.jweAlgo + ":" + 
			   "jwt=" + this.jwt + ":" + 
			   "iss=" + this.issuer + ":" + 
			   "aud=" + this.audience;
	}

	public ExecutionResult execute(MessageContext msgContext, ExecutionContext execContext) {
		try {
			this.init(msgContext, execContext);
			this.validateProperties();
			String claimsJSON = this.verifyJWT();
			this.setResult(RESULT_SUCCESS, REASON_VALID, claimsJSON);
			return ExecutionResult.SUCCESS;
		} catch (Exception e) {
			this.setResult(RESULT_FAILURE, e.getMessage(), CLAIMS_NA);
			return ExecutionResult.ABORT;
		}
	}

	private void init(MessageContext msgContext, ExecutionContext execContext) throws Exception {
		this.msgContext = msgContext;
		this.execContext = execContext;

		this.jws = "true".equals(this.resolveVariable(this.properties.get("jws")));
		this.jwsAlgo = this.resolveVariable(this.properties.get("jws-algo"));
		this.jwsKey = this.resolveVariable(this.properties.get("jws-key"));

		this.jwe = "true".equals(this.resolveVariable(this.properties.get("jwe")));
		this.jweKey = this.resolveVariable(this.properties.get("jwe-key"));
		this.jweKeyPassword = this.resolveVariable(this.properties.get("jwe-key-pass"));
		this.jweKeyAlgo = this.resolveVariable(this.properties.get("jwe-key-algo"));
		this.jweAlgo = this.resolveVariable(this.properties.get("jwe-algo"));
		
		this.jwt = this.resolveVariable(this.properties.get("jwt"));
		this.issuer = this.resolveVariable(this.properties.get("iss"));
		this.audience = this.resolveVariable(this.properties.get("aud"));

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
		if (isEmpty(this.jwt)) {
			throw new InvalidConfig("Invalid JWT");
		}
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

	private String verifyJWT() throws Exception {
	    JwtConsumerBuilder builder = new JwtConsumerBuilder();
	    // Basics
	    builder.setRequireExpirationTime();
	    builder.setRequireSubject();

	    if (!isEmpty(this.issuer)) {
	    	builder.setExpectedIssuer(this.issuer);
	    }
	    if (!isEmpty(this.audience)) {
	    	builder.setExpectedAudience(this.audience);
	    }
	    if (this.jws) {
		    AlgorithmConstraints jwsAlgConstraints = 
			    new AlgorithmConstraints(ConstraintType.WHITELIST,ALGORITHMS.get(jwsAlgo));
			builder.setJwsAlgorithmConstraints(jwsAlgConstraints);

			builder.setVerificationKey(getJWSKey(this.jwsKey, this.jwsAlgo));
	    }
	    if (this.jwe) {
	    	if (!this.jws) {
	    		builder.setDisableRequireSignature();
	    	}
		    AlgorithmConstraints jweAlgConstraints = 
			    new AlgorithmConstraints(ConstraintType.WHITELIST, ALGORITHMS.get(jweKeyAlgo));
			builder.setJweAlgorithmConstraints(jweAlgConstraints);

		    AlgorithmConstraints jweEncConstraints = 
		    	new AlgorithmConstraints(ConstraintType.WHITELIST, ALGORITHMS.get(jweAlgo));
			builder.setJweContentEncryptionAlgorithmConstraints(jweEncConstraints);
			
			builder.setDecryptionKey(getJWEKey(this.jweKey, this.jweKeyAlgo, this.jweKeyPassword));
	    }

    	JwtConsumer jwtConsumer = builder.build();
        JwtClaims claims = jwtConsumer.processToClaims(jwt);
        return claims.toJson();
	}

	private Key getJWSKey(String key, String algo) throws Exception {
		if ("HMAC_SHA256".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA256");
		} else if ("HMAC_SHA384".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA384");
		} else if ("HMAC_SHA512".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA512");
		} else if ("RSA_USING_SHA256".equals(algo)) {
			return getDERPublicKeyFromPEM(key);
		} else if ("RSA_USING_SHA384".equals(algo)) {
			return getDERPublicKeyFromPEM(key);
		} else if ("RSA_USING_SHA512".equals(algo)) {
			return getDERPublicKeyFromPEM(key);
		}
		// TODO RSA with PSS, Elliptic curve, etc.
		return null;
	}

	private Key getJWEKey(String key, String algo, String password) throws Exception {
		if ("A128GCMKW".equals(algo) || "A192GCMKW".equals(algo) || "A256GCMKW".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
		} else if ("A128KW".equals(algo) || "A192KW".equals(algo) || "A256KW".equals(algo)) {
			return new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
		} else if ("RSA_OAEP".equals(algo) || "RSA1_5".equals(algo)) {
			return getDERPrivateKeyFromPEM(key, password);
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

	private void setResult(String result, String reason, String claims) {
		this.msgContext.setVariable(RESULT, result);
		this.msgContext.setVariable(REASON, reason);
		this.msgContext.setVariable(CLAIMS, claims);
		this.debugMessage("Claims", claims);
	}

	private void debugMessage(String key, String message) {
		this.msgContext.setVariable(DEBUG_MESSAGE + key, key + "____" + message);
		this.msgContext.setVariable(DEBUG_MESSAGE, key + "____" + message);
	}

	private static boolean isEmpty(String str) {
		return (str == null) || (str.length() == 0);
	}
	
	private String printMap(Map<String, String> map) {
		String result = "";
		for (Map.Entry entry : map.entrySet()) {
			result += entry.getKey() + "=" + entry.getValue() + "&";
		}
		return result;
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

	private class InvalidConfig extends Exception { public InvalidConfig(String message) { super(message); } }
}

