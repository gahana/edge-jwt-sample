package com.apigeecs.jwt;

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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import mockit.Mock;
import mockit.MockUp;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.MessageContext;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.MalformedClaimException;

public class JWTValidatorTest {

	private static String RESULT = "JWTValidatorResult";
	private static String RESULT_SUCCESS = "Success";
	private static String RESULT_FAILURE = "Failure";

	private static String REASON = "JWTValidatorReason";
	private static String REASON_VALID = "ValidToken";
	private static String REASON_ERROR = "ProcessingError";
	private static String REASON_INVALID_KEY = "InvalidKey";

	private static String JWT = "JWTValidatorJWT";
	private static String CLAIMS = "JWTValidatorClaims";

	private static String SAMPLE_CLAIMS = "{ \"sub\": \"abc xyz\", \"email\": \"abc@xyz.com\" }";
	private static String SHARED_KEY = "abcde12345";
	
	private static String PROPERTY_CLAIMS_JSON = "claims-json";
	private static String PROPERTY_JWT = "jwt";
	private static String PROPERTY_ISSUER = "iss";
	private static String PROPERTY_AUDIENCE = "aud";
	private static String PROPERTY_EXPIRY = "expiry";

	private static String PROPERTY_JWS = "jws";
	private static String PROPERTY_JWS_KEY = "jws-key";
	private static String PROPERTY_JWS_ALGO = "jws-algo";
	private static String PROPERTY_JWE = "jwe";
	private static String PROPERTY_JWE_KEY = "jwe-key";
	private static String PROPERTY_JWE_KEY_PASS = "jwe-key-pass";
	private static String PROPERTY_JWE_KEY_ALGO = "jwe-key-algo";
	private static String PROPERTY_JWE_ALGO = "jwe-algo";

	private static Map<String, String> ALGORITHMS = supportedAlgos();

	private MessageContext mctx;
	private ExecutionContext ectx;

	@Before
	public void setup() {
        this.mctx = mockMessageContext();
        this.ectx = mockExecutionContext();
	}

	@Test
	public void canary() {
		assertTrue(true);
	}	

	@Test
	public void testEmptyValidator() {
		JWTValidator validator = new JWTValidator(new HashMap<String, String>());
		ExecutionResult result = validator.execute(this.mctx, this.ectx);
		verifyFailureResult(result);
	}

	@Test
	public void testJWSNotEnabled() {
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_JWS_KEY, SHARED_KEY);
		properties.put(PROPERTY_JWS_ALGO, "HMAC_SHA256");
		properties.put(PROPERTY_JWT, "abcd.12345.xyz");
		JWTValidator validator = new JWTValidator(properties);
		ExecutionResult result = validator.execute(this.mctx, this.ectx);
		verifyFailureResult(result);
	}

	@Test
	public void testJWSWithSharedKeyHS256() {
		String claimsJSON = sampleClaims();
		SecretKey key = getHmacSHA256Key();
		String jwt = jwsSign(claimsJSON, key, "HMAC_SHA256");

		JWTValidator validator = jwsValidator(keyToString(key), "HMAC_SHA256", jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWSWithSharedKeyHS384() {
		String claimsJSON = sampleClaims();
		SecretKey key = getHmacSHA384Key();
		String jwt = jwsSign(claimsJSON, key, "HMAC_SHA384");

		JWTValidator validator = jwsValidator(keyToString(key), "HMAC_SHA384", jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWSWithSharedKeyHS512() {
		String claimsJSON = sampleClaims();
		SecretKey key = getHmacSHA512Key();
		String jwt = jwsSign(claimsJSON, key, "HMAC_SHA512");

		JWTValidator validator = jwsValidator(keyToString(key), "HMAC_SHA512", jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWSWithWrongAlgo() {
		String claimsJSON = sampleClaims();
		SecretKey key = getHmacSHA512Key();
		String jwt = jwsSign(claimsJSON, key, "HMAC_SHA512");

		JWTValidator validator = jwsValidator(keyToString(key), "HMAC_SHA256", jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifyFailureResult(result);
	}

	@Test
	public void testJWSWithExpiredJWT() {
		String claimsJSON = claims(SAMPLE_CLAIMS, "edge-jwt-gen", "aud-1", 0);
		SecretKey key = getHmacSHA512Key();
		String jwt = jwsSign(claimsJSON, key, "HMAC_SHA512");

		JWTValidator validator = jwsValidator(keyToString(key), "HMAC_SHA512", jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifyFailureResult(result);
	}

	@Test
	public void testJWSWithInvalidIssuer() {
		String claimsJSON = claims(SAMPLE_CLAIMS, "edge-jwt-gen", "aud-1", 300);
		SecretKey key = getHmacSHA512Key();
		String jwt = jwsSign(claimsJSON, key, "HMAC_SHA512");

		JWTValidator validator = jwsValidator(keyToString(key), "HMAC_SHA512", jwt, "edge-jwt-gen-2", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifyFailureResult(result);
	}

	@Test
	public void testJWSWithInvalidAudience() {
		String claimsJSON = claims(SAMPLE_CLAIMS, "edge-jwt-gen", "aud-1", 300);
		SecretKey key = getHmacSHA512Key();
		String jwt = jwsSign(claimsJSON, key, "HMAC_SHA512");

		JWTValidator validator = jwsValidator(keyToString(key), "HMAC_SHA512", jwt, "edge-jwt-gen", "aud-2", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifyFailureResult(result);
	}

	@Test
	public void testJWSWithInvalidJWT() {
		String claimsJSON = sampleClaims();
		SecretKey key = getHmacSHA512Key();
		String jwt = jwsSign(claimsJSON, key, "HMAC_SHA512");

		JWTValidator validator = jwsValidator(keyToString(key), "HMAC_SHA512", jwt.substring(0, jwt.length() - 1), "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifyFailureResult(result);
	}

	@Test
	public void testJWSWithRSAKeyRS256() {
		String claimsJSON = sampleClaims();
		KeyPair rsaKeyPair = getRSAKeyPair();
		String jwt = jwsSign(claimsJSON, rsaKeyPair.getPrivate(), "RSA_USING_SHA256");
		String pemPublicKey = getPEMPublicKeyFromDER(rsaKeyPair.getPublic());
		
		JWTValidator validator = jwsValidator(pemPublicKey, "RSA_USING_SHA256", jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWSWithRSAKeyRS384() {
		String claimsJSON = sampleClaims();
		KeyPair rsaKeyPair = getRSAKeyPair();
		String jwt = jwsSign(claimsJSON, rsaKeyPair.getPrivate(), "RSA_USING_SHA384");
		String pemPublicKey = getPEMPublicKeyFromDER(rsaKeyPair.getPublic());
		
		JWTValidator validator = jwsValidator(pemPublicKey, "RSA_USING_SHA384", jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWSWithRSAKeyRS512() {
		String claimsJSON = sampleClaims();
		KeyPair rsaKeyPair = getRSAKeyPair();
		String jwt = jwsSign(claimsJSON, rsaKeyPair.getPrivate(), "RSA_USING_SHA512");
		String pemPublicKey = getPEMPublicKeyFromDER(rsaKeyPair.getPublic());
		
		JWTValidator validator = jwsValidator(pemPublicKey, "RSA_USING_SHA512", jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWENotEnabled() {
		String claimsJSON = sampleClaims();
		SecretKey secretKey = getAESKey(128);
		String jwt = jweEncrypt(claimsJSON, false, secretKey, "A128GCMKW", "AES_128_CBC_HMAC_SHA_256");

		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_JWE_KEY, keyToString(secretKey));
		properties.put(PROPERTY_JWE_KEY_ALGO, "A128GCMKW");
		properties.put(PROPERTY_JWE_ALGO, "AES_128_CBC_HMAC_SHA_256");
		properties.put(PROPERTY_JWT, jwt);
		JWTValidator validator = new JWTValidator(properties);
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifyFailureResult(result);
	}

	@Test
	public void testJWEWithAESAESKey1() {
		String claimsJSON = sampleClaims();
		SecretKey secretKey = getAESKey(128);
		String jwt = jweEncrypt(claimsJSON, false, secretKey, "A128GCMKW", "AES_128_CBC_HMAC_SHA_256");

		JWTValidator validator = 
			jweValidator(
				keyToString(secretKey), "A128GCMKW", "AES_128_CBC_HMAC_SHA_256", 
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWEWithAESAESKey2() {
		String claimsJSON = sampleClaims();
		SecretKey secretKey = getAESKey(128);
		String jwt = jweEncrypt(claimsJSON, false, secretKey, "A128GCMKW", "AES_128_GCM");

		JWTValidator validator = 
			jweValidator(
				keyToString(secretKey), "A128GCMKW", "AES_128_GCM", 
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWEWithAESAESAESKey3() {
		String claimsJSON = sampleClaims();
		SecretKey secretKey = getAESKey(128);
		String jwt = jweEncrypt(claimsJSON, false, secretKey, "A128KW", "AES_128_CBC_HMAC_SHA_256");

		JWTValidator validator = 
			jweValidator(
				keyToString(secretKey), "A128KW", "AES_128_CBC_HMAC_SHA_256", 
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWEWithAESAESKey4() {
		String claimsJSON = sampleClaims();
		SecretKey secretKey = getAESKey(128);
		String jwt = jweEncrypt(claimsJSON, false, secretKey, "A128KW", "AES_128_GCM");

		JWTValidator validator = 
			jweValidator(
				keyToString(secretKey), "A128KW", "AES_128_GCM", 
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWEWithRSAAESKey1() {
		String claimsJSON = sampleClaims();
		KeyPair rsaKeyPair = getRSAKeyPair();
		String jwt = jweEncrypt(claimsJSON, false, rsaKeyPair.getPublic(), "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256");
		String pemPrivateKey = getPEMPrivateKeyFromDER(rsaKeyPair.getPrivate());

		JWTValidator validator = 
			jweValidator(
				pemPrivateKey, "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256", 
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWEWithRSAAESKey2() {
		String claimsJSON = sampleClaims();
		KeyPair rsaKeyPair = getRSAKeyPair();
		String jwt = jweEncrypt(claimsJSON, false, rsaKeyPair.getPublic(), "RSA_OAEP", "AES_128_GCM");
		String pemPrivateKey = getPEMPrivateKeyFromDER(rsaKeyPair.getPrivate());

		JWTValidator validator = 
			jweValidator(
				pemPrivateKey, "RSA_OAEP", "AES_128_GCM", 
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWEAndJWSWithRSAAndRSA() {
		String claimsJSON = sampleClaims();
		KeyPair rsaKeyPairSign = getRSAKeyPair();
		String pemPublicKeySign = getPEMPublicKeyFromDER(rsaKeyPairSign.getPublic());
		KeyPair rsaKeyPairEnc = getRSAKeyPair();
		String pemPrivateKeyEnc = getPEMPrivateKeyFromDER(rsaKeyPairEnc.getPrivate());
		
		String innerJWT = jwsSign(claimsJSON, rsaKeyPairSign.getPrivate(), "RSA_USING_SHA256");
		String jwt = jweEncrypt(innerJWT, true, rsaKeyPairEnc.getPublic(), "RSA_OAEP", "AES_128_GCM");

		JWTValidator validator = 
			validatorJWSAndJWE(
				pemPublicKeySign, "RSA_USING_SHA256",
				pemPrivateKeyEnc, "RSA_OAEP", "AES_128_GCM", 
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWEAndJWSWithRSAAndHMAC() {
		String claimsJSON = sampleClaims();
		SecretKey keySign = getHmacSHA256Key();
		KeyPair rsaKeyPairEnc = getRSAKeyPair();
		String pemPrivateKeyEnc = getPEMPrivateKeyFromDER(rsaKeyPairEnc.getPrivate());
		
		String innerJWT = jwsSign(claimsJSON, keySign, "HMAC_SHA256");
		String jwt = jweEncrypt(innerJWT, true, rsaKeyPairEnc.getPublic(), "RSA_OAEP", "AES_128_GCM");

		JWTValidator validator = 
			validatorJWSAndJWE(
				keyToString(keySign), "HMAC_SHA256",
				pemPrivateKeyEnc, "RSA_OAEP", "AES_128_GCM", 
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWSWithEncryptedPrivateKey() {
		String pemPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----MIIE6TAbBgkqhkiG9w0BBQMwDgQIh52IJa6i0TACAggABIIEyAKXYcajrZWfvvH3eCRtMgGn4v0MaH39hYnYLF3Y3AyEJDkCPJ9jVzK1LBhYpe2kl7JFVfI8uR+ofNxD4xTRrevWrq4ejtI1eL1e+38Y68wVf389W5t2KGxTEltiiOBd6l2ANon5nAPE8IL6VfF38FGbgSIvMER33j0tjAKHumd817qj9QqIyIOD8H959JZZ+QlfaIvPFrtzvAwjQBjyGgr8XybVHUdT+9XAUrFCMMREKDGW2CaO94JI4Ca6noL9KT4L57vbXa2zYeEKyr2Bnpni27Qvb/a0I8Eml2GLC6fM/ZDOgi8RoYyMtyhaHTYPAy0oRAL2w3WjO7iomw7d6WKqqnATAn40T9rRK7anvbyv6kMxM6kwaQOfjCR/3tgrlVC2Q5MNnsBvsxUpKlg81GL++xZoTXw6znuaY5DCBNNj7CRSES/taE2PrDxy/2wv6UwVlwznqj1GPmCC4ri5Y7M1RhtlbTFaPC18wapG34rAeg2RJ22/oJmGbQv/m/nOxnUXqYjTX5T6oOxCmBQbUTOOVETbFcHrDptvntQ9hakMl9OhtnhhRqkYwSfvvRTa+cAq/Cbp+RI1hURTmL4gp0/qMFljNSWbGfPSIwKyJcvvgmPkSYDtV0m1t25RNiaCiMdmD0GR/68sWvtL09PI/Cn4eK4oV2wF9qvF5R4YkFgWZvg73yyepeuXfe6PeDOQSJp3mYDzwgiy1Dpt96QRPgGHYJJk5Z6+jv4KX45NTuXrZl/WXP4bOcQUDAc/ezJaanUeQxfsR2enGoVkWJmo12CnK6ZgyVRXG7G/0AxmANnhO7rB6i8K1aGl3jZqOnYilI7fw44bl1TMqEyNG8F9GTfGKoEn0vJq0v4kbznGVHCkxSZI0uzHPnt8CgRnz3CWfSecv9slf3z6rVMJesF1JLy7CeYclB0G5EBW/PsvqpbMDZQYC+iZNnS+KGdTt4cq9WWudkJrs2Ge+jAJHVTvUSXWbJTOflavkBqqaheSMlr72bZj0KjMkaEuSCKNluN06FU//gnE5oxstAnaLacJUHpHSaOb2GNRNCoO60lTPvFtTWNJTr4rGTIC3xAFCspiNiqJZ/R9BqYxAxzHNP0/fNPth8r6tLYcmLbWNrupvPYsj16lX1g4hBHAy49LOZf7WwP5bSVDNmC5C3LJ5JMF+cuk3dg5HjWLmolUzRqZ1NZEHgcv6k6Wm5jcJj+xLgp/RS7K6l/DSlcFCoPsq4RI9Og7jCqujr41zz0DkiSjz1X8eQIgC1zGacquCcUXJ0cLSevxHuZoQJlxijSklR5k6m7qIKEGpJS9J8SMRWpr26mMZ22VEwtPewuVjtxIpyJhpk/MfMZeyvOQMaZ486OC2kyz7G/dH9AlRthtotC/Ae5+qLmI05so1O0xGV1HzCpt4p8xg6Tc7AP3GWkPEjsUBw8MZl0iqe6IKEP7M+299RQacARudqgOEP+ghp0ASKiyw3cKLl//CZtlUUo4ryDxOQONDCG5M0S/TmLoi6Sih8xuMww8CPWi62Lc4rkClxRgVSHIp0MnWkuipMhB5J7ONNyM6G2UffSd/zmB5lNPdAPGc5GIYr1LryJ9tlwjrq4rF05sAGNsjy2rqeWVW+LYGyOFpSq91QC+6w==-----END ENCRYPTED PRIVATE KEY-----";
		String pemPublicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoE/tMVvp1JqQ/1eGATl1aq+ciUXrGJ8yekFh6F4QhcModrQb15ojvbaQ11ZseLu3tswsdMP5oLKe9ZtvRWAhYX1APINo1sCQBYQZNf9L015iCYSYDCQucRziLWk4K+QXYG7sZIA/8Gb/rbamtBLho16UNaAzkbrR7+rdrRyCyDeyQ9tIfOnSPmjiP0o705sybRs86cfbgOg6yUG3WEU/v5mhg+g+zM3R1nMIgyE1QEKM9zgwvbbR0IkN3L5N0XJFWvR0XNEes5XTHPmh0O6PI4m6vic1UhwyWFy513p4e0tRAIKeU9pCDT1HFTHWPX2gKB9RcuEFxSxczXCc6RCPwIDAQAB-----END PUBLIC KEY-----";
		PublicKey publicKey = getDERPublicKeyFromPEM(pemPublicKey);

		String claimsJSON = sampleClaims();
		String jwt = jwsSign(claimsJSON, getDERPrivateKeyFromPEM(pemPrivateKey, "123"), "RSA_USING_SHA256");
		JWTValidator validator = jwsValidator(pemPublicKey, "RSA_USING_SHA256", jwt, "edge-jwt-gen", "aud-1", "300");

		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWEWithEncryptedPrivateKey() {		
		String pemPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----MIIE6TAbBgkqhkiG9w0BBQMwDgQIh52IJa6i0TACAggABIIEyAKXYcajrZWfvvH3eCRtMgGn4v0MaH39hYnYLF3Y3AyEJDkCPJ9jVzK1LBhYpe2kl7JFVfI8uR+ofNxD4xTRrevWrq4ejtI1eL1e+38Y68wVf389W5t2KGxTEltiiOBd6l2ANon5nAPE8IL6VfF38FGbgSIvMER33j0tjAKHumd817qj9QqIyIOD8H959JZZ+QlfaIvPFrtzvAwjQBjyGgr8XybVHUdT+9XAUrFCMMREKDGW2CaO94JI4Ca6noL9KT4L57vbXa2zYeEKyr2Bnpni27Qvb/a0I8Eml2GLC6fM/ZDOgi8RoYyMtyhaHTYPAy0oRAL2w3WjO7iomw7d6WKqqnATAn40T9rRK7anvbyv6kMxM6kwaQOfjCR/3tgrlVC2Q5MNnsBvsxUpKlg81GL++xZoTXw6znuaY5DCBNNj7CRSES/taE2PrDxy/2wv6UwVlwznqj1GPmCC4ri5Y7M1RhtlbTFaPC18wapG34rAeg2RJ22/oJmGbQv/m/nOxnUXqYjTX5T6oOxCmBQbUTOOVETbFcHrDptvntQ9hakMl9OhtnhhRqkYwSfvvRTa+cAq/Cbp+RI1hURTmL4gp0/qMFljNSWbGfPSIwKyJcvvgmPkSYDtV0m1t25RNiaCiMdmD0GR/68sWvtL09PI/Cn4eK4oV2wF9qvF5R4YkFgWZvg73yyepeuXfe6PeDOQSJp3mYDzwgiy1Dpt96QRPgGHYJJk5Z6+jv4KX45NTuXrZl/WXP4bOcQUDAc/ezJaanUeQxfsR2enGoVkWJmo12CnK6ZgyVRXG7G/0AxmANnhO7rB6i8K1aGl3jZqOnYilI7fw44bl1TMqEyNG8F9GTfGKoEn0vJq0v4kbznGVHCkxSZI0uzHPnt8CgRnz3CWfSecv9slf3z6rVMJesF1JLy7CeYclB0G5EBW/PsvqpbMDZQYC+iZNnS+KGdTt4cq9WWudkJrs2Ge+jAJHVTvUSXWbJTOflavkBqqaheSMlr72bZj0KjMkaEuSCKNluN06FU//gnE5oxstAnaLacJUHpHSaOb2GNRNCoO60lTPvFtTWNJTr4rGTIC3xAFCspiNiqJZ/R9BqYxAxzHNP0/fNPth8r6tLYcmLbWNrupvPYsj16lX1g4hBHAy49LOZf7WwP5bSVDNmC5C3LJ5JMF+cuk3dg5HjWLmolUzRqZ1NZEHgcv6k6Wm5jcJj+xLgp/RS7K6l/DSlcFCoPsq4RI9Og7jCqujr41zz0DkiSjz1X8eQIgC1zGacquCcUXJ0cLSevxHuZoQJlxijSklR5k6m7qIKEGpJS9J8SMRWpr26mMZ22VEwtPewuVjtxIpyJhpk/MfMZeyvOQMaZ486OC2kyz7G/dH9AlRthtotC/Ae5+qLmI05so1O0xGV1HzCpt4p8xg6Tc7AP3GWkPEjsUBw8MZl0iqe6IKEP7M+299RQacARudqgOEP+ghp0ASKiyw3cKLl//CZtlUUo4ryDxOQONDCG5M0S/TmLoi6Sih8xuMww8CPWi62Lc4rkClxRgVSHIp0MnWkuipMhB5J7ONNyM6G2UffSd/zmB5lNPdAPGc5GIYr1LryJ9tlwjrq4rF05sAGNsjy2rqeWVW+LYGyOFpSq91QC+6w==-----END ENCRYPTED PRIVATE KEY-----";
		String pemPublicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoE/tMVvp1JqQ/1eGATl1aq+ciUXrGJ8yekFh6F4QhcModrQb15ojvbaQ11ZseLu3tswsdMP5oLKe9ZtvRWAhYX1APINo1sCQBYQZNf9L015iCYSYDCQucRziLWk4K+QXYG7sZIA/8Gb/rbamtBLho16UNaAzkbrR7+rdrRyCyDeyQ9tIfOnSPmjiP0o705sybRs86cfbgOg6yUG3WEU/v5mhg+g+zM3R1nMIgyE1QEKM9zgwvbbR0IkN3L5N0XJFWvR0XNEes5XTHPmh0O6PI4m6vic1UhwyWFy513p4e0tRAIKeU9pCDT1HFTHWPX2gKB9RcuEFxSxczXCc6RCPwIDAQAB-----END PUBLIC KEY-----";
		PublicKey publicKey = getDERPublicKeyFromPEM(pemPublicKey);

		String claimsJSON = sampleClaims();
		String jwt = jweEncrypt(claimsJSON, false, publicKey, "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256");

		JWTValidator validator = 
			jweValidator(
				pemPrivateKey, "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256", "123",
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		varifyClaims(this.mctx.getVariable(CLAIMS));
	}

	@Test
	public void testJWEWithEncryptedPrivateKeyAndWrongPassword() {		
		String pemPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----MIIE6TAbBgkqhkiG9w0BBQMwDgQIh52IJa6i0TACAggABIIEyAKXYcajrZWfvvH3eCRtMgGn4v0MaH39hYnYLF3Y3AyEJDkCPJ9jVzK1LBhYpe2kl7JFVfI8uR+ofNxD4xTRrevWrq4ejtI1eL1e+38Y68wVf389W5t2KGxTEltiiOBd6l2ANon5nAPE8IL6VfF38FGbgSIvMER33j0tjAKHumd817qj9QqIyIOD8H959JZZ+QlfaIvPFrtzvAwjQBjyGgr8XybVHUdT+9XAUrFCMMREKDGW2CaO94JI4Ca6noL9KT4L57vbXa2zYeEKyr2Bnpni27Qvb/a0I8Eml2GLC6fM/ZDOgi8RoYyMtyhaHTYPAy0oRAL2w3WjO7iomw7d6WKqqnATAn40T9rRK7anvbyv6kMxM6kwaQOfjCR/3tgrlVC2Q5MNnsBvsxUpKlg81GL++xZoTXw6znuaY5DCBNNj7CRSES/taE2PrDxy/2wv6UwVlwznqj1GPmCC4ri5Y7M1RhtlbTFaPC18wapG34rAeg2RJ22/oJmGbQv/m/nOxnUXqYjTX5T6oOxCmBQbUTOOVETbFcHrDptvntQ9hakMl9OhtnhhRqkYwSfvvRTa+cAq/Cbp+RI1hURTmL4gp0/qMFljNSWbGfPSIwKyJcvvgmPkSYDtV0m1t25RNiaCiMdmD0GR/68sWvtL09PI/Cn4eK4oV2wF9qvF5R4YkFgWZvg73yyepeuXfe6PeDOQSJp3mYDzwgiy1Dpt96QRPgGHYJJk5Z6+jv4KX45NTuXrZl/WXP4bOcQUDAc/ezJaanUeQxfsR2enGoVkWJmo12CnK6ZgyVRXG7G/0AxmANnhO7rB6i8K1aGl3jZqOnYilI7fw44bl1TMqEyNG8F9GTfGKoEn0vJq0v4kbznGVHCkxSZI0uzHPnt8CgRnz3CWfSecv9slf3z6rVMJesF1JLy7CeYclB0G5EBW/PsvqpbMDZQYC+iZNnS+KGdTt4cq9WWudkJrs2Ge+jAJHVTvUSXWbJTOflavkBqqaheSMlr72bZj0KjMkaEuSCKNluN06FU//gnE5oxstAnaLacJUHpHSaOb2GNRNCoO60lTPvFtTWNJTr4rGTIC3xAFCspiNiqJZ/R9BqYxAxzHNP0/fNPth8r6tLYcmLbWNrupvPYsj16lX1g4hBHAy49LOZf7WwP5bSVDNmC5C3LJ5JMF+cuk3dg5HjWLmolUzRqZ1NZEHgcv6k6Wm5jcJj+xLgp/RS7K6l/DSlcFCoPsq4RI9Og7jCqujr41zz0DkiSjz1X8eQIgC1zGacquCcUXJ0cLSevxHuZoQJlxijSklR5k6m7qIKEGpJS9J8SMRWpr26mMZ22VEwtPewuVjtxIpyJhpk/MfMZeyvOQMaZ486OC2kyz7G/dH9AlRthtotC/Ae5+qLmI05so1O0xGV1HzCpt4p8xg6Tc7AP3GWkPEjsUBw8MZl0iqe6IKEP7M+299RQacARudqgOEP+ghp0ASKiyw3cKLl//CZtlUUo4ryDxOQONDCG5M0S/TmLoi6Sih8xuMww8CPWi62Lc4rkClxRgVSHIp0MnWkuipMhB5J7ONNyM6G2UffSd/zmB5lNPdAPGc5GIYr1LryJ9tlwjrq4rF05sAGNsjy2rqeWVW+LYGyOFpSq91QC+6w==-----END ENCRYPTED PRIVATE KEY-----";
		String pemPublicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoE/tMVvp1JqQ/1eGATl1aq+ciUXrGJ8yekFh6F4QhcModrQb15ojvbaQ11ZseLu3tswsdMP5oLKe9ZtvRWAhYX1APINo1sCQBYQZNf9L015iCYSYDCQucRziLWk4K+QXYG7sZIA/8Gb/rbamtBLho16UNaAzkbrR7+rdrRyCyDeyQ9tIfOnSPmjiP0o705sybRs86cfbgOg6yUG3WEU/v5mhg+g+zM3R1nMIgyE1QEKM9zgwvbbR0IkN3L5N0XJFWvR0XNEes5XTHPmh0O6PI4m6vic1UhwyWFy513p4e0tRAIKeU9pCDT1HFTHWPX2gKB9RcuEFxSxczXCc6RCPwIDAQAB-----END PUBLIC KEY-----";
		PublicKey publicKey = getDERPublicKeyFromPEM(pemPublicKey);

		String claimsJSON = sampleClaims();
		String jwt = jweEncrypt(claimsJSON, false, publicKey, "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256");

		JWTValidator validator = 
			jweValidator(
				pemPrivateKey, "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256", "1234",
				jwt, "edge-jwt-gen", "aud-1", "300");
		ExecutionResult result = validator.execute(this.mctx, this.ectx);

		verifyFailureResult(result);
	}

	// ------------- BEGIN SPECIAL TESTS -------------
	
	// BELOW TESTS INVOLVE AES256 AND BECAUSE OF THE LARGE KEY SIZE MAKE SURE YOU HAVE INSTALLED THE 
	// JAVA CRYPTOGRAPHY EXTENSION (JCE) UNLIMITED STRENGTH JURISDICTION POLICY FILES
	// HTTP://WWW.ORACLE.COM/TECHNETWORK/JAVA/JAVASE/DOWNLOADS/JCE-7-DOWNLOAD-432124.HTML

	// @Test
	// public void testJWEWithRSAAESAESKey3() {
	// 	String claimsJSON = sampleClaims();
	// 	KeyPair rsaKeyPair = getRSAKeyPair();
	// 	String jwt = jweEncrypt(claimsJSON, false, rsaKeyPair.getPublic(), "RSA1_5", "AES_256_CBC_HMAC_SHA_512");
	// 	String pemPrivateKey = getPEMPrivateKeyFromDER(rsaKeyPair.getPrivate());

	// 	JWTValidator validator = 
	// 		jweValidator(
	// 			pemPrivateKey, "RSA1_5", "AES_256_CBC_HMAC_SHA_512", 
	// 			jwt, "edge-jwt-gen", "aud-1", "300");
	// 	ExecutionResult result = validator.execute(this.mctx, this.ectx);

	// 	verifySuccessResult(result);
	// 	varifyClaims(this.mctx.getVariable(CLAIMS));
	// }

	// @Test
	// public void testJWEWithRSAAESKey4() {
	// 	String claimsJSON = sampleClaims();
	// 	KeyPair rsaKeyPair = getRSAKeyPair();
	// 	String jwt = jweEncrypt(claimsJSON, false, rsaKeyPair.getPublic(), "RSA1_5", "AES_256_GCM");
	// 	String pemPrivateKey = getPEMPrivateKeyFromDER(rsaKeyPair.getPrivate());

	// 	JWTValidator validator = 
	// 		jweValidator(
	// 			pemPrivateKey, "RSA1_5", "AES_256_GCM", 
	// 			jwt, "edge-jwt-gen", "aud-1", "300");
	// 	ExecutionResult result = validator.execute(this.mctx, this.ectx);

	// 	verifySuccessResult(result);
	// 	varifyClaims(this.mctx.getVariable(CLAIMS));
	// }

	// @Test
	// public void testJWEAndJWSWithRSAAndHMAC2() {
	// 	String claimsJSON = sampleClaims();
	// 	SecretKey keySign = getHmacSHA512Key();
	// 	KeyPair rsaKeyPairEnc = getRSAKeyPair();
	// 	String pemPrivateKeyEnc = getPEMPrivateKeyFromDER(rsaKeyPairEnc.getPrivate());

	// 	System.out.println("HMAC Key: " + keyToString(keySign));
	// 	System.out.println("Enc Public Key: " + getPEMPublicKeyFromDER(rsaKeyPairEnc.getPublic()));
	// 	System.out.println("Enc Private Key: " + pemPrivateKeyEnc);
		
	// 	String innerJWT = jwsSign(claimsJSON, keySign, "HMAC_SHA512");
	// 	String jwt = jweEncrypt(innerJWT, true, rsaKeyPairEnc.getPublic(), "RSA_OAEP", "AES_256_CBC_HMAC_SHA_512");

	// 	JWTValidator validator = 
	// 		validatorJWSAndJWE(
	// 			keyToString(keySign), "HMAC_SHA512",
	// 			pemPrivateKeyEnc, "RSA_OAEP", "AES_256_CBC_HMAC_SHA_512", 
	// 			jwt, "edge-jwt-gen", "aud-1", "300");
	// 	ExecutionResult result = validator.execute(this.mctx, this.ectx);

	// 	verifySuccessResult(result);
	// 	varifyClaims(this.mctx.getVariable(CLAIMS));
	// }

	// ------------- END SPECIAL TESTS -------------

	private MessageContext mockMessageContext() {
		return new MockUp<MessageContext>() {
            private Map<String, String> variables = new HashMap<String, String>();
            @Mock public String getVariable(String name) {
                return variables.get(name);
            }
            @Mock public boolean setVariable(String name, Object value) {
                variables.put(name, (String) value);
                return true;
            }
            @Mock public boolean removeVariable(String name) {
                if (variables.containsKey(name)) {
                    variables.remove(name);
                }
                return true;
            }
        }.getMockInstance();
	}

	private ExecutionContext mockExecutionContext() {
		return new MockUp<ExecutionContext>(){ }.getMockInstance();
	}

	private String sampleClaims() {
	    return claims(SAMPLE_CLAIMS, "edge-jwt-gen", "aud-1", 300);
	}

	private String claims(String claimsJSON, String iss, String aud, int expiry) {
		try {
			JwtClaims claims = JwtClaims.parse(claimsJSON);
			claims.setIssuer(iss);
			claims.setAudience(aud);
			claims.setExpirationTimeMinutesInTheFuture(expiry);
			claims.setGeneratedJwtId();
			claims.setIssuedAtToNow();
			claims.setNotBeforeMinutesInThePast(2);
			return claims.toJson();
		} catch (Exception e) {
			return null;
		}
	}

	private String jwsSign(String claimsJSON, Key key, String algo) {
		try {
			JsonWebSignature jws = new JsonWebSignature();
			jws.setPayload(claimsJSON);
			jws.setAlgorithmHeaderValue(ALGORITHMS.get(algo));
			jws.setKey(key);
			return jws.getCompactSerialization();
		} catch (Exception e) {
			fail();
			return null;
		}
	}

	private String jweEncrypt(String payload, boolean isJWT, Key key, String keyAlgo, String jweAlgo) {
		try {
			JsonWebEncryption jwe = new JsonWebEncryption();
			jwe.setAlgorithmHeaderValue(ALGORITHMS.get(keyAlgo));
			jwe.setEncryptionMethodHeaderParameter(ALGORITHMS.get(jweAlgo));
			jwe.setKey(key);
			if (isJWT) jwe.setContentTypeHeaderValue("JWT");
			jwe.setPayload(payload);
			return jwe.getCompactSerialization();
		} catch (Exception e) {
			fail();
			return null;
		}
	}

	// https://adangel.org/2016/08/29/openssl-rsa-java/
	private PublicKey getDERPublicKeyFromPEM(String key) {
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
			return null;
		}
	}

	private PrivateKey getDERPrivateKeyFromPEM(String key, String password) {
		try {
		    PKCS8EncodedKeySpec p8eks = null;
			if (isEncrypted(key)) {
				p8eks = getEncodedPrivateKeySpec(key, password);
			} else {
				p8eks = getUnencodedPrivateKeySpec(key);
			}
			return KeyFactory.getInstance("RSA").generatePrivate(p8eks);
		} catch (Exception e) {
			return null;
		}
	}

	public PKCS8EncodedKeySpec getEncodedPrivateKeySpec(String key, String password) throws Exception {
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

	public PKCS8EncodedKeySpec getUnencodedPrivateKeySpec(String key) throws Exception {
	    // strip of header, footer, newlines, whitespaces
	    String privateKeyPEM = key
	            .replace("-----BEGIN PRIVATE KEY-----", "")
	            .replace("-----END PRIVATE KEY-----", "")
	            .replaceAll("\\s", "");

	    // decode to get the binary DER representation
	    byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

	    return new PKCS8EncodedKeySpec(privateKeyDER);
	}

	private boolean isEncrypted(String key) {
		return key.indexOf("-----BEGIN ENCRYPTED PRIVATE KEY-----") != -1;
	}

	private JWTValidator jwsValidator(String key, String algo, String jwt, String iss, String aud, String expiry) {
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_JWS, "true");
		properties.put(PROPERTY_JWS_KEY, key);
		properties.put(PROPERTY_JWS_ALGO, algo);
		properties.put(PROPERTY_JWT, jwt);
		properties.put(PROPERTY_ISSUER, iss);
		properties.put(PROPERTY_AUDIENCE, aud);
		properties.put(PROPERTY_EXPIRY, expiry);
		return new JWTValidator(properties);
	}

	private Map<String, String> getDefaultJWEProperties(String key, String keyAlgo, String jweAlgo, String jwt, String iss, String aud, String expiry) {
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_JWE, "true");
		properties.put(PROPERTY_JWE_KEY, key);
		properties.put(PROPERTY_JWE_KEY_ALGO, keyAlgo);
		properties.put(PROPERTY_JWE_ALGO, jweAlgo);
		properties.put(PROPERTY_JWT, jwt);
		properties.put(PROPERTY_ISSUER, iss);
		properties.put(PROPERTY_AUDIENCE, aud);
		properties.put(PROPERTY_EXPIRY, expiry);
		return properties;
	}

	private JWTValidator jweValidator(String key, String keyAlgo, String jweAlgo, String password, String jwt, String iss, String aud, String expiry) {
		Map<String, String> properties = getDefaultJWEProperties(key, keyAlgo, jweAlgo, jwt, iss, aud, expiry);
		properties.put(PROPERTY_JWE_KEY_PASS, password);
		return new JWTValidator(properties);
	}

	private JWTValidator jweValidator(String key, String keyAlgo, String jweAlgo, String jwt, String iss, String aud, String expiry) {
		return new JWTValidator(getDefaultJWEProperties(key, keyAlgo, jweAlgo, jwt, iss, aud, expiry));
	}

	private JWTValidator validatorJWSAndJWE(String jwsKey, String jwsAlgo, String jweKey, String jweKeyAlgo, String jweAlgo, String jwt, String iss, String aud, String expiry) {
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_JWS, "true");
		properties.put(PROPERTY_JWS_KEY, jwsKey);
		properties.put(PROPERTY_JWS_ALGO, jwsAlgo);
		properties.put(PROPERTY_JWE, "true");
		properties.put(PROPERTY_JWE_KEY, jweKey);
		properties.put(PROPERTY_JWE_KEY_ALGO, jweKeyAlgo);
		properties.put(PROPERTY_JWE_ALGO, jweAlgo);
		properties.put(PROPERTY_JWT, jwt);
		properties.put(PROPERTY_ISSUER, iss);
		properties.put(PROPERTY_AUDIENCE, aud);
		properties.put(PROPERTY_EXPIRY, expiry);
		return new JWTValidator(properties);
	}


	private void verifySuccessResult(ExecutionResult result) {
		System.out.println(this.mctx.getVariable(REASON).toString());
		assertEquals(ExecutionResult.SUCCESS, result);
		assertEquals(RESULT_SUCCESS, this.mctx.getVariable(RESULT));
	}

	private void verifyFailureResult(ExecutionResult result) {
		System.out.println(this.mctx.getVariable(REASON).toString());
		assertEquals(ExecutionResult.ABORT, result);
		assertEquals(RESULT_FAILURE, this.mctx.getVariable(RESULT));
	}

	private void varifyClaims(String claimsJSON) {
		try {
			JwtClaims claims = JwtClaims.parse(claimsJSON);
			assertEquals("abc xyz", claims.getSubject());
			assertEquals("abc@xyz.com", claims.getClaimValue("email"));
		} catch (Exception e) {
			fail();
		}
	}

	private KeyPair getRSAKeyPair() {
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

	private static String getPEMPublicKeyFromDER(PublicKey publicKey) {
		String begin = "-----BEGIN PUBLIC KEY-----";
		String end = "-----END PUBLIC KEY-----";
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		String key = Base64.getEncoder().encodeToString(x509EncodedKeySpec.getEncoded());
		return begin + "\n" + key + "\n" + end;
	}

	private static String getPEMPrivateKeyFromDER(PrivateKey privateKey) {
		String begin = "-----BEGIN PRIVATE KEY-----";
		String end = "-----END PRIVATE KEY-----";
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		String key = Base64.getEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded());
		return begin + "\n" + key + "\n" + end;
	}

	private SecretKey getAESKey(int bits) {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(bits);
			return keyGen.generateKey();
		} catch (Exception e) {
			return null;
		}
	}

	private SecretKey getHMACKey(String algo) {
		try {
			return KeyGenerator.getInstance(algo).generateKey();
		} catch (Exception e) {
			return null;
		}
	}

	private SecretKey getHmacSHA256Key() {
		return getHMACKey("HmacSHA256");
	}

	private SecretKey getHmacSHA384Key() {
		return getHMACKey("HmacSHA384");
	}

	private SecretKey getHmacSHA512Key() {
		return getHMACKey("HmacSHA512");
	}

	private String keyToString(SecretKey key) {
		return Base64.getEncoder().encodeToString(key.getEncoded());
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

}