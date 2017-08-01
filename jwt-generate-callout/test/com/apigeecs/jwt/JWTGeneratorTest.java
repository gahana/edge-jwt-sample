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

public class JWTGeneratorTest {

	private static String RESULT = "JWTGeneratorResult";
	private static String RESULT_SUCCESS = "Success";
	private static String RESULT_FAILURE = "Failure";

	private static String REASON = "JWTGeneratorReason";
	private static String REASON_VALID = "ValidToken";
	private static String REASON_ERROR = "ProcessingError";
	private static String REASON_INVALID_KEY = "InvalidKey";

	private static String JWT = "JWTGeneratorJWT";

	private static String SAMPLE_CLAIMS = "{ \"sub\": \"abc xyz\", \"email\": \"abc@xyz.com\" }";
	
	private static String PROPERTY_CLAIMS_JSON = "claims-json";
	private static String PROPERTY_ISSUER = "iss";
	private static String PROPERTY_AUDIENCE = "aud";
	private static String PROPERTY_EXPIRY = "expiry";

	private static String PROPERTY_JWS = "jws";
	private static String PROPERTY_JWS_KEY = "jws-key";
	private static String PROPERTY_JWS_KEY_PASS = "jws-key-pass";
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
	public void testEmptyGenerator() {
		JWTGenerator generator = new JWTGenerator(new HashMap<String, String>());
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifyFailureResult(result);
	}

	@Test
	public void testJWSNotEnabled() {
		SecretKey key = getHmacSHA256Key();
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_JWS_KEY, keyToString(key));
		properties.put(PROPERTY_JWS_ALGO, "HMAC_SHA256");
		properties.put(PROPERTY_CLAIMS_JSON, SAMPLE_CLAIMS);
		JWTGenerator generator = new JWTGenerator(properties);
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifyFailureResult(result);
	}

	@Test
	public void testJWSWithSharedKeyHS256() {
		SecretKey key = getHmacSHA256Key();
		JWTGenerator generator = jwsGenerator(keyToString(key), "HMAC_SHA256");
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifySuccessResult(result);
		String jwt = this.mctx.getVariable(JWT);
		verifyJWS(key, jwt);
	}

	@Test
	public void testJWSWithSharedKeyHS384() {
		SecretKey key = getHmacSHA384Key();
		JWTGenerator generator = jwsGenerator(keyToString(key), "HMAC_SHA384");
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifySuccessResult(result);
		String jwt = this.mctx.getVariable(JWT);
		verifyJWS(key, jwt);
	}

	@Test
	public void testJWSWithSharedKeyHS512() {
		SecretKey key = getHmacSHA512Key();
		JWTGenerator generator = jwsGenerator(keyToString(key), "HMAC_SHA512");
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifySuccessResult(result);
		String jwt = this.mctx.getVariable(JWT);
		verifyJWS(key, jwt);
	}

	@Test
	public void testJWSWithWrongAlgo() {
		SecretKey key = getHmacSHA512Key();
		JWTGenerator generator = jwsGenerator(keyToString(key), "Invalid");
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifyFailureResult(result);
	}

	@Test
	public void testJWSWithRSAKeyRS256() {
		KeyPair rsaKeyPair = getRSAKeyPair();
		String pemPrivateKey = getPEMPrivateKeyFromDER(rsaKeyPair.getPrivate());
		JWTGenerator generator = jwsGenerator(pemPrivateKey, "RSA_USING_SHA256");

		ExecutionResult result = generator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		verifyJWS(rsaKeyPair.getPublic(), this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWSWithRSAKeyRS384() {
		KeyPair rsaKeyPair = getRSAKeyPair();
		String pemPrivateKey = getPEMPrivateKeyFromDER(rsaKeyPair.getPrivate());
		JWTGenerator generator = jwsGenerator(pemPrivateKey, "RSA_USING_SHA384");

		ExecutionResult result = generator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		verifyJWS(rsaKeyPair.getPublic(), this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWSWithRSAKeyRS512() {
		KeyPair rsaKeyPair = getRSAKeyPair();
		String pemPrivateKey = getPEMPrivateKeyFromDER(rsaKeyPair.getPrivate());
		JWTGenerator generator = jwsGenerator(pemPrivateKey, "RSA_USING_SHA512");

		ExecutionResult result = generator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		verifyJWS(rsaKeyPair.getPublic(), this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWENotEnabled() {
		SecretKey secretKey = getAESKey(128);
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_JWE_KEY, encodedKey);
		properties.put(PROPERTY_JWE_KEY_ALGO, "A128GCMKW");
		properties.put(PROPERTY_JWE_ALGO, "AES_128_CBC_HMAC_SHA_256");
		properties.put(PROPERTY_CLAIMS_JSON, SAMPLE_CLAIMS);

		JWTGenerator generator = new JWTGenerator(properties);
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifyFailureResult(result);
	}

	@Test
	public void testJWEWithAESAESKey1() {
		SecretKey secretKey = getAESKey(128);
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

		JWTGenerator generator = jweGenerator(encodedKey, "A128GCMKW", "AES_128_CBC_HMAC_SHA_256");
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifySuccessResult(result);
		verifyJWE(secretKey, "A128GCMKW", "AES_128_CBC_HMAC_SHA_256", this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWEWithAESAESKey2() {
		SecretKey secretKey = getAESKey(128);
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

		JWTGenerator generator = jweGenerator(encodedKey, "A128GCMKW", "AES_128_GCM");
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifySuccessResult(result);
		verifyJWE(secretKey, "A128GCMKW", "AES_128_GCM", this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWEWithAESAESAESKey3() {
		SecretKey secretKey = getAESKey(128);
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

		JWTGenerator generator = jweGenerator(encodedKey, "A128KW", "AES_128_CBC_HMAC_SHA_256");
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifySuccessResult(result);
		verifyJWE(secretKey, "A128KW", "AES_128_CBC_HMAC_SHA_256", this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWEWithAESAESKey4() {
		SecretKey secretKey = getAESKey(128);
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

		JWTGenerator generator = jweGenerator(encodedKey, "A128KW", "AES_128_GCM");
		ExecutionResult result = generator.execute(this.mctx, this.ectx);
		verifySuccessResult(result);
		verifyJWE(secretKey, "A128KW", "AES_128_GCM", this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWEWithRSAAESKey1() {
		KeyPair rsaKeyPair = getRSAKeyPair();
		String pemPublicKey = getPEMPublicKeyFromDER(rsaKeyPair.getPublic());
		JWTGenerator generator = jweGenerator(pemPublicKey, "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256");

		ExecutionResult result = generator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		verifyJWE(rsaKeyPair.getPrivate(), "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256", this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWEWithRSAAESKey2() {
		KeyPair rsaKeyPair = getRSAKeyPair();
		String pemPublicKey = getPEMPublicKeyFromDER(rsaKeyPair.getPublic());
		JWTGenerator generator = jweGenerator(pemPublicKey, "RSA_OAEP", "AES_128_GCM");

		ExecutionResult result = generator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		verifyJWE(rsaKeyPair.getPrivate(), "RSA_OAEP", "AES_128_GCM", this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWEAndJWSWithRSAAndHMAC() {
		SecretKey keySign = getHmacSHA512Key();
		KeyPair rsaKeyPairEnc = getRSAKeyPair();
		String pemPublicKeyEnc = getPEMPublicKeyFromDER(rsaKeyPairEnc.getPublic());

		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_CLAIMS_JSON, SAMPLE_CLAIMS);
		properties.put(PROPERTY_ISSUER, "edge-jwt-gen");
		properties.put(PROPERTY_AUDIENCE, "aud-1");
		properties.put(PROPERTY_EXPIRY, "300");
		
		properties.put(PROPERTY_JWS, "true");
		properties.put(PROPERTY_JWS_KEY, keyToString(keySign));
		properties.put(PROPERTY_JWS_ALGO, "HMAC_SHA512");
		properties.put(PROPERTY_JWE, "true");
		properties.put(PROPERTY_JWE_KEY, pemPublicKeyEnc);
		properties.put(PROPERTY_JWE_KEY_ALGO, "RSA_OAEP");
		properties.put(PROPERTY_JWE_ALGO, "AES_128_CBC_HMAC_SHA_256");
		
		JWTGenerator generator = new JWTGenerator(properties);
		ExecutionResult result = generator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		verifyJWEWithJWS(
			rsaKeyPairEnc.getPrivate(), "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256",
			keySign, "HMAC_SHA512",
			this.mctx.getVariable(JWT));
	}


	@Test
	public void testJWSWithEncryptedPrivateKey() {
		String pemPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----MIIE6TAbBgkqhkiG9w0BBQMwDgQIh52IJa6i0TACAggABIIEyAKXYcajrZWfvvH3eCRtMgGn4v0MaH39hYnYLF3Y3AyEJDkCPJ9jVzK1LBhYpe2kl7JFVfI8uR+ofNxD4xTRrevWrq4ejtI1eL1e+38Y68wVf389W5t2KGxTEltiiOBd6l2ANon5nAPE8IL6VfF38FGbgSIvMER33j0tjAKHumd817qj9QqIyIOD8H959JZZ+QlfaIvPFrtzvAwjQBjyGgr8XybVHUdT+9XAUrFCMMREKDGW2CaO94JI4Ca6noL9KT4L57vbXa2zYeEKyr2Bnpni27Qvb/a0I8Eml2GLC6fM/ZDOgi8RoYyMtyhaHTYPAy0oRAL2w3WjO7iomw7d6WKqqnATAn40T9rRK7anvbyv6kMxM6kwaQOfjCR/3tgrlVC2Q5MNnsBvsxUpKlg81GL++xZoTXw6znuaY5DCBNNj7CRSES/taE2PrDxy/2wv6UwVlwznqj1GPmCC4ri5Y7M1RhtlbTFaPC18wapG34rAeg2RJ22/oJmGbQv/m/nOxnUXqYjTX5T6oOxCmBQbUTOOVETbFcHrDptvntQ9hakMl9OhtnhhRqkYwSfvvRTa+cAq/Cbp+RI1hURTmL4gp0/qMFljNSWbGfPSIwKyJcvvgmPkSYDtV0m1t25RNiaCiMdmD0GR/68sWvtL09PI/Cn4eK4oV2wF9qvF5R4YkFgWZvg73yyepeuXfe6PeDOQSJp3mYDzwgiy1Dpt96QRPgGHYJJk5Z6+jv4KX45NTuXrZl/WXP4bOcQUDAc/ezJaanUeQxfsR2enGoVkWJmo12CnK6ZgyVRXG7G/0AxmANnhO7rB6i8K1aGl3jZqOnYilI7fw44bl1TMqEyNG8F9GTfGKoEn0vJq0v4kbznGVHCkxSZI0uzHPnt8CgRnz3CWfSecv9slf3z6rVMJesF1JLy7CeYclB0G5EBW/PsvqpbMDZQYC+iZNnS+KGdTt4cq9WWudkJrs2Ge+jAJHVTvUSXWbJTOflavkBqqaheSMlr72bZj0KjMkaEuSCKNluN06FU//gnE5oxstAnaLacJUHpHSaOb2GNRNCoO60lTPvFtTWNJTr4rGTIC3xAFCspiNiqJZ/R9BqYxAxzHNP0/fNPth8r6tLYcmLbWNrupvPYsj16lX1g4hBHAy49LOZf7WwP5bSVDNmC5C3LJ5JMF+cuk3dg5HjWLmolUzRqZ1NZEHgcv6k6Wm5jcJj+xLgp/RS7K6l/DSlcFCoPsq4RI9Og7jCqujr41zz0DkiSjz1X8eQIgC1zGacquCcUXJ0cLSevxHuZoQJlxijSklR5k6m7qIKEGpJS9J8SMRWpr26mMZ22VEwtPewuVjtxIpyJhpk/MfMZeyvOQMaZ486OC2kyz7G/dH9AlRthtotC/Ae5+qLmI05so1O0xGV1HzCpt4p8xg6Tc7AP3GWkPEjsUBw8MZl0iqe6IKEP7M+299RQacARudqgOEP+ghp0ASKiyw3cKLl//CZtlUUo4ryDxOQONDCG5M0S/TmLoi6Sih8xuMww8CPWi62Lc4rkClxRgVSHIp0MnWkuipMhB5J7ONNyM6G2UffSd/zmB5lNPdAPGc5GIYr1LryJ9tlwjrq4rF05sAGNsjy2rqeWVW+LYGyOFpSq91QC+6w==-----END ENCRYPTED PRIVATE KEY-----";
		String pemPublicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoE/tMVvp1JqQ/1eGATl1aq+ciUXrGJ8yekFh6F4QhcModrQb15ojvbaQ11ZseLu3tswsdMP5oLKe9ZtvRWAhYX1APINo1sCQBYQZNf9L015iCYSYDCQucRziLWk4K+QXYG7sZIA/8Gb/rbamtBLho16UNaAzkbrR7+rdrRyCyDeyQ9tIfOnSPmjiP0o705sybRs86cfbgOg6yUG3WEU/v5mhg+g+zM3R1nMIgyE1QEKM9zgwvbbR0IkN3L5N0XJFWvR0XNEes5XTHPmh0O6PI4m6vic1UhwyWFy513p4e0tRAIKeU9pCDT1HFTHWPX2gKB9RcuEFxSxczXCc6RCPwIDAQAB-----END PUBLIC KEY-----";
		PublicKey publicKey = getDERPublicKeyFromPEM(pemPublicKey);

		JWTGenerator generator = jwsGenerator(pemPrivateKey, "RSA_USING_SHA256", "123");

		ExecutionResult result = generator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		verifyJWS(publicKey, this.mctx.getVariable(JWT));
	}

	@Test
	public void testJWSWithEncryptedPrivateKeyAndWrongPassword() {
		String pemPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----MIIE6TAbBgkqhkiG9w0BBQMwDgQIh52IJa6i0TACAggABIIEyAKXYcajrZWfvvH3eCRtMgGn4v0MaH39hYnYLF3Y3AyEJDkCPJ9jVzK1LBhYpe2kl7JFVfI8uR+ofNxD4xTRrevWrq4ejtI1eL1e+38Y68wVf389W5t2KGxTEltiiOBd6l2ANon5nAPE8IL6VfF38FGbgSIvMER33j0tjAKHumd817qj9QqIyIOD8H959JZZ+QlfaIvPFrtzvAwjQBjyGgr8XybVHUdT+9XAUrFCMMREKDGW2CaO94JI4Ca6noL9KT4L57vbXa2zYeEKyr2Bnpni27Qvb/a0I8Eml2GLC6fM/ZDOgi8RoYyMtyhaHTYPAy0oRAL2w3WjO7iomw7d6WKqqnATAn40T9rRK7anvbyv6kMxM6kwaQOfjCR/3tgrlVC2Q5MNnsBvsxUpKlg81GL++xZoTXw6znuaY5DCBNNj7CRSES/taE2PrDxy/2wv6UwVlwznqj1GPmCC4ri5Y7M1RhtlbTFaPC18wapG34rAeg2RJ22/oJmGbQv/m/nOxnUXqYjTX5T6oOxCmBQbUTOOVETbFcHrDptvntQ9hakMl9OhtnhhRqkYwSfvvRTa+cAq/Cbp+RI1hURTmL4gp0/qMFljNSWbGfPSIwKyJcvvgmPkSYDtV0m1t25RNiaCiMdmD0GR/68sWvtL09PI/Cn4eK4oV2wF9qvF5R4YkFgWZvg73yyepeuXfe6PeDOQSJp3mYDzwgiy1Dpt96QRPgGHYJJk5Z6+jv4KX45NTuXrZl/WXP4bOcQUDAc/ezJaanUeQxfsR2enGoVkWJmo12CnK6ZgyVRXG7G/0AxmANnhO7rB6i8K1aGl3jZqOnYilI7fw44bl1TMqEyNG8F9GTfGKoEn0vJq0v4kbznGVHCkxSZI0uzHPnt8CgRnz3CWfSecv9slf3z6rVMJesF1JLy7CeYclB0G5EBW/PsvqpbMDZQYC+iZNnS+KGdTt4cq9WWudkJrs2Ge+jAJHVTvUSXWbJTOflavkBqqaheSMlr72bZj0KjMkaEuSCKNluN06FU//gnE5oxstAnaLacJUHpHSaOb2GNRNCoO60lTPvFtTWNJTr4rGTIC3xAFCspiNiqJZ/R9BqYxAxzHNP0/fNPth8r6tLYcmLbWNrupvPYsj16lX1g4hBHAy49LOZf7WwP5bSVDNmC5C3LJ5JMF+cuk3dg5HjWLmolUzRqZ1NZEHgcv6k6Wm5jcJj+xLgp/RS7K6l/DSlcFCoPsq4RI9Og7jCqujr41zz0DkiSjz1X8eQIgC1zGacquCcUXJ0cLSevxHuZoQJlxijSklR5k6m7qIKEGpJS9J8SMRWpr26mMZ22VEwtPewuVjtxIpyJhpk/MfMZeyvOQMaZ486OC2kyz7G/dH9AlRthtotC/Ae5+qLmI05so1O0xGV1HzCpt4p8xg6Tc7AP3GWkPEjsUBw8MZl0iqe6IKEP7M+299RQacARudqgOEP+ghp0ASKiyw3cKLl//CZtlUUo4ryDxOQONDCG5M0S/TmLoi6Sih8xuMww8CPWi62Lc4rkClxRgVSHIp0MnWkuipMhB5J7ONNyM6G2UffSd/zmB5lNPdAPGc5GIYr1LryJ9tlwjrq4rF05sAGNsjy2rqeWVW+LYGyOFpSq91QC+6w==-----END ENCRYPTED PRIVATE KEY-----";
		String pemPublicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoE/tMVvp1JqQ/1eGATl1aq+ciUXrGJ8yekFh6F4QhcModrQb15ojvbaQ11ZseLu3tswsdMP5oLKe9ZtvRWAhYX1APINo1sCQBYQZNf9L015iCYSYDCQucRziLWk4K+QXYG7sZIA/8Gb/rbamtBLho16UNaAzkbrR7+rdrRyCyDeyQ9tIfOnSPmjiP0o705sybRs86cfbgOg6yUG3WEU/v5mhg+g+zM3R1nMIgyE1QEKM9zgwvbbR0IkN3L5N0XJFWvR0XNEes5XTHPmh0O6PI4m6vic1UhwyWFy513p4e0tRAIKeU9pCDT1HFTHWPX2gKB9RcuEFxSxczXCc6RCPwIDAQAB-----END PUBLIC KEY-----";
		PublicKey publicKey = getDERPublicKeyFromPEM(pemPublicKey);

		JWTGenerator generator = jwsGenerator(pemPrivateKey, "RSA_USING_SHA256", "1234");

		ExecutionResult result = generator.execute(this.mctx, this.ectx);

		verifyFailureResult(result);
	}

	@Test
	public void testJWEWithEncryptedRSAAESKey() {
		String pemPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----MIIE6TAbBgkqhkiG9w0BBQMwDgQIh52IJa6i0TACAggABIIEyAKXYcajrZWfvvH3eCRtMgGn4v0MaH39hYnYLF3Y3AyEJDkCPJ9jVzK1LBhYpe2kl7JFVfI8uR+ofNxD4xTRrevWrq4ejtI1eL1e+38Y68wVf389W5t2KGxTEltiiOBd6l2ANon5nAPE8IL6VfF38FGbgSIvMER33j0tjAKHumd817qj9QqIyIOD8H959JZZ+QlfaIvPFrtzvAwjQBjyGgr8XybVHUdT+9XAUrFCMMREKDGW2CaO94JI4Ca6noL9KT4L57vbXa2zYeEKyr2Bnpni27Qvb/a0I8Eml2GLC6fM/ZDOgi8RoYyMtyhaHTYPAy0oRAL2w3WjO7iomw7d6WKqqnATAn40T9rRK7anvbyv6kMxM6kwaQOfjCR/3tgrlVC2Q5MNnsBvsxUpKlg81GL++xZoTXw6znuaY5DCBNNj7CRSES/taE2PrDxy/2wv6UwVlwznqj1GPmCC4ri5Y7M1RhtlbTFaPC18wapG34rAeg2RJ22/oJmGbQv/m/nOxnUXqYjTX5T6oOxCmBQbUTOOVETbFcHrDptvntQ9hakMl9OhtnhhRqkYwSfvvRTa+cAq/Cbp+RI1hURTmL4gp0/qMFljNSWbGfPSIwKyJcvvgmPkSYDtV0m1t25RNiaCiMdmD0GR/68sWvtL09PI/Cn4eK4oV2wF9qvF5R4YkFgWZvg73yyepeuXfe6PeDOQSJp3mYDzwgiy1Dpt96QRPgGHYJJk5Z6+jv4KX45NTuXrZl/WXP4bOcQUDAc/ezJaanUeQxfsR2enGoVkWJmo12CnK6ZgyVRXG7G/0AxmANnhO7rB6i8K1aGl3jZqOnYilI7fw44bl1TMqEyNG8F9GTfGKoEn0vJq0v4kbznGVHCkxSZI0uzHPnt8CgRnz3CWfSecv9slf3z6rVMJesF1JLy7CeYclB0G5EBW/PsvqpbMDZQYC+iZNnS+KGdTt4cq9WWudkJrs2Ge+jAJHVTvUSXWbJTOflavkBqqaheSMlr72bZj0KjMkaEuSCKNluN06FU//gnE5oxstAnaLacJUHpHSaOb2GNRNCoO60lTPvFtTWNJTr4rGTIC3xAFCspiNiqJZ/R9BqYxAxzHNP0/fNPth8r6tLYcmLbWNrupvPYsj16lX1g4hBHAy49LOZf7WwP5bSVDNmC5C3LJ5JMF+cuk3dg5HjWLmolUzRqZ1NZEHgcv6k6Wm5jcJj+xLgp/RS7K6l/DSlcFCoPsq4RI9Og7jCqujr41zz0DkiSjz1X8eQIgC1zGacquCcUXJ0cLSevxHuZoQJlxijSklR5k6m7qIKEGpJS9J8SMRWpr26mMZ22VEwtPewuVjtxIpyJhpk/MfMZeyvOQMaZ486OC2kyz7G/dH9AlRthtotC/Ae5+qLmI05so1O0xGV1HzCpt4p8xg6Tc7AP3GWkPEjsUBw8MZl0iqe6IKEP7M+299RQacARudqgOEP+ghp0ASKiyw3cKLl//CZtlUUo4ryDxOQONDCG5M0S/TmLoi6Sih8xuMww8CPWi62Lc4rkClxRgVSHIp0MnWkuipMhB5J7ONNyM6G2UffSd/zmB5lNPdAPGc5GIYr1LryJ9tlwjrq4rF05sAGNsjy2rqeWVW+LYGyOFpSq91QC+6w==-----END ENCRYPTED PRIVATE KEY-----";
		String pemPublicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoE/tMVvp1JqQ/1eGATl1aq+ciUXrGJ8yekFh6F4QhcModrQb15ojvbaQ11ZseLu3tswsdMP5oLKe9ZtvRWAhYX1APINo1sCQBYQZNf9L015iCYSYDCQucRziLWk4K+QXYG7sZIA/8Gb/rbamtBLho16UNaAzkbrR7+rdrRyCyDeyQ9tIfOnSPmjiP0o705sybRs86cfbgOg6yUG3WEU/v5mhg+g+zM3R1nMIgyE1QEKM9zgwvbbR0IkN3L5N0XJFWvR0XNEes5XTHPmh0O6PI4m6vic1UhwyWFy513p4e0tRAIKeU9pCDT1HFTHWPX2gKB9RcuEFxSxczXCc6RCPwIDAQAB-----END PUBLIC KEY-----";
		PublicKey publicKey = getDERPublicKeyFromPEM(pemPublicKey);

		JWTGenerator generator = jweGenerator(pemPublicKey, "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256");

		ExecutionResult result = generator.execute(this.mctx, this.ectx);

		verifySuccessResult(result);
		verifyJWE(getDERPrivateKeyFromPEM(pemPrivateKey, "123"), "RSA_OAEP", "AES_128_CBC_HMAC_SHA_256", this.mctx.getVariable(JWT));
	}

	// ------------- BEGIN SPECIAL TESTS -------------
	
	// BELOW TESTS INVOLVE AES256 AND BECAUSE OF THE LARGE KEY SIZE MAKE SURE YOU HAVE INSTALLED THE 
	// JAVA CRYPTOGRAPHY EXTENSION (JCE) UNLIMITED STRENGTH JURISDICTION POLICY FILES
	// HTTP://WWW.ORACLE.COM/TECHNETWORK/JAVA/JAVASE/DOWNLOADS/JCE-7-DOWNLOAD-432124.HTML
	
	// @Test
	// public void testJWEWithRSAAESAESKey3() {
	// 	KeyPair rsaKeyPair = getRSAKeyPair();
	// 	String pemPublicKey = getPEMPublicKeyFromDER(rsaKeyPair.getPublic());
	// 	JWTGenerator generator = jweGenerator(pemPublicKey, "RSA1_5", "AES_256_CBC_HMAC_SHA_512");

	// 	ExecutionResult result = generator.execute(this.mctx, this.ectx);

	// 	verifySuccessResult(result);
	// 	verifyJWE(rsaKeyPair.getPrivate(), "RSA1_5", "AES_256_CBC_HMAC_SHA_512", this.mctx.getVariable(JWT));
	// }

	// @Test
	// public void testJWEWithRSAAESKey4() {
	// 	KeyPair rsaKeyPair = getRSAKeyPair();
	// 	String pemPublicKey = getPEMPublicKeyFromDER(rsaKeyPair.getPublic());
	// 	JWTGenerator generator = jweGenerator(pemPublicKey, "RSA1_5", "AES_256_GCM");

	// 	ExecutionResult result = generator.execute(this.mctx, this.ectx);

	// 	verifySuccessResult(result);
	// 	verifyJWE(rsaKeyPair.getPrivate(), "RSA1_5", "AES_256_GCM", this.mctx.getVariable(JWT));
	// }

	// @Test
	// public void testJWEAndJWSWithRSAAndRSA() {
	// 	KeyPair rsaKeyPairSign = getRSAKeyPair();
	// 	String pemPrivateKeySign = getPEMPrivateKeyFromDER(rsaKeyPairSign.getPrivate());

	// 	KeyPair rsaKeyPairEnc = getRSAKeyPair();
	// 	String pemPublicKeyEnc = getPEMPublicKeyFromDER(rsaKeyPairEnc.getPublic());

	// 	Map<String, String> properties = new HashMap<String, String>();
	// 	properties.put(PROPERTY_CLAIMS_JSON, SAMPLE_CLAIMS);
	// 	properties.put(PROPERTY_ISSUER, "edge-jwt-gen");
	// 	properties.put(PROPERTY_AUDIENCE, "aud-1");
	// 	properties.put(PROPERTY_EXPIRY, "300");

	// 	properties.put(PROPERTY_JWS, "true");
	// 	properties.put(PROPERTY_JWS_KEY, pemPrivateKeySign);
	// 	properties.put(PROPERTY_JWS_ALGO, "RSA_USING_SHA512");
	// 	properties.put(PROPERTY_JWE, "true");
	// 	properties.put(PROPERTY_JWE_KEY, pemPublicKeyEnc);
	// 	properties.put(PROPERTY_JWE_KEY_ALGO, "RSA1_5");
	// 	properties.put(PROPERTY_JWE_ALGO, "AES_256_GCM");
		
	// 	JWTGenerator generator = new JWTGenerator(properties);
	// 	ExecutionResult result = generator.execute(this.mctx, this.ectx);

	// 	verifySuccessResult(result);
	// 	verifyJWEWithJWS(
	// 		rsaKeyPairEnc.getPrivate(), "RSA1_5", "AES_256_GCM",
	// 		rsaKeyPairSign.getPublic(), "RSA_USING_SHA512",
	// 		this.mctx.getVariable(JWT));
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

	private Map<String, String> getDefaultJWSProperties(String key, String algo) {
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_JWS, "true");
		properties.put(PROPERTY_JWS_KEY, key);
		properties.put(PROPERTY_JWS_ALGO, algo);
		properties.put(PROPERTY_CLAIMS_JSON, SAMPLE_CLAIMS);
		properties.put(PROPERTY_ISSUER, "edge-jwt-gen");
		properties.put(PROPERTY_AUDIENCE, "aud-1");
		properties.put(PROPERTY_EXPIRY, "300");
		return properties;
	}

	private JWTGenerator jwsGenerator(String key, String algo) {
		return new JWTGenerator(this.getDefaultJWSProperties(key, algo));
	}

	private JWTGenerator jwsGenerator(String key, String algo, String password) {
		Map<String, String> properties = this.getDefaultJWSProperties(key, algo);
		properties.put(PROPERTY_JWS_KEY_PASS, password);
		return new JWTGenerator(properties);
	}

	private JWTGenerator jweGenerator(String key, String keyAlgo, String jweAlgo) {
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PROPERTY_JWE, "true");
		properties.put(PROPERTY_JWE_KEY, key);
		properties.put(PROPERTY_JWE_KEY_ALGO, keyAlgo);
		properties.put(PROPERTY_JWE_ALGO, jweAlgo);
		properties.put(PROPERTY_CLAIMS_JSON, SAMPLE_CLAIMS);
		properties.put(PROPERTY_ISSUER, "edge-jwt-gen");
		properties.put(PROPERTY_AUDIENCE, "aud-1");
		properties.put(PROPERTY_EXPIRY, "300");
		return new JWTGenerator(properties);
	}

	private void verifySuccessResult(ExecutionResult result) {
		System.out.println(this.mctx.getVariable(REASON).toString());
		assertEquals(ExecutionResult.SUCCESS, result);
		assertEquals(RESULT_SUCCESS, this.mctx.getVariable(RESULT));
	}

	private void verifyFailureResult(ExecutionResult result) {
		// System.out.println(this.mctx.getVariable(REASON).toString());
		assertEquals(ExecutionResult.ABORT, result);
		assertEquals(RESULT_FAILURE, this.mctx.getVariable(RESULT));
	}

	private void verifyJWS(Key key, String jwt) {
		try {
			JsonWebSignature jws = new JsonWebSignature();
			jws.setKey(key);
			jws.setCompactSerialization(jwt);
			jws.setDoKeyValidation(false);
			assertTrue(jws.verifySignature());
			JwtClaims claims = JwtClaims.parse(jws.getPayload());
			assertEquals("abc xyz", claims.getSubject());
			assertEquals("abc@xyz.com", claims.getClaimValue("email"));
		} catch (Exception e) {
			fail();
		}
	}

	private void verifyJWE(Key key, String keyAlgo, String jweAlgo, String jwt) {
		try {
		    JsonWebEncryption jwe = new JsonWebEncryption();
		    jwe.setAlgorithmConstraints(
		    	new AlgorithmConstraints(
		    		ConstraintType.WHITELIST, 
		    		ALGORITHMS.get(keyAlgo)));
		    jwe.setContentEncryptionAlgorithmConstraints(
		    	new AlgorithmConstraints(
		    		ConstraintType.WHITELIST, 
		    		ALGORITHMS.get(jweAlgo)));
		    jwe.setCompactSerialization(jwt);
		    jwe.setKey(key);
			JwtClaims claims = JwtClaims.parse(jwe.getPlaintextString());
			assertEquals("abc xyz", claims.getSubject());
			assertEquals("abc@xyz.com", claims.getClaimValue("email"));
		} catch (Exception e) {
			fail();
		}
	}

	private static void verifyJWEWithJWS(Key jweKey, String jweKeyAlgo, String jweAlgo, Key jwsKey, String jwsAlgo, String jwt) {
	    AlgorithmConstraints jwsAlgConstraints = 
		    new AlgorithmConstraints(
		    	ConstraintType.WHITELIST,
		    	ALGORITHMS.get(jwsAlgo));

	    AlgorithmConstraints jweAlgConstraints = 
		    new AlgorithmConstraints(
		    	ConstraintType.WHITELIST,
		    	ALGORITHMS.get(jweKeyAlgo));

	    AlgorithmConstraints jweEncConstraints = 
	    	new AlgorithmConstraints(
	    		ConstraintType.WHITELIST,
	    		ALGORITHMS.get(jweAlgo));

	    JwtConsumer jwtConsumer = 
	    	new JwtConsumerBuilder()
	            .setRequireExpirationTime()
	            .setMaxFutureValidityInMinutes(300)
	            .setRequireSubject()
	            .setExpectedIssuer("edge-jwt-gen")
	            .setExpectedAudience("aud-1")
	            .setDecryptionKey(jweKey)
	            .setVerificationKey(jwsKey)
	            .setRelaxVerificationKeyValidation()
	            .setJwsAlgorithmConstraints(jwsAlgConstraints)
	            .setJweAlgorithmConstraints(jweAlgConstraints)
	            .setJweContentEncryptionAlgorithmConstraints(jweEncConstraints)
	            .build();

	    try {
	        JwtClaims claims = jwtConsumer.processToClaims(jwt);
			assertEquals("abc xyz", claims.getSubject());
			assertEquals("abc@xyz.com", claims.getClaimValue("email"));
	    } catch (InvalidJwtException e) {
	        System.out.println("Invalid JWT! " + e);
	        fail();
	    } catch (MalformedClaimException e) {
	    	System.out.println("Invalid Claims" + e);
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