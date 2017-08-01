# Edge proxy to generate and validate JSON Web Tokens (JWTs)
## Introducton
This is a sample [Apigee Edge](https://apigee.com/api-management) API proxy to generate or validate [JSON Web Tokens](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32). A Java callout with [jose4j](https://bitbucket.org/b_c/jose4j/wiki/Home) library is used within an API proxy to support various signing and encryption algorithms for JWTs. 

## Prerequisites
- Install [gradle](https://gradle.org/install/) to compile and build Java callout needed for API proxy.
- Install [NodeJS](https://nodejs.org/en/download/) and [npm](https://www.npmjs.com/).
- Install [apigeetool](https://github.com/apigee/apigeetool-node) to package and deploy API proxy.
- Install [grunt](https://gruntjs.com/), [cucumber](https://github.com/cucumber/cucumber-js) and [apickli](https://github.com/apickli/apickli) to run BDD tests
- If you plan to use algorithms with large key sizes like AES256, you need to install [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)

## Install
`git clone https://github.com/gahana/edge-jwt-sample.git` or download this repository.

Set your Apigee Edge username and password in environment variables

```
$ export EDGE_USERNAME=<Apigee Edge Username>
$ export EDGE_PASSWORD=<Apigee Edge Password>
```

Update Edge organization and environment in `deploy.sh` file

```
ORG="org name"
ENV="env name"
```

To deploy both generate and validate proxies. (Make sure `deploy.sh` file has execution privileges.)

```
$ ./deploy.sh all
```

To deploy generate proxy

```
$ ./deploy.sh generate
```

To deploy validate proxy

```
$ ./deploy.sh validate
```

To compile and run generate java callout

```
$ cd jwt-generate-callout
$ gradle build
```

To run tests on validate java callout

```
$ cd jwt-validate-callout
$ gradle test
```

To run BDD tests, first update org and env name in URL variable of file `edge-jwt-sample/test/features/step_definitions/jwt-steps.js`. Then

```
$ cd test
$ grunt
```

## Usage
### Java Callout properties 
Java Callout Property tag's name attribute and it value are summarized below.

|   Property   |           Presence          |                                                                         Description                                                                          |
| ------------ | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| jws          | Optional                    | Value can be either true or false. Default is false. Atleast one of jws or jwe should be set to true.                                                        |
| jws-algo     | Required, if jws is true    | See table below for supported signing algorithm values.                                                                                                      |
| jws-key      | Required, if jws is true    | Key used to sign JWTs, can be HMAC or RSA public/private key.                                                                                                |
| jws-key-pass | Optional                    | Password used to decrypt RSA private key.                                                                                                                    |
| jwe          | Optional                    | Value can be either true or false. Default is false. Atleast one of jws or jwe should be set to true.                                                        |
| jwe-algo     | Required, if jwe is true    | See table below for supported encryption algorithm values.                                                                                                   |
| jwe-key-algo | Required, if jwe is true    | See table below for supported encryption key management algorithm values.                                                                                    |
| jwe-key      | Required, if jwe is true    | Key used to sign JWTs, can be AES or RSA public/private key.                                                                                                 |
| jwe-key-pass | Optional                    | Password used to decrypt RSA private key.                                                                                                                    |
| claims-json  | Required                    | Claims in the JSON string format. Property "sub" is mandatory and any other claims are optional.                                                             |
| iss          | Required                    | When generating a JWT, this is the issuer property that will go in claims. When validating a JWT, the value to compare and error out if it does not match.   |
| aud          | Required                    | When generating a JWT, this is the audience property that will go in claims. When validating a JWT, the value to compare and error out if it does not match. |
| expiry       | Required, if generating JWT | Expiry time for JWT in minutes when generating it. Not needed while validating JWT.                                                                          |
| jwt          | Required, if validating JWT | JWT to validate. Not needed for JWT generation.                                                                                                              |

### Supported algorithms
This sample implementation covers some of the algorithms([JWA](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40)) for signing([JWS](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41)) and/or encrypting([JWE](https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40)) JWTs.

The values for jws-algo property and supported signing algorithms are summarized below.

|     jws-algo     |          Description           |
| ---------------- | ------------------------------ |
| HMAC_SHA256      | HMAC using SHA-256             |
| HMAC_SHA384      | HMAC using SHA-384             |
| HMAC_SHA512      | HMAC using SHA-512             |
| RSA_USING_SHA256 | RSASSA-PKCS-v1_5 using SHA-256 |
| RSA_USING_SHA384 | RSASSA-PKCS-v1_5 using SHA-384 |
| RSA_USING_SHA512 | RSASSA-PKCS-v1_5 using SHA-512 |

The values for jws-key-algo property and supported key management algorithms are summarized below.

| jws-key-algo |                        Description                        |
| ------------ | --------------------------------------------------------- |
| A128KW       | AES Key Wrap with default initial value using 128 bit key |
| A192KW       | AES Key Wrap with default initial value using 192 bit key |
| A256KW       | AES Key Wrap with default initial value using 256 bit key |
| A128GCMKW    | Key wrapping with AES GCM using 128 bit key               |
| A192GCMKW    | Key wrapping with AES GCM using 192 bit key               |
| A256GCMKW    | Key wrapping with AES GCM using 256 bit key               |
| RSA_OAEP     | RSAES OAEP using default parameters                       |
| RSA1_5       | RSAES-PKCS1-V1_5                                          |

The values for jws-key-algo property and supported key management algorithms are summarized below.

|         jws-algo         |                         Description                         |
| ------------------------ | ----------------------------------------------------------- |
| AES_128_CBC_HMAC_SHA_256 | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm |
| AES_192_CBC_HMAC_SHA_384 | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm |
| AES_256_CBC_HMAC_SHA_512 | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm |
| AES_128_GCM              | AES GCM using 128 bit key                                   |
| AES_192_GCM              | AES GCM using 192 bit key                                   |
| AES_256_GCM              | AES GCM using 256 bit key                                   |

Other algorithms as per JWS and JWE are not implemented in this sample project. However it should be easy to extend this implementation to cover those algorithms as well. [JSON Web Keys](https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41) is currently not supported with this implementation.

## Examples

### Signed JWTs
A sample Java Callout policy to generate signed JWTs with `HMAC_SHA512` algorithm. The properties issuer `iss`, audience `aud` and expiry in minutes `expiry` are added to claims in the `claims-json` property. `claims-json` must have `sub` property at the minimum and be in JSON string format. The `jws` property must be set to true, otherwise the JWTs will not be signed.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JavaCallout async="false" continueOnError="false" enabled="true" name="JC-JWTGenerate">
    <DisplayName>JC-JWTGenerate</DisplayName>
    <FaultRules/>
    <Properties>
        <Property name="jws">true</Property>
        <Property name="jws-algo">HMAC_SHA512</Property>
        <Property name="jws-key">lr7LQmTSqre2v ... q7L1M/ZKJWhBLw==</Property>
        <Property name="claims-json">{"sub":"John Doe","email":"johndoe@gmail.com"}</Property>
        <Property name="iss">issuer-name</Property>
        <Property name="aud">audience-1</Property>
        <Property name="expiry">300</Property>
    </Properties>
    <ClassName>com.apigeecs.jwt.JWTGenerator</ClassName>
    <ResourceURL>java://edge-jwt-generate.jar</ResourceURL>
</JavaCallout>
```

The JWTs generated above or by any OpenID Connect provider with same signing algorithm and shared key, can be validated using the below Java Callout policy.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JavaCallout async="false" continueOnError="false" enabled="true" name="JC-JWTValidate">
    <DisplayName>JC-JWTValidate</DisplayName>
    <Properties>
        <Property name="jws">true</Property>
        <Property name="jws-algo">HMAC_SHA512</Property>
        <Property name="jws-key">lr7LQmTSqre2v ... q7L1M/ZKJWhBLw==</Property>
        <Property name="jwt">eyJhbGc ... eXk57TblVQ</Property>
        <Property name="iss">issuer-name</Property>
        <Property name="aud">audience-1</Property>
    </Properties>
    <ClassName>com.apigeecs.jwt.JWTValidator</ClassName>
    <ResourceURL>java://edge-jwt-validate.jar</ResourceURL>
</JavaCallout>
```


A sample Java Callout policy to generate signed JWTs with `RSA_USING_SHA256` algorithm. Same as above except `jws-key` now points to an RSA private key for signing JWTs. Optionally, a password for the private key can be specified using `jws-key-pass` property.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JavaCallout async="false" continueOnError="false" enabled="true" name="JC-JWTGenerate">
    <DisplayName>JC-JWTGenerate</DisplayName>
    <FaultRules/>
    <Properties>
        <Property name="jws">true</Property>
        <Property name="jws-algo">RSA_USING_SHA256</Property>
        <Property name="jws-key">-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgk ... qnFpfsTENfvYh7ldpfIDHbCvtUBtA==
-----END PRIVATE KEY-----</Property>
        <Property name="jws-key-pass">abcd123</Property>
        <Property name="claims-json">{"sub":"John Doe","email":"johndoe@gmail.com"}</Property>
        <Property name="iss">issuer-name</Property>
        <Property name="aud">audience-1</Property>
        <Property name="expiry">300</Property>
    </Properties>
    <ClassName>com.apigeecs.jwt.JWTGenerator</ClassName>
    <ResourceURL>java://edge-jwt-generate.jar</ResourceURL>
</JavaCallout>
```

The JWTs generated above or by any OpenID Connect provider with same signing algorithm and public key, can be validated using the below Java Callout policy.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JavaCallout async="false" continueOnError="false" enabled="true" name="JC-JWTValidate">
    <DisplayName>JC-JWTValidate</DisplayName>
    <Properties>
        <Property name="jws">true</Property>
        <Property name="jws-algo">RSA_USING_SHA256</Property>
        <Property name="jws-key">-----BEGIN PUBLIC KEY-----
MIIBIjANBg ... Unpcj+/nQ4Vl7OYV/P0ipKQIDAQAB
-----END PUBLIC KEY-----</Property>
        <Property name="jwt">eyJhbGc ... eXk57TblVQ</Property>
        <Property name="iss">issuer-name</Property>
        <Property name="aud">audience-1</Property>
    </Properties>
    <ClassName>com.apigeecs.jwt.JWTValidator</ClassName>
    <ResourceURL>java://edge-jwt-validate.jar</ResourceURL>
</JavaCallout>
```

### Signed and encrypted JWTs
Sample Java callout policy to generate a signed and then encrypted JWT is below. Here the `claims-json` is updated with `iss`, `aud` and `expiry` (in minutes) properties. It is then signed with `HMAC_SHA512` algorithm. Finally, it is encrypted using `AES_256_CBC_HMAC_SHA_512` algorithm. For the final step, encryption/signing key is determined using a public key with `RSA_OAEP` key management algorithm

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JavaCallout async="false" continueOnError="false" enabled="true" name="JC-JWTGenerate">
    <DisplayName>JC-JWTGenerate</DisplayName>
    <FaultRules/>
    <Properties>
        <Property name="jws">true</Property>
        <Property name="jws-algo">HMAC_SHA512</Property>
        <Property name="jws-key">lr7LQmTSqre2v ... q7L1M/ZKJWhBLw==</Property>
        <Property name="jwe">true</Property>
        <Property name="jwe-algo">AES_256_CBC_HMAC_SHA_512</Property>
        <Property name="jwe-key-algo">RSA_OAEP</Property>
        <Property name="jwe-key">-----BEGIN PUBLIC KEY-----
MIIBIjAN ... PwIDAQAB
-----END PUBLIC KEY-----</Property>
        <Property name="claims-json">{"sub":"John Doe","email":"johndoe@gmail.com"}</Property>
        <Property name="iss">issuer-name</Property>
        <Property name="aud">audience-1</Property>
        <Property name="expiry">300</Property>
    </Properties>
    <ClassName>com.apigeecs.jwt.JWTGenerator</ClassName>
    <ResourceURL>java://edge-jwt-generate.jar</ResourceURL>
</JavaCallout>
```

The JWTs generated above or by any OpenID Connect provider with same signing and encryption algorithm and private key, can be validated using the below Java Callout policy.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JavaCallout async="false" continueOnError="false" enabled="true" name="JC-JWTGenerate">
    <DisplayName>JC-JWTGenerate</DisplayName>
    <FaultRules/>
    <Properties>
        <Property name="jws">true</Property>
        <Property name="jws-algo">HMAC_SHA512</Property>
        <Property name="jws-key">lr7LQmTSqre2v ... q7L1M/ZKJWhBLw==</Property>
        <Property name="jwe">true</Property>
        <Property name="jwe-algo">AES_256_CBC_HMAC_SHA_512</Property>
        <Property name="jwe-key-algo">RSA_OAEP</Property>
        <Property name="jwe-key">-----BEGIN PUBLIC KEY-----
MIIBIj ... PwIDAQAB
-----END PUBLIC KEY-----</Property>
        <Property name="jwt">eyJhbGc ... eXk57TblVQ</Property>
        <Property name="iss">issuer-name</Property>
        <Property name="aud">audience-1</Property>
    </Properties>
    <ClassName>com.apigeecs.jwt.JWTValidator</ClassName>
    <ResourceURL>java://edge-jwt-validate.jar</ResourceURL>
</JavaCallout>
```

### Flow variables for input and output
API proxy flow variables can be used to specify input to Java Callout and pick up the results i.e. JWT or Claims for generation and validation respectively.

Note: The default Java callout on Edge does not provide this feature. This mechanism to lookup variables for Java callout properties is custom implemented in the callout class to improve usability in this use case.

For example, the input for JWT validation can come from flow variables with prefix `jwt` as shown below.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JavaCallout async="false" continueOnError="false" enabled="true" name="JC-JWTValidate">
    <DisplayName>JC-JWTValidate</DisplayName>
    <Properties>
        <Property name="jwt">true</Property>
        <Property name="iss">{jwt.issuer}</Property>
        <Property name="aud">{jwt.audience}</Property>
        <Property name="jws">{jwt.jws}</Property>
        <Property name="jws-algo">{jwt.jwsAlgo}</Property>
        <Property name="jws-key">{jwt.jwsKey}</Property>
        <Property name="jws-key-pass">{jwt.jwsKeyPassword}</Property>
        <Property name="jwe">true</Property>
        <Property name="jwe-algo">{jwt.jweAlgo}</Property>
        <Property name="jwe-key-algo">{jwt.jweKeyAlgo}</Property>
        <Property name="jwe-key">{jwt.jweKey}</Property>
        <Property name="jwe-key-pass">{jwt.jweKeyPassword}</Property>
    </Properties>
    <ClassName>com.apigeecs.jwt.JWTValidator</ClassName>
    <ResourceURL>java://edge-jwt-validate.jar</ResourceURL>
</JavaCallout>
```

The JWT can be picked up from an Authorization header from request, the keys for signing and encryption can come from a KVM. These variables can be setup using policies like [`ExtractVariables`](http://docs.apigee.com/api-services/reference/extract-variables-policy), [`KeyValueMapOperations`](http://docs.apigee.com/api-services/reference/key-value-map-operations-policy), etc.

The output of Java callout is available again in flow variables. 

For JWT generation he JWT is available in `JWTGeneratorJWT` flow variable. You can know about the result of Java callout as `Success` or `Failure` in the `JWTGeneratorResult` variable. In case of errors, you can find out the main reason in `JWTGeneratorReason` besides a number of other variables the help debug the flow and state.

For JWT vlaidation, the claims extracted from JWT is available in `JWTValidatorClaims` flow variable. You can know about the result of Java callout as `Success` or `Failure` in the `JWTValidatorResult` variable. In case of errors, you can find out the main reason in `JWTValidatorReason` besides a number of other variables the help debug the flow and state. 

### RSA public and private keys used in Java callouts
If you are using RSA based algorithms for signing and encryption, the public and private keys must be in PEM format. In addition the private key must be in PKCS#8 encoding. See this [blog](https://adangel.org/2016/08/29/openssl-rsa-java/) for details on how RSA keys are used in the Java callout. 

Below commands summarize how to generate and format public and private keys needed for RSA based algorithms.
To generate a fresh key pair

```
$ openssl genrsa -out privatekey.pem 2048
```

Extract public from above private key

```
$ openssl rsa -in privatekey.pem -out publickey.pem -pubout
```

Convert private key to PKCS#8 format. 

```
$ openssl pkcs8 -in privatekey.pem -topk8 -nocrypt -out privatekey-pkcs8.pem
```

Note: Above command uses `nocrypt` option. While this is fine for development purpose, it is recommended to use encryption for products keys.

## Attribution
The initial part of this project started from this [earlier](https://github.com/apigee/iloveapis2015-jwt-jwe-jws) JWT implementation for edge.
