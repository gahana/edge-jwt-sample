Feature: Check if signed and then encrypted JWTs can be verified correctly

Scenario: Generate an HMAC_SHA512 signed and then A128GCMKW / AES_128_GCM encrypted JWT and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_HS_KEY`             |  
        | jwsAlgo    | HMAC_SHA512              |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES128_KEY`         |  
        | jweKeyAlgo | A128GCMKW                |  
        | jweAlgo    | AES_128_GCM              |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as HS_AES_128_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `HS_AES_128_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_HS_KEY`             |  
        | jwsAlgo    | HMAC_SHA512              |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES128_KEY`         |  
        | jweKeyAlgo | A128GCMKW                |  
        | jweAlgo    | AES_128_GCM              |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an RSA_USING_SHA256 signed and then A256KW / AES_256_CBC_HMAC_SHA_512 encrypted JWT and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PRIVATE_KEY`    |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES256_KEY`         |  
        | jweKeyAlgo | A256KW                   |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSA_AES_256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RSA_AES_256_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES256_KEY`         |  
        | jweKeyAlgo | A256KW                   |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1


Scenario: Generate an HMAC_SHA384 signed and then RSA1_5 / AES_128_GCM encrypted JWT and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_HS_KEY`             |  
        | jwsAlgo    | HMAC_SHA384              |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA1_5                   |  
        | jweAlgo    | AES_128_GCM              |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as HS_RSA15_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `HS_RSA15_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_HS_KEY`             |  
        | jwsAlgo    | HMAC_SHA384              |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA1_5                   |  
        | jweAlgo    | AES_128_GCM              |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an RSA_USING_SHA256 signed and then RSA1_5 / AES_192_CBC_HMAC_SHA_384 encrypted JWT and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PRIVATE_KEY`    |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA1_5                   |  
        | jweAlgo    | AES_192_CBC_HMAC_SHA_384 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSA_RSA15_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RSA_RSA15_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA1_5                   |  
        | jweAlgo    | AES_192_CBC_HMAC_SHA_384 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an HMAC_SHA256 signed and then RSA_OAEP / AES_256_GCM encrypted JWT and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_HS_KEY`             |  
        | jwsAlgo    | HMAC_SHA256              |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_GCM              |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as HS_RSA_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `HS_RSA_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_HS_KEY`             |  
        | jwsAlgo    | HMAC_SHA256              |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_GCM              |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an RSA_USING_SHA256 signed and then RSA_OAEP / AES_256_CBC_HMAC_SHA_512 encrypted JWT and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PRIVATE_KEY`    |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSA_RSA_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RSA_RSA_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an expired RSA_USING_SHA256 signed and then RSA_OAEP / AES_256_CBC_HMAC_SHA_512 encrypted JWT and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PRIVATE_KEY`    |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 0                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as EXPIRED_RSA_RSA_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `EXPIRED_RSA_RSA_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Wrong sign algo should fail
    Given I set Authorization header to Bearer `RSA_RSA_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA384         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Wrong enc key algo should fail
    Given I set Authorization header to Bearer `RSA_RSA_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | A128KW                   |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Wrong enc algo should fail
    Given I set Authorization header to Bearer `RSA_RSA_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_128_GCM              |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Wrong issuer should fail
    Given I set Authorization header to Bearer `RSA_RSA_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-2                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Wrong audience should fail
    Given I set Authorization header to Bearer `RSA_RSA_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-2                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Validation with correct params
    Given I set Authorization header to Bearer `RSA_RSA_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jws        | true                     |  
        | jwsKey     | `JWS_RSA_PUBLIC_KEY`     |  
        | jwsAlgo    | RSA_USING_SHA256         |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

