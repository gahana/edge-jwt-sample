Feature: Check if encrypted JWTs can be verified correctly

Scenario: Generate an encrypted JWT with A128GCMKW Key and AES_128_CBC_HMAC_SHA_256 algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES128_KEY`         |  
        | jweKeyAlgo | A128GCMKW                |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as A128GCMKW_AES128HS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `A128GCMKW_AES128HS256_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES128_KEY`         |  
        | jweKeyAlgo | A128GCMKW                |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an expired and encrypted JWT with A128GCMKW Key and AES_128_CBC_HMAC_SHA_256 algo and varify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES128_KEY`         |  
        | jweKeyAlgo | A128GCMKW                |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 0                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as EXPIRED_A128GCMKW_AES128HS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `EXPIRED_A128GCMKW_AES128HS256_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES128_KEY`         |  
        | jweKeyAlgo | A128GCMKW                |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Generate an encrypted JWT with A192GCMKW Key and AES_128_CBC_HMAC_SHA_256 algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES192_KEY`         |  
        | jweKeyAlgo | A192GCMKW                |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as A192GCMKW_AES128HS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `A192GCMKW_AES128HS256_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES192_KEY`         |  
        | jweKeyAlgo | A192GCMKW                |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an encrypted JWT with A256GCMKW Key and AES_128_CBC_HMAC_SHA_256 algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES256_KEY`         |  
        | jweKeyAlgo | A256GCMKW                |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as A256GCMKW_AES128HS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `A256GCMKW_AES128HS256_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES256_KEY`         |  
        | jweKeyAlgo | A256GCMKW                |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an encrypted JWT with A128KW Key and AES_128_CBC_HMAC_SHA_256 algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES128_KEY`         |  
        | jweKeyAlgo | A128KW                   |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as A128KW_AES128HS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `A128KW_AES128HS256_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES128_KEY`         |  
        | jweKeyAlgo | A128KW                   |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an encrypted JWT with A192KW Key and AES_128_CBC_HMAC_SHA_256 algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES192_KEY`         |  
        | jweKeyAlgo | A192KW                   |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as A192KW_AES128HS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `A192KW_AES128HS256_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES192_KEY`         |  
        | jweKeyAlgo | A192KW                   |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an encrypted JWT with A256KW Key and AES_128_CBC_HMAC_SHA_256 algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_AES256_KEY`         |  
        | jweKeyAlgo | A256KW                   |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as A256KW_AES128HS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `A256KW_AES128HS256_JWT`
      And I set request to JSON data
        | name       | value                    |  
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

Scenario: Generate an encrypted JWT with RSA1_5 Key and AES_128_GCM algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA1_5                   |  
        | jweAlgo    | AES_128_GCM              |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSA15_AES128GCM_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RSA15_AES128GCM_JWT`
      And I set request to JSON data
        | name       | value                    |  
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

Scenario: Generate an encrypted JWT with RSA1_5 Key and AES_192_CBC_HMAC_SHA_384 algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA1_5                   |  
        | jweAlgo    | AES_192_CBC_HMAC_SHA_384 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSA15_AES192HS384_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RSA15_AES192HS384_JWT`
      And I set request to JSON data
        | name       | value                    |  
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

Scenario: Generate an encrypted JWT with RSA1_5 Key and AES_256_GCM algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA1_5                   |  
        | jweAlgo    | AES_256_GCM              |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSA15_AES256GCM_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RSA15_AES256GCM_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA1_5                   |  
        | jweAlgo    | AES_256_GCM              |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an encrypted JWT with RSA_OAEP Key and AES_128_CBC_HMAC_SHA_256 algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSAOAEP_AES128HS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RSAOAEP_AES128HS256_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an encrypted JWT with RSA_OAEP Key and AES_192_GCM algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_192_GCM              |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSAOAEP_AES192GCM_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RSAOAEP_AES192GCM_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_192_GCM              |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an encrypted JWT with RSA_OAEP Key and AES_256_CBC_HMAC_SHA_512 algo and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSAOAEP_AES256HS512_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RSAOAEP_AES256HS512_JWT`
      And I set request to JSON data
        | name       | value                    |  
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

Scenario: Validation fails with public key
    Given I set Authorization header to Bearer `RSAOAEP_AES256HS512_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Validation fails with wrong private key
    Given I set Authorization header to Bearer `RSAOAEP_AES256HS512_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWS_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Validation fails with wrong key algo
    Given I set Authorization header to Bearer `RSAOAEP_AES256HS512_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA1_5                   |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Validation fails with wrong algo
    Given I set Authorization header to Bearer `RSAOAEP_AES256HS512_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_GCM              |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

    Given I set Authorization header to Bearer `RSAOAEP_AES256HS512_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-2                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Validation fails with wrong audience
    Given I set Authorization header to Bearer `RSAOAEP_AES256HS512_JWT`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `JWE_RSA_PRIVATE_KEY`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_256_CBC_HMAC_SHA_512 |  
        | issuer     | gen-1                    |  
        | audience   | aud-2                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Validation with correct param succeeds
    Given I set Authorization header to Bearer `RSAOAEP_AES256HS512_JWT`
      And I set request to JSON data
        | name       | value                    |  
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

Scenario: Generate an encrypted JWT with RSA_OAEP private key encryption and verify
    Given I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `RSA_PUBLIC_KEY`     |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | claims     | `CLAIMS`                 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
        | expiry     | 5                        |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RSAOAEP_AES128HS256_JWT_2 in global scope
    When I reset context
      And I set Authorization header to Bearer `RSAOAEP_AES128HS256_JWT_2`
      And I set request to JSON data
        | name       | value                    |  
        | jwe        | true                     |  
        | jweKey     | `RSA_PRIVATE_KEY_ENC`    |  
        | jweKeyPassword     | `RSA_PRIVATE_KEY_PASS`    |  
        | jweKeyAlgo | RSA_OAEP                 |  
        | jweAlgo    | AES_128_CBC_HMAC_SHA_256 |  
        | issuer     | gen-1                    |  
        | audience   | aud-1                    |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1