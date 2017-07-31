Feature: Check if signed JWTs can be verified correctly

Scenario: Generate a valid JWT and sign it using HMAC_SHA512 and verify
    Given I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA512           |  
        | claims   | `CLAIMS`              |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
        | expiry   | 5                     |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as HS512_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `HS512_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA512           |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate an expired JWT and sign it using HMAC_SHA512 and verify
    Given I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA512           |  
        | claims   | `CLAIMS`              |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
        | expiry   | 0                     |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as CURRENT_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `EXPIRED_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA512           |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Generate a valid JWT and sign it using HMAC_SHA256 and verify
    Given I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA256           |  
        | claims   | `CLAIMS`              |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
        | expiry   | 5                     |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as HS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `HS256_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA256           |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate a valid JWT and sign it using HMAC_SHA384 and verify
    Given I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA384           |  
        | claims   | `CLAIMS`              |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
        | expiry   | 5                     |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as HS384_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `HS384_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA384           |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Re-Validation of JWT with correct params
    Given I set Authorization header to Bearer `HS384_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA384           |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Validation of JWT fails with wrong sign algo
    Given I set Authorization header to Bearer `HS384_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA256           |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Validation of JWT fails with wrong sign key
    Given I set Authorization header to Bearer `HS384_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | abcde12345            |  
        | jwsAlgo  | HMAC_SHA384           |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Validation of JWT fails with wrong issuer
    Given I set Authorization header to Bearer `HS384_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA384           |  
        | issuer   | gen-2                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Validation of JWT fails with wrong audience
    Given I set Authorization header to Bearer `HS384_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_HS_KEY`          |  
        | jwsAlgo  | HMAC_SHA384           |  
        | issuer   | gen-1                 |  
        | audience | aud-2                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 401

Scenario: Generate a valid JWT and sign it using RSA_USING_SHA256 and verify
    Given I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_RSA_PRIVATE_KEY` |  
        | jwsAlgo  | RSA_USING_SHA256      |  
        | claims   | `CLAIMS`              |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
        | expiry   | 5                     |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RS256_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RS256_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_RSA_PUBLIC_KEY`  |  
        | jwsAlgo  | RSA_USING_SHA256      |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate a valid JWT and sign it using RSA_USING_SHA384 and verify
    Given I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_RSA_PRIVATE_KEY` |  
        | jwsAlgo  | RSA_USING_SHA384      |  
        | claims   | `CLAIMS`              |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
        | expiry   | 5                     |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RS384_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RS384_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_RSA_PUBLIC_KEY`  |  
        | jwsAlgo  | RSA_USING_SHA384      |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate a valid JWT and sign it using RSA_USING_SHA512 and verify
    Given I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_RSA_PRIVATE_KEY` |  
        | jwsAlgo  | RSA_USING_SHA512      |  
        | claims   | `CLAIMS`              |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
        | expiry   | 5                     |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RS512_JWT in global scope
    When I reset context
      And I set Authorization header to Bearer `RS512_JWT`
      And I set request to JSON data
        | name     | value                 |  
        | jws      | true                  |  
        | jwsKey   | `JWS_RSA_PUBLIC_KEY`  |  
        | jwsAlgo  | RSA_USING_SHA512      |  
        | issuer   | gen-1                 |  
        | audience | aud-1                 |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1

Scenario: Generate a valid JWT and sign it using RSA_USING_SHA512 with private key password encryption and verify
    Given I set request to JSON data
        | name           | value                  |  
        | jws            | true                   |  
        | jwsKey         | `RSA_PRIVATE_KEY_ENC`  |  
        | jwsKeyPassword | `RSA_PRIVATE_KEY_PASS` |  
        | jwsAlgo        | RSA_USING_SHA512       |  
        | claims         | `CLAIMS`               |  
        | issuer         | gen-1                  |  
        | audience       | aud-1                  |  
        | expiry         | 5                      |  
      And I POST to /v1/jwt-generate-api
      And I store the value of body path id_token as RS512_JWT_2 in global scope
    When I reset context
      And I set Authorization header to Bearer `RS512_JWT_2`
      And I set request to JSON data
        | name     | value            |  
        | jws      | true             |  
        | jwsKey   | `RSA_PUBLIC_KEY` |  
        | jwsAlgo  | RSA_USING_SHA512 |  
        | issuer   | gen-1            |  
        | audience | aud-1            |  
      And I POST to /v1/jwt-validate-api
    Then response code should be 200
      And response body path $.sub should be John Doe
      And response body path $.email should be johndoe@gmail.com
      And response body path $.iss should be gen-1
      And response body path $.aud should be aud-1