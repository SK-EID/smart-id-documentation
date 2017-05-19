# Table of Contents

* [1. Introduction](#1-introduction)
    * [1.1. Terminology](#11-terminology)
* [2. References](#2-references)
* [3. General description](#3-general-description)
    * [3.1. UUID encoding](#31-uuid-encoding)
    * [3.2. relyingPartyName handling](#32-relyingpartyname-handling)
    * [3.3. Hash algorithms](#33-hash-algorithms)
    * [3.4. Relying Party authentication](#34-relying-party-authentication)
    * [3.5. API endpoint authentication](#35-api-endpoint-authentication)
* [4. REST API](#4-rest-api)
    * [4.1. Interface patterns](#41-interface-patterns)
        * [4.1.1. Session management](#411-session-management)
        * [4.1.2. REST object references](#412-rest-object-references)
        * [4.1.3. HTTP status code usage](#413-http-status-code-usage)
        * [4.1.4. Response on successful session creation](#414-response-on-successful-session-creation)
        * [4.1.5. Idempotent behaviour](#415-idempotent-behaviour)
    * [4.2. REST API main flows](#42-rest-api-main-flows)
    * [4.3. Certificate choice session](#43-certificate-choice-session)
        * [4.3.1. Preconditions](#431-preconditions)
        * [4.3.2. Postconditions](#432-postconditions)
        * [4.3.3. Error conditions](#433-error-conditions)
        * [4.3.4. Request parameters](#434-request-parameters)
        * [4.3.5. Example response](#435-example-response)
    * [4.4. Authentication session](#44-authentication-session)
        * [4.4.1. Preconditions](#441-preconditions)
        * [4.4.2. Postconditions](#442-postconditions)
        * [4.4.3. Error conditions](#443-error-conditions)
        * [4.4.4. Authentication request parameters](#444-authentication-request-parameters)
        * [4.4.5. Example response](#445-example-response)
    * [4.5. Signing session](#45-signing-session)
        * [4.5.1. Preconditions](#451-preconditions)
        * [4.5.2. Postconditions](#452-postconditions)
        * [4.5.3. Error conditions](#453-error-conditions)
        * [4.5.4. Request parameters](#454-request-parameters)
        * [4.5.5. Example response](#455-example-response)
    * [4.6. Session status](#46-session-status)
        * [4.6.1. Preconditions](#461-preconditions)
        * [4.6.2. Postconditions](#462-postconditions)
        * [4.6.3. Error conditions](#463-error-conditions)
        * [4.6.4. Response structure](#464-response-structure)
* [5. Session end result codes](#5-session-end-result-codes)
* [6. Protocols](#6-protocols)
    * [6.1. Authentication protocol](#61-authentication-protocol)
        * [6.1.1. Sending authentication request](#611-sending-authentication-request)
        * [6.1.2. Computing the verification code](#612-computing-the-verification-code)
        * [6.1.3. Verifying the authentication response](#613-verifying-the-authentication-response)
* [7. Known issues](#7-known-issues)

# 1. Introduction

Relying Party interface offers the entry point to Smart-ID main use cases, i.e. authentication and signing.

The interface is to be used by all parties who wish consume Smart-ID services, i.e. ask end users to perform authentication and signing operations.

*Cybernetica AS reference: Y-952-4, version 6.0.*

## 1.1. Terminology

* **Document number** - A unique number given to end user accounts in Smart-ID system, identifies a particular set of end user cryptographic key pairs with their certificates.
* **Relying Party (RP)** - a provider of some kind of e-service (like an internet banking site or government agency website), or, technically, that same e-service. Relying Party authenticates users via Smart-ID service and requests digital certificates from them.
* **Session** - Alternatively, "RP Request". A process initated by Relying Party, which contains a single certificate choice, authentication or signing operation.

# 2. References

* R. Fielding et al. Hypertext Transfer Protocol – HTTP/1.1. RFC 2616 (Draft Standard). Internet Engineering Task Force, June 1999. URL: http://www.ietf.org/rfc/rfc2616.txt.

# 3. General description

Relying Party API is exposed over a REST interface as described below.

All messages are encoded using UTF-8.

## 3.1. UUID encoding

UUID values are encoded as strings containing hexadecimal digits, in canonical 8-4-4-4-12 format, i.e. de305d54-75b4-431b-adb2-eb6b9e546014.

Smart-ID uses version 4 (random) UUID values.

## 3.2. relyingPartyName handling

relyingPartyName request field is case insensitive, must match one of the names configured for the calling RP.

The string is passed to end user as sent in via API.

## 3.3. Hash algorithms

Smart-ID supports signature operations based on SHA-2 family of hash algorithms, namely SHA-256, SHA-384 and SHA-512. Their corresponding identifiers in APIs are "SHA256", "SHA384" and "SHA512".

## 3.4. Relying Party authentication

Interface users are authenticated based on their originating IP-address and relyingPartyUUID protocol parameter combinations.

When authentication fails, server must respond with HTTP error 401.

## 3.5. API endpoint authentication

It is essential that RP performs all the required checks when connecting to the HTTPS API endpoint, to make sure that the connection endpoint is authentic and that the connection is secure. This is required to prevent MITM attacks for the authentication and signature protocols.

The RP must do the following checks:

1. Verify if the HTTPS connection and the TLS handshake is performed with the secure TLS ciphersuite.
1. Verify that the X.509 certificate of the HTTPS endpoint belongs to the well-known public key of the Smart-ID API. The RP must implement HTTPS pinning (https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning)
1. Verify that the X.509 certificate of the HTTPS endpoint is valid (not expired, signed by trusted CA and not revoked)

In case the RP fails to verify the connection security and the attacks is able to launch MITM attack (https://en.wikipedia.org/wiki/Man-in-the-middle_attack) on the connection and circumvent the connection authentication, the following attack is possible:

1. End user connects to the RP website and asks for the authentication with the Smart-ID.
1. RP connects to the authentication API endpoint, but attacker is able to MITM the connection and answer himself.
1. RP sends the correctly formed authentication request with randomly generated hash (h1) to the attacker, acting as the Smart-ID API.
1. Attacker creates another connection to the RP website and asks for the authentication with the Smart-ID, under the identity of same end user.
1. RP connects to the authentication API endpoint, but attacker is able MITM the connection and answer himself.
1. RP sends the correctly formed authentication request with randomly generated hash (h2) to the attacker, acting as the Smart-ID API.
1. Attacker computes the VC values for both hashes, i.e.
  1. vc1 = integer(SHA256(h1)[−2:−1]) mod 10000
  1. vc2 = integer(SHA256(h2)[−2:−1]) mod 10000
1. If the vc1 != vc1, the attacker drops the connection to the RP website and creates a new one. The connections are tried until the randomly generated hash value yields the same VC value as the vc1. It should take about 5000 tries, before such collision is found.
1. The attacker sends the authentication request with the hash value h2 to the Smart-ID authentication API endpoint.
1. Smart-ID sends the authentication request to the end user mobile device and asks to verify the VC.
1. End user compares the vc1 displayed on the browser to the vc2 displayed on the mobile device and finds that they are equivalent and consents to the authentication.
1. Attacker receives the authentication response from the Smart-ID API and returns this to the RP connected, associated with the attacker's session.
1. RP receives the authentication response with the signature on the hash h2, verifies that the signature is valid and creates authenticated session for the attacker, under the end user identity.
1. The attacker is logged in as the end user.

# 4. REST API

## 4.1. Interface patterns

BASE URL value is given in service documentation and may vary between environments and service instances.The base URL for SK DEMO environment is  https://sid.demo.sk.ee/smart-id-rp/v1/NB! The production environment base URL is different and it's fixed in service agreement.

### 4.1.1. Session management

Base of all operations on the API is a "session".

Session is created using one of the POST requests and it ends when a result gets created or when session ends with an error.

Session is identified by an ID, in reality a long random string.

Session is created for one of the three operations:

* Authentication
* Signing certificate choice (needed for certain digital signature schemes, see below)
* Signing 

Session result can be obtained using a GET request described below.

### 4.1.2. REST object references

* Objects referenced by "pno/:country/:national-identity-number" are natural persons identified by their ETSI PNO-type identifier (i.e. PNOEE-12345 becomes pno/EE/12345)
  * Please not that the country code here conforms to ISO 3166-1 alpha-2 code and as such **must me in upper case**.
* Objects referenced by "document/:documentnumber" are particular documents (also known as user accounts) in the Smart-ID system.

### 4.1.3. HTTP status code usage

Normally, all positive responses are given using HTTP status code "200 OK".

In some cases, 4xx series error codes are used, those cases are described per request.

All 5xx series error codes indicate some kind of fatal server error.

There are two custom status codes which are specific to this interface:

* **480** - The client (i.e. client-side implementation of this API) is old and not supported any more. Relying Party must contact customer support.
* **580** - System is under maintenance, retry later.

### 4.1.4. Response on successful session creation

This response is returned from all POST method calls that create a new session.

Parameter | Type | Mandatory | Description
----------|------|-----------|------------
sessionID | string | + | A string that can be used to request operation result, see below.

**successful session creation response:**
```
{	
      "sessionID": "de305d54-75b4-431b-adb2-eb6b9e546014"
}
```


### 4.1.5. Idempotent behaviour

Whenever a RP session creation request (POST to certificatechoice/, signature/, authentication/) is repeated inside a given timeframe with exactly the same parameters, session ID of an existing session can be returned as a result.

This allows to retry RP POST requests in case of communication errors.

Retry timeframe is **15 seconds**.

When requestor wants, it can override the idempotent behaviour inside of this timeframe using an optional "nonce" parameter present for all POST requests. Normally, that parameter can be omitted.

## 4.2. REST API main flows

![RP API sequences](https://github.com/raunotali/rauno-pokes-at-smartid-doc/blob/master/images/RP_API_sequences_REST.png)

## 4.3. Certificate choice session

Method | URL
-------|----
POST | BASE/certificatechoice/pno/:country/:national-identity-number
POST | BASE/certificatechoice/document/:documentnumber


Initiates certificate choice between multiple signing certificates the user may hold on his/her different mobile devices.

Having a correct certificate is needed for giving signatures under *AdES schemes.

**This method can be ignored if the signature scheme does not mandate presence of certificate under the signature itself.**

This method initiates a certificate (device) choice dialogue on end user's device, so it may not be called without explicit need (i.e. it may be called only as the first step in signing process).

### 4.3.1. Preconditions

* User identified in the request (either by PNO identifier or document number) is present in the system.
* User has certificate(s) with level which is equal to or higher than the level requested.

### 4.3.2. Postconditions

* New session has been created in the system and its ID returned to Relying Party.

### 4.3.3. Error conditions

* HTTP error code 403 - Relying Party has no permission to issue the request. This may happen when:
  * Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
* HTTP error code 404 - object described in URL was not found, essentially meaning that the user does not have account in Smart-ID system.

### 4.3.4. Request parameters

Parameter | Type | Mandatory | Description
----------|------|-----------|------------
relyingPartyUUID | string | + | UUID of Relying Party
relyingPartyName | string | + | RP friendly name, one of those configured for particular RP
certificateLevel | string |   | Level of certificate requested. "ADVANCED"/"QUALIFIED". **Defaults to "QUALIFIED".**
nonce | string |   | Random string, up to 30 characters. If present, must have at least 1 character.

**Certificate choice request:**
```
{
	"relyingPartyUUID": "de305d54-75b4-431b-adb2-eb6b9e546014",
	"relyingPartyName": "BANK123",
	"certificateLevel": "ADVANCED"
}
```
### 4.3.5. Example response

**Certificate choice session creation response:**
```
{	
      "sessionID": "de305d54-75b4-431b-adb2-eb6b9e546014"
}
```


## 4.4. Authentication session

Method | URL
-------|----
POST | BASE/authentication/pno/:country/:national-identity-number
POST | BASE/authentication/document/:documentnumber

This method is the main entry point to authentication logic.

It selects user's authentication key as the one to be used in the process.

### 4.4.1. Preconditions

* User identified in the request (either by PNO identifier or document number) is present in the system.
* User (as limited by the previous point) has at least one account with given or higher certificate level.

### 4.4.2. Postconditions

* New session has been created in the system and its ID returned to Relying Party.

### 4.4.3. Error conditions

* HTTP error code 403 - Relying Party has no permission to issue the request. This may happen when:
  * Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
* HTTP error code 404 - object described in URL was not found, essentially meaning that the user does not have account in Smart-ID system.

### 4.4.4. Authentication request parameters

Parameter | Type | Mandatory | Description
----------|------|-----------|------------
relyingPartyUUID | string | + | UUID of Relying Party
relyingPartyName | string | + | RP friendly name, one of those configured for particular RP
certificateLevel | string |   | Level of certificate requested. "ADVANCED"/"QUALIFIED". **Defaults to "QUALIFIED".**
hash | string | + | Base64 encoded hash function output to be signed.hashTypestring+Hash algorithm. See hash algorithm section.
displayText | string |  | Text to display for authentication consent dialog on the mobile device
nonce | string |   | Random string, up to 30 characters. If present, must have at least 1 character.

**Authentication request:**
```
{
   "relyingPartyUUID": "de305d54-75b4-431b-adb2-eb6b9e546014",
   "relyingPartyName": "BANK123",
   "certificateLevel": "ADVANCED"
   "hash": "ZHNmYmhkZmdoZGcgZmRmMTM0NTM...",
   "hashType": "SHA512",
   "displayText": "Log into internet banking system"
}
```

### 4.4.5. Example response

**Authentication session creation response:**
```
{	
      "sessionID": "de305d54-75b4-431b-adb2-eb6b9e546015"
}
```

## 4.5. Signing session

 Method | URL | Notes
 -------|-----|------
 POST | BASE/signature/document/:documentnumber | 
 POST | BASE/signature/pno/:country/:national-identity-number | **See description below, this method must be used with care.**


This method is the main entry point to signature logic.

There are two main modes of signature operation and Relying Party must choose carefully between them. They look like the ones used in case of authentication, but there are important differences.

* **Signature by document number.** This is the main and common usage scenario. Document number can be obtained from result of certificate choice operation or authentication result. It is vitally important that signatures using any of the *AdES signature schemes that include certificate as part of signature use this method. Otherwise, the signature may be given by the person specified, but not using the key pair corresponding to the certificate chosen by Relying Party.
* **Signature by person's identifier.** This method should only be used if it is acceptable that the end user gives the signature using any of the Smart-ID devices at his/her possession (which is normally not the case).

### 4.5.1. Preconditions

* User identified in the request (either by PNO identifier or document number) is present in the system.
* User (as limited by the previous point) has at least one account with given or higher certificate level.
* RP knows the user's signing certificate related to particular document, if needed by signature scheme.

### 4.5.2. Postconditions

* A new RP request request and a related transaction record has been created.

### 4.5.3. Error conditions

* HTTP error code 403 - Relying Party has no permission to issue the request. This may happen when:
 * Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
* HTTP error code 404 - object described in URL was not found, essentially meaning that the user does not have account in Smart-ID system.

### 4.5.4. Request parameters 

Parameter | Type | Mandatory | Description
----------|------|-----------|------------
relyingPartyUUID | string | + | UUID of Relying Party
relyingPartyName | string | + | RP friendly name, one of those configured for particular RP
certificateLevel | string |   | Level of certificate requested. "ADVANCED"/"QUALIFIED". **Defaults to "QUALIFIED".**
hash | string | + | Base64 encoded hash function output to be signed.hashTypestring+Hash algorithm. See hash algorithm section.
displayText | string |  | Text to display for authentication consent dialog on the mobile device
nonce | string |   | Random string, up to 30 characters. If present, must have at least 1 character.
 
**Signature request:**
```
{
   "relyingPartyUUID": "de305d54-75b4-431b-adb2-eb6b9e546014",
   "relyingPartyName": "BANK123",
   "certificateLevel": "ADVANCED"
   "hash": "ZHNmYmhkZmdoZGcgZmRmMTM0NTM...",
   "hashType": "SHA512",
   "displayText": "Authorize transfer of £10"
}
```

### 4.5.5. Example response

**Signature session creation response:**
```
{	
      "sessionID": "de305d54-75b4-431b-adb2-eb6b9e546016"
}
```

## 4.6. Session status

Method | URL
-------|----
GET | BASE/session/:sessionId

**Query parameter****Contents**timeoutMs
Request long poll timeout value in milliseconds. If not provided, a default is used. Server configuration may force this value into a certain range, see server configuration documentation for details.

This method can be used to retrieve session result from Smart-ID backend.

This is a long poll method, meaning it might not return until a timeout expires. Caller can tune the request parameters inside the bounds set by service operator.

Example URL:

**https://sid.demo.sk.ee/smart-id-rp/v1/session/de305d54-75b4-431b-adb2-eb6b9e546016?timeoutMs=10000**

### 4.6.1. Preconditions

* Session is present in the system and the request is either running or has been completed less than 5 minutes ago.

### 4.6.2. Postconditions

*  Request result has been returned to RP.

### 4.6.3. Error conditions

* HTTP error code 404 - session does not exist or is too old or has expired.  

### 4.6.4. Response structure 

Parameter | Type | Mandatory | Description
----------|------|-----------|------------
state | string | + | State of request. "RUNNING"/"COMPLETE". There are only two possible status codes for now.
result | object |  | Structure describing end result, may be empty or missing when still running
result.endResult | string | + | End result of the transaction. Refer to the subsection below.
result.documentNumber | string | for OK | Document number, can be used in further signature and authentication requests to target the same device.
signature | object |   | Structure describing the signature result, if any.
signature.value | string | + | Signature value, base64 encoded.
signature.algorithm | string | + | Signature algorithm, in the form of sha256WithRSAEncryption
cert | object | for OK | Structure describing the certificate related to request.
cert.value | string | + | Certificate value, DER+Base64 encoded.
cert.assuranceLevel | string |   | **DEPRECATED. **Please use cert.certificateLevel parameter instead.
cert.certificateLevel | string | + | Level of Smart-ID certificate: **ADVANCED** - Used for Smart-ID basic. **QUALIFIED** - Used for Smart-ID. This means that issued certificate is qualified.

**successful response when still waiting for user's response:**
```
{
    "state": "RUNNING",
    "result": {}
}
```

**successful response after completion:**
```
{
    "state": "COMPLETE",
	"result": {
            "endResult": "OK",
            "documentNumber": "PNOEE-372...."
    },
    "signature": {
        "value": "B+C9XVjIAZnCHH9vfBSv...",
        "algorithm": "sha512WithRSAEncryption"
    },
    "cert": {
        "value": "B+C9XVjIAZnCHH9vfBSv...",
        "assuranceLevel": "http://eidas.europa.eu/LoA/substantial",
		"certificateLevel": "QUALIFIED"
    }
}
```


# 5. Session end result codes

* **OK** - session was completed successfully, there is a certificate, document number and possibly signature in return structure.
* **USER_REFUSED** - user refused the session.
* **TIMEOUT** - there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe.
* **DOCUMENT_UNUSABLE** - for some reason, this RP request cannot be completed. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.

# 6. Protocols

Previous sections give the overview of the specific API methods, which can be used to perform the authentication and signature operations. This section gives the overview of how to securely combine them and how to deduce the operation result.

## 6.1. Authentication protocol

### 6.1.1. Sending authentication request

The RP must create the new hash value for each new authentication request. The recommended way of doing this is to use the Java SecureRandom class (https://docs.oracle.com/javase/7/docs/api/java/security/SecureRandom.html) or equivalent method in other programming languages, to generated random value for each new authentication request.

For example, the following code snippet generates the 64 random bytes and computes the hash value and encodes it in Base64.

```
    SecureRandom random = new SecureRandom();
    byte randBytes[] = new byte[64];
    random.nextBytes(randBytes);
	MessageDigest md = MessageDigest.getInstance("SHA-512");
	md.update(randBytes);
	byte[] hash = md.digest();
	byte[] encodedHash = Base64.encodeBase64(hash);
```

The value of the 'encodedHash' must be recorded in the current user's session for later comparison.

### 6.1.2. Computing the verification code

The RP must then compute the verification code for this authentication request, so that user can bind together the session on the browser and the authentication request on the Smart-ID app. The VC is computed as

```
integer(SHA256(hash)[−2:−1]) mod 10000
```

where we take SHA256 result, extract 2 rightmost bytes from it, interpret them as a big-endian unsigned integer and take the last 4 digits in decimal for display. SHA256 is always used here, no matter what was the algorithm used to calculate hash.

Please mind that hash is real hash byte value (for example, the byte array returned from the md.digest() call), not Base64 form used for transport.

The VC value must be displayed to the user in the browser together with a message that ask the end user to verify the code.

### 6.1.3. Verifying the authentication response

After receiving the transaction response from the getRequestResult() API call, the following algorithm must be used to decide, if the authentication result is trustworthy and what is the identity of the authentication end user.

* "result.endResult" has the value "OK"
* "signature.value" is the valid signature over the same "hash", which was submitted by the RP.
* "signature.value" is the valid signature, verifiable with the public key inside the certificate of the user, given in the field "cert.value"
* The person's certificate given in the "cert.value" is valid (not expired, signed by trusted CA and with correct (i.e. the same as in response structure, greater than or equal to that in the original request) level).
* The identity of the authenticated person is in the 'subject' field of the included X.509 certificate.

After successful authentication, the RP must invalidate the old user's browser or API session identifier and generate a new one.

# 7. Known issues

# This repo / TODO

Should be automated:
- header counts
Should not be automated:
- two lists in one chapter are numbered
IDK if should be automated:
- images
- i might shoot myself before i get table creation to work in a fully automated way
