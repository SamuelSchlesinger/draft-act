---
title: "Privacy Pass Issuance Protocol for Anonymous Credit Tokens"
abbrev: "Privacy Pass Issuance Protocol for ACT"
category: std

docname: draft-schlesinger-privacypass-act-latest
submissiontype: IETF
consensus: true
number:
date:
v: 3
venue:
  group: PRIVACYPASS
  type: Privacy Pass
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
 -
    ins: S. Schlesinger
    name: Samuel Schlesinger
    organization: Google
    email: samschlesinger@google.com
 -
    ins: J. Katz
    name: Jonathan Katz
    org: Google
    email: jkcrypto@google.com

normative:
  ACT: I-D.draft-schlesinger-cfrg-act
  ARC: I-D.draft-yun-privacypass-arc
  ARC_PP: I-D.draft-yun-cfrg-arc
  ARCHITECTURE: RFC9576
  AUTHSCHEME: RFC9577
  ISSUANCE: RFC9578

informative:

--- abstract

This document specifies the issuance and redemption protocols for
tokens based on the Anonymous Credit Tokens (ACT) protocol.

--- middle

# Introduction

{{ARCHITECTURE}} describes the Privacy Pass architecture, and {{ISSUANCE}} and
{{AUTHSCHEME}} describe the issuance and redemption protocols for basic Privacy
Pass tokens, i.e., those computed using blind RSA signatures as specified in
{{Section 6 of ISSUANCE}} or verifiable oblivious pseudorandom functions as specified in {{Section 5 of ISSUANCE}}. Further, {{ARC}} scheme, and its associated integration in {{ARCHITECTURE}} {{ARC_PP}}, extends these approaches to multi-use
tokens.

The Anonymous Credit Tokens (ACT) protocol, as specified in {{ACT}}, offers a
differentiated approach to rate limiting from {{ARC}}. In particular,
ACT credentials can be presented up-to N times. When they
spend a certain number of credits from their token, their old token is
invalidated and they redeem a new token with the new balance.

This document specifies the issuance and redemption protocols for ACT. {{motivation}}
describes motivation for this new type of token, {{overview}} presents an overview
of the protocols, and the remainder of the document specifies the protocols themselves.

# Motivation

To demonstrate how ACT is useful, one can use a similar example to the
the one presented in {{Section 2 of ARC_PP}}: a client that wishes to keep its IP address private while accessing a service. {{ARC_PP}} offers the origin to limit the number of requests a client can make to N. This is enforced by each origin getting its own presentation context, and limiting the number of presentations per context to N. This means that, from a single token, we
can produce N presentations and access the system N times,
unlinkably. These presentations can be generated in parallel.

On the other hand, consider the case of an ACT with N credits in it. A client willing to redeem N different credits has to spend `1`, then get a refund, spend
`1`, then get a refund, and so on. Because the client can't spend `1` until they
get a refund for their previous credit, a single live
session is enforced per ACT. This provides
concurrency control. A client is also able to spend more than `1`, allowing for a more efficient redemption of multipe tokens.
Finally, as new presentation requires the obtention of a previous refund,
the origin gains the ability to invalidate a session by declining said refund.
This creates the
ability to shed harmful future traffic or redirect it in a favorable way.

One such use case for this is a privacy proxy, another is privately accessing
web APIs like the artificial intelligence models, and finally zero trust networks
which act as forward proxies for their user traffic.

Therefore, ACT provides the following properties

1. Concurrency control: Preventing multiple simultaneous uses of the same
credential, mitigating abuse from token sharing or replay.
2. Dynamic Revocation: Enabling immediate invalidation of tokens in response to
origin policy, without waiting for token expiry.
3. Per-Session Rate Limiting: Enforcing access policies that adapt to user,
device, or risk context, rather than static per-token limits. This creates incentives
for platform to deploy such methods.

# Terminology

{::boilerplate bcp14-tagged}

This document uses the terms Origin, Client, Issuer, and Token as defined in
{{Section 2 of ARCHITECTURE}}. Moreover, the following additional terms are
used throughout this document.

- Issuer Public Key: The public key (from a private-public key pair) used by
  the Issuer for issuing and verifying Tokens.
- Issuer Private Key: The private key (from a private-public key pair) used by
  the Issuer for issuing and verifying Tokens.

Unless otherwise specified, this document encodes protocol messages in TLS
notation from {{Section 3 of !TLS13=RFC8446}}. Moreover, all constants are in
network byte order.

# Protocol Overview {#overview}

The issuance and redemption protocols defined in this document are built on
the Anonymous Credit Tokens (ACT) protocol. ACT tokens can be thought of as
single use tokens, similar to the RSA Blind Signatures protocol. However,
by another viewpoint, they might be thought of as stateful, multi-use tokens.

With ACT, Clients receive TokenChallenge inputs from the redemption protocol
({{AUTHSCHEME, Section 2.1}}). If they have a valid ACT for the designated
Issuer, Clients can use the TokenChallenge to produce a single token for
presentation. Otherwise, Clients invoke the issuance protocol to obtain an
ACT. This interaction is shown below.

~~~ aasvg
                                      +--------------------------.
+--------+          +----------+      |  +--------+   +--------+  |
| Client |          | Attester |      |  | Issuer |   | Origin |  |
+---+----+          +-----+----+      |  +----+---+   +---+----+  |
    |                     |            `------|-----------|------'
    |                     |                   |           |
    |--------------------- Request ---------------------->|
    |<---------------- TokenChallenge --------------------+
    |                     |                   |           |
    |<=== Attestation ===>|                   |           |
    +----------- CredentialRequest ---------->|           |
    |<---------- CredentialResponse ----------+           |
    |                     |                   |           |
    |----------- Request + Token ------------------------>|
    |                     |                   |           |
~~~
{: #fig-overview title="Issuance and Redemption Overview"}

Similar to the core Privacy Pass protocols, the TokenChallenge can
be interactive or non-interactive, and per-origin or cross-origin.

ACT is only compatible with deployment models where the Issuer and Origin
are operated by the same entity (see {{Section 4 of ARCHITECTURE}}), as
tokens produced from a credential are not publicly verifiable. The details
of attestation are outside the scope of the issuance protocol; see
{{Section 4 of ARCHITECTURE}} for information about how attestation can
be implemented in each of the relevant deployment models.

The issuance and redemption protocols in this document are built on
{{ACT}}.

# Configuration {#setup}

ACT Issuers are configured with key material used for issuance and token
verification. Concretely, Issuers run the `KeyGen` function from {{ACT}}
to produce a private and public key, denoted skI and pkI, respectively.

~~~
skI, pkI = SetupServer()
~~~

The Issuer Public Key ID, denoted `issuer_key_id`, is computed as the
SHA-256 hash of the Issuer Public Key, i.e., `issuer_key_id = SHA-256(pkI_serialized)`,
where `pkI_serialized` is the serialized version of `pk` as described in {{Section 4.1 of ACT}} (TODO actually write and sync serialization, CBOR and TLS seems weird).

# Token Challenge Requirements {#token-challenge-requirements}

The ACT protocol uses a modified TokenChallenge structure from the one
specified in {{AUTHSCHEME}}. In particular, the updated TokenChallenge
structure is as follows:

~~~
struct {
    uint16_t token_type = 0xE5AC; /* Type ACT(Ristretto255) */
    opaque issuer_name<1..2^16-1>;
    opaque redemption_context<0..32>;
    opaque origin_info<0..2^16-1>;
    opaque credential_context<0..32>;
} TokenChallenge;
~~~

With the exception of `credential_context`, all fields are exactly as specified
in {{Section 2.1.1 of AUTHSCHEME}}. The `credential_context` field is defined as
follows:

- "credential_context" is a field that is either 0 or 32 bytes, prefixed with a single
octet indicating the length (either 0 or 32). If value is non-empty, it is a 32-byte value
generated by the origin that allows the origin to require that clients fetch credentials
bound to a specific context. Challenges with credential_context values of invalid lengths
MUST be ignored.

Similar to the `redemption_context` field, the `credential_context` is used to bind
information to the credential. This might be useful, for example, to enforce some
expiration on the credential. Origins might do this by constructing `credential_context`
as F(current time window), where F is a pseudorandom function. Semantically, this is
equivalent to the Origin asking the Client for a token from a credential that is
bound to "current time window."

OPEN ISSUE: give more guidance about how to construct credential_context and redemption_context depending on the application's needs.

In addition to this updated TokenChallenge, the HTTP authentication challenge
also SHOULD contain the following additional attribute:

- "cost", which contains a JSON number indicating the amount of credits to
  to spend out of the ARC.

Implementation-specific steps: the client should store the Origin-provided input `tokenChallenge` so that when they receive a new `tokenChallenge` value, they can check if it has changed and which fields are different. This will inform the client's behavior - for example, if `credential_context` is being used to enforce an expiration on the credential, then if the `credential_context` has changed, this can prompt the client to request a new credential.

# Credential Issuance Protocol

Issuers provide an Issuer Private and Public Key, denoted `skI` and `pkI`
respectively, used to produce tokens as input to the protocol. See {{setup}}
for how these keys are generated.

Clients provide the following as input to the issuance protocol:

- Issuer Request URL: A URL identifying the location to which issuance requests
  are sent. This can be a URL derived from the "issuer-request-uri" value in the
  Issuer's directory resource, or it can be another Client-configured URL. The value
  of this parameter depends on the Client configuration and deployment model.
  For example, in the 'Joint Origin and Issuer' deployment model, the Issuer
  Request URL might correspond to the Client's configured Attester, and the
  Attester is configured to relay requests to the Issuer.
- Issuer name: An identifier for the Issuer. This is typically a host name that
  can be used to construct HTTP requests to the Issuer.
- Issuer Public Key: `pkI`, with a key identifier `token_key_id` computed as
  described in {{setup}}.

Given this configuration and these inputs, the two messages exchanged in
this protocol to produce a credential are described below.

## Client-to-Issuer Request

Given Origin-provided input `tokenChallenge` and the Issuer Public Key ID `issuer_key_id`,
the Client first creates a credential request message using the `CredentialRequest`
function from {{ACT}} as follows:

~~~
request_context = concat(tokenChallenge.issuer_name,
  tokenChallenge.origin_info,
  tokenChallenge.credential_context,
  issuer_key_id)
(clientSecrets, request) = CredentialRequest(request_context)
~~~

The Client then creates a TokenRequest structure as follows:

~~~
struct {
  uint16_t token_type = 0xE5AD; /* Type ACT(Ristretto255) */
  uint8_t truncated_issuer_key_id;
  uint8_t encoded_request[Nrequest];
} TokenRequest;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer.

- "truncated_issuer_key_id" is the least significant byte of the `issuer_key_id`
  ({{setup}}) in network byte order (in other words, the last 8
  bits of `issuer_key_id`). This value is truncated so that Issuers cannot use
  `issuer_key_id` as a way of uniquely identifying Clients; see {{security}}
  and referenced information for more details.

- "encoded_request" is the Nrequest-octet request, computed as the serialization
  of the `request` value as defined in {{Section 4.2.1 of ARC}}.

The Client then generates an HTTP POST request to send to the Issuer Request URL,
with the TokenRequest as the content. The media type for this request is
"application/private-credential-request". An example request for the Issuer Request URL
"https://issuer.example.net/request" is shown below.

~~~
POST /request HTTP/1.1
Host: issuer.example.net
Accept: application/private-credential-response
Content-Type: application/private-credential-request
Content-Length: <Length of TokenRequest>

<Bytes containing the TokenRequest>
~~~

## Issuer-to-Client Response

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported token_type equal to value 0xE5AD.
- The TokenRequest.truncated_token_key_id corresponds to the truncated key ID
  of an Issuer Public Key, with corresponding secret key `skI`, owned by
  the Issuer.
- The TokenRequest.encoded_request is of the correct size (`Nrequest`).

If any of these conditions is not met, the Issuer MUST return an HTTP 422
(Unprocessable Content) error to the client.

If these conditions are met, the Issuer then tries to deserialize
TokenRequest.encoded_request according to {{Section 4.2.1 of ARC}}, yielding `request`.
If this fails, the Issuer MUST return an HTTP 422 (Unprocessable Content)
error to the client. Otherwise, if the Issuer is willing to produce a credential
for the Client, the Issuer completes the issuance flow by an issuance response
as follows:

~~~
response = CredentialResponse(skI, pkI, request)
~~~

The Issuer then creates a TokenResponse structured as follows:

~~~
struct {
   uint8_t encoded_response[Nresponse];
} TokenResponse;
~~~

The structure fields are defined as follows:

- "encoded_response" is the Nresponse-octet encoded issuance response message, computed
  as the serialization of `response` as specified in {{Section 4.1.2 of ACT}}.

The Issuer generates an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-credential-response".

~~~
HTTP/1.1 200 OK
Content-Type: application/private-credential-response
Content-Length: <Length of TokenResponse>

<Bytes containing the TokenResponse>
~~~

## Credential Finalization

Upon receipt, the Client handles the response and, if successful, deserializes
the content values `TokenResponse.encoded_response` according to {{Section 4.1.2 of ARC}}
yielding `response`. If deserialization fails, the Client aborts the protocol.
Otherwise, the Client processes the response as follows:

~~~
credential = VerifyIssuance(clientSecrets, pkI, request, response)
~~~

The Client then saves the credential structure, associated with the given Issuer
Name, to use when producing Token values in response to future token challenges.

# Token Redemption Protocol

The token redemption protocol takes as input TokenChallenge and cost
values from {{AUTHSCHEME, Section 2.1}}; the cost is sent as an additional
attribute within the HTTP challenge as described in {{token-challenge-requirements}}.
Clients use credentials from the issuance protocol in producing tokens
bound to the TokenChallenge. The process for producing a token in this
way, as well as verifying a resulting token, is described in the following sections.

## Token Creation

Given a TokenChallenge value as input, denoted `challenge`, a cost,
denoted `cost`, and a previously computed credential that is valid
for the Issuer identifier in the challenge, denoted `credential`, containing at
least `cost` credits. Clients compute a spend request as follows:

~~~
spend_request, state = ProveSpend(credential, cost)
~~~

This credential MUST only ever be used for a single spend request. When we
receive the refund from the server, we will be able to use this credential
instead. If we use the same credential more than once, we violate the privacy
assumptions of ACT by presenting the same nullifier twice.

The resulting Token value is then constructed as follows:

~~~
struct {
    uint16_t token_type = 0xE5AD; /* Type ACT(Ristretto255) */
    uint8_t challenge_digest[32];
    uint8_t issuer_key_id[Nid];
    uint8_t spend_request[Npresentation];
} Token;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, in network byte order, equal to 0xE5AC.

- "challenge_digest" is a 32-octet value containing the hash of the original TokenChallenge, SHA-256(TokenChallenge).

- "nullifier" is a 32-octet value containing the single-use nullifier from the credential.

- "issuer_key_id" is a Nid-octet identifier for the Issuer Public Key, computed
as defined in {{setup}}.

- "spend_request" is a Nspend_request-octet spend_request, set to the serialized
`spend_request` value (see {{Section 4.1.3 of ACT}} for serialiation details).

## Token Refund {#refund}

Given a deserialized spend_request from the token, denoted `spend_request` and
obtained by deserializing a spend_request according to {{Section 4.1.3 of ARC}},
a cost, denoted `cost`, a nullifier from a token, denoted `nullifier`, and the
digest of a token challenge, denoted `challenge_digest`, verifying a Token requires
invoking the VerifyAndRefund function from {{Section 3.4.2 of ACT}} in the following ways:

~~~
request_context = concat(tokenChallenge.issuer_name,
  tokenChallenge.origin_info,
  tokenChallenge.credential_context,
  issuer_key_id)
refund = VerifyAndRefund(skI, requestContext, spend_proof, cost)
~~~

This function returns the `refund` serialized according to {{Section 4.1.4 of ACT}} if the CredentialToken is valid, and nil otherwise.

Implementation-specific steps: to prevent double spending, the Origin should perform a check that the
nullifier (spend_proof.nullifier) has not previously been seen. It then stores the tag for use in future double
spending checks. To reduce the overhead of performing double spend checks, the Origin can store and
look up the tags corresponding to the associated request_context value.

~~~
struct {
    uint8_t refund[Nrefund];
} Refund;
~~~

Finally, we send down the refund back to the client encoded as the above `Refund` struct.

## New Token from Refund

Differently from {{ARC}}, we have to reconstruct our new token based on the `Refund` response. To do
so, we invoke the `ConstructRefundToken` from {{Section 3.4.4 of ACT}} in the following ways:

~~~
token = ConstructRefundToken(pkI, spend_proof, refund, state)
~~~

Now, finally, we can replace our old credential with this new one and this one can be properly used.

# Security Considerations {#security}

Privacy considerations for tokens based on deployment details, such as issuer configuration
and issuer selection, are discussed in {{Section 6.1 of ARCHITECTURE}}. Note that ACT
requires a joint Origin and Issuer configuration given that it is privately verifiable.

ACT offers Origin-Client unlinkability, Issuer-Client unlinkability, and redemption context
unlinkability, as described in {{Section 3.3 of ARCHITECTURE}}.

# IANA Considerations

This document updates the "Privacy Pass Token Type" Registry with the
following entries.

* Value: 0xE5AD
* Name: ACT (Ristretto255)
* Token Structure: As defined in {{Section 2.2 of AUTHSCHEME}}
* Token Key Encoding: Serialized as described in {{setup}}
* TokenChallenge Structure: As defined in {{Section 2.1 of AUTHSCHEME}}
* Public Verifiability: N
* Public Metadata: N
* Private Metadata: N
* Nk: 0 (not applicable)
* Nid: 32
* Reference: This document
* Notes: None


--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank Cathie Yun, Thibault Meunier, and Chris Wood.
