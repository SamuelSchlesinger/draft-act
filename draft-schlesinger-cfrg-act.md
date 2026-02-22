---
title: "Anonymous Credit Tokens"
abbrev: "ACT"
category: info

docname: draft-schlesinger-cfrg-act-latest
submissiontype: IRTF
number:
date:
v: 3
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg"
  github: "SamuelSchlesinger/draft-act"
  latest: "https://SamuelSchlesinger.github.io/draft-act/draft-schlesinger-cfrg-act.html"

author:
 -
    fullname: Samuel Schlesinger
    organization: Google
    email: samschlesinger@google.com
 -
    fullname: Jonathan Katz
    organization: Google
    email: jkcrypto@google.com

normative:
  RFC2119:
  RFC6090:
  RFC8174:
  RFC8949:
  RFC9380:
  RFC9496:
  BLAKE3:
    title: "BLAKE3: One Function, Fast Everywhere"
    target: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
    date: 2020-01-09
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: 2009-05-21
  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    target: https://www.secg.org/sec2-v2.pdf
    date: 2010-01-27

informative:
  RFC9474:
  ORRU-SIGMA:
    title: "Sigma Protocols"
    target: https://www.ietf.org/archive/id/draft-orru-zkproof-sigma-protocols-00.txt
    date: 2025-01-19
  ORRU-FS:
    title: "The Fiat-Shamir Transform"
    target: https://mmaker.github.io/draft-zkproof-sigma-protocols/draft-orru-zkproof-fiat-shamir.html
    date: 2025-01-19
  BBS:
    title: "Short Group Signatures"
    target: https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf
    date: 2004
  KVAC:
    title: "Keyed-Verification Anonymous Credentials"
    target: https://eprint.iacr.org/2013/516.pdf
    date: 2014
  TZ23:
    title: "Revisiting BBS Signatures"
    target: https://eprint.iacr.org/2023/275
    date: 2023
...

--- abstract

This document specifies Anonymous Credit Tokens (ACT), a
privacy-preserving authentication protocol that enables numerical
credit systems without tracking individual clients. Based on
keyed-verification anonymous credentials and privately verifiable
BBS-style signatures, the protocol allows issuers to grant tokens
containing credits that clients can later spend anonymously with
that issuer.

The protocol's key features include: (1) unlinkable transactions -
the issuer cannot correlate credit issuance with spending, or link
multiple spends by the same client, (2) partial spending - clients
can spend a portion of their credits and receive anonymous change,
and (3) double-spend prevention through cryptographic nullifiers
that preserve privacy while ensuring each token is used only once.

Anonymous Credit Tokens are designed for modern web services
requiring rate limiting, usage-based billing, or resource allocation
while respecting user privacy. Example applications include rate
limiting and API credits.

This document is a product of the Crypto Forum Research Group (CFRG)
in the IRTF.

--- middle

# Introduction

Modern web services face a fundamental tension between operational
needs and user privacy. Services need to implement rate limiting to
prevent abuse, charge for API usage to sustain operations, and
allocate computational resources fairly. However, traditional
approaches require tracking client identities and creating detailed
logs of client behavior, raising significant privacy concerns in an
era of increasing data protection awareness and regulation.

Anonymous Credit Tokens (ACT) help to resolve this tension by
providing a cryptographic protocol that enables credit-based systems
without client tracking. Built on keyed-verification anonymous
credentials {{KVAC}} and privately verifiable BBS-style signatures
{{BBS}}, the protocol allows services to issue, track, and spend
credits while maintaining client privacy.

## Key Properties

The protocol provides four essential properties that make it
suitable for privacy-preserving credit systems:

1. **Unlinkability**: The issuer cannot link credit issuance to
   spending, or connect multiple transactions by the same client.
   This property is information-theoretic, not merely computational.

2. **Partial Spending**: Clients can spend any amount up to their
   balance and receive anonymous change without revealing their
   previous or current
   balance, enabling flexible spending.

3. **Double-Spend Prevention**: Cryptographic nullifiers ensure each
   token is used only once, without linking it to issuance.

4. **Balance Privacy**: During spending, only the amount being spent
   is revealed, not the total balance in the token, protecting
   clients from balance-based profiling.

## Use Cases

Anonymous Credit Tokens can be applied to various scenarios:

- **Rate Limiting**: Services can issue daily credit allowances that
  clients spend anonymously for API calls or resource access.

- **API Credits**: API providers can sell credit packages that
  developers use to pay for API requests without creating a detailed
  usage history linked to their identity. This enables:
  - Pre-paid API access without requiring credit cards for each
    transaction
  - Anonymous API usage for privacy-sensitive applications
  - Usage-based billing without tracking individual request patterns
  - Protection against competitive analysis through usage monitoring

## Protocol Overview

The protocol involves two parties: an issuer (typically a service
provider) and clients (typically users of the service). The
interaction follows three main phases:

1. **Setup**: The issuer generates a key pair and publishes the
   public key.

2. **Issuance**: A client requests credits from the issuer. The
   issuer creates a blind signature on the credit value and a
   client-chosen nullifier, producing a credit token.

3. **Spending**: To spend credits, the client reveals a nullifier
   and proves possession of a valid token associated with that
   nullifier having sufficient balance. The issuer verifies the
   proof, checks the nullifier hasn't been used before, and issues a
   new token (which remains hidden from the issuer) for any remaining
   balance.

## Design Goals

The protocol is designed with the following goals:

- **Privacy**: Unlinkability between issuance and spending; see the Security
  Properties section for the formal definition.

- **Security**: Clients cannot spend more credits than they possess or use the
  same credits multiple times.

- **Efficiency**: All operations should be computationally efficient, with
  performance characteristics suitable for high-volume web services and a
  large number of applications.

- **Simplicity**: The protocol should be straightforward to implement and
  integrate into existing systems relative to other comparable solutions.

## Relation to Existing Work

This protocol builds upon several cryptographic primitives:

- **BBS Signatures** {{BBS}}: The core signature scheme that enables efficient
  proofs of possession. We use a variant that is privately verifiable, which
  avoids the need for pairings and makes our protocol more efficient.

- **Sigma Protocols** {{ORRU-SIGMA}}: The zero-knowledge proof framework used
  for spending proofs.

- **Fiat-Shamir Transform** {{ORRU-FS}}: The technique to make the interactive
  proofs non-interactive.

The protocol can be viewed as a specialized instantiation of keyed-verification
anonymous credentials {{KVAC}} optimized for numerical values and partial
spending.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Notation

This document uses the following notation:

- `||`: Concatenation of byte strings

- `x <- S`: Sampling x uniformly from the set S

- `x := y`: Assignment of the value y to the variable x

- `[n]`: The set of integers {0, 1, ..., n-1}

- `|x|`: The length of byte string x

- `0x` prefix: Hexadecimal values

- We use additive notation for group operations, so group elements are added
  together like `a + b` and scalar multiplication of a group element by a scalar
  is written as `a * n`, with group element `a` and scalar `n`.

## Data Types

The protocol uses the following data types:

- **Scalar**: An integer modulo the group order q
- **Element**: An element of the ciphersuite's prime-order group
- **ByteString**: A sequence of bytes

## Ciphersuites

This document defines five ciphersuites. All parties in a protocol session MUST
agree on the same ciphersuite. Implementations MUST NOT mix parameters from
different ciphersuites.

### ACT-Ristretto255-BLAKE3

| Parameter | Value |
|-----------|-------|
| Group | Ristretto255 {{RFC9496}} |
| Element encoding | 32 bytes, compressed Ristretto point |
| Scalar encoding | 32 bytes, little-endian |
| Group order q | 2^252 + 27742317777372353535851937790883648493 |
| Generator G | Standard Ristretto255 generator |
| Hash-to-group | HashToRistretto255 (OneWayMap from {{RFC9496}} Section 4.3.4) |
| Protocol version | `"curve25519-ristretto anonymous-credits v1.0"` |

### ACT-P256-BLAKE3

| Parameter | Value |
|-----------|-------|
| Group | P-256 (secp256r1) {{RFC6090}} |
| Element encoding | 33 bytes, SEC1 compressed point (0x02/0x03 prefix + 32 bytes) {{SEC1}} |
| Scalar encoding | 32 bytes, big-endian |
| Group order q | 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 |
| Generator G | Standard P-256 generator |
| Hash-to-group | HashToP256 (hash_to_curve from {{RFC9380}} with suite P256_XMD:SHA-256_SSWU_RO_) |
| Protocol version | `"p256 anonymous-credits v1.0"` |

### ACT-secp256k1-BLAKE3

| Parameter | Value |
|-----------|-------|
| Group | secp256k1 {{SEC2}} |
| Element encoding | 33 bytes, SEC1 compressed point (0x02/0x03 prefix + 32 bytes) {{SEC1}} |
| Scalar encoding | 32 bytes, big-endian |
| Group order q | 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 |
| Generator G | Standard secp256k1 generator |
| Hash-to-group | HashToSecp256k1 (hash_to_curve from {{RFC9380}} with suite secp256k1_XMD:SHA-256_SSWU_RO_) |
| Protocol version | `"secp256k1 anonymous-credits v1.0"` |

### ACT-P384-BLAKE3

| Parameter | Value |
|-----------|-------|
| Group | P-384 (secp384r1) {{RFC6090}} |
| Element encoding | 49 bytes, SEC1 compressed point (0x02/0x03 prefix + 48 bytes) {{SEC1}} |
| Scalar encoding | 48 bytes, big-endian |
| Group order q | 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973 |
| Generator G | Standard P-384 generator |
| Hash-to-group | HashToP384 (hash_to_curve from {{RFC9380}} with suite P384_XMD:SHA-384_SSWU_RO_) |
| Protocol version | `"p384 anonymous-credits v1.0"` |

### ACT-P521-BLAKE3

| Parameter | Value |
|-----------|-------|
| Group | P-521 (secp521r1) {{RFC6090}} |
| Element encoding | 67 bytes, SEC1 compressed point (0x02/0x03 prefix + 66 bytes) {{SEC1}} |
| Scalar encoding | 66 bytes, big-endian |
| Group order q | 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409 |
| Generator G | Standard P-521 generator |
| Hash-to-group | HashToP521 (hash_to_curve from {{RFC9380}} with suite P521_XMD:SHA-512_SSWU_RO_) |
| Protocol version | `"p521 anonymous-credits v1.0"` |

## Cryptographic Parameters

The protocol is defined generically over a prime-order group. The ciphersuite
determines the concrete group and encoding. The key parameters are:

- **q**: The prime order of the group (ciphersuite-dependent, see above)
- **G**: The standard generator of the group (ciphersuite-dependent)
- **L**: The bit length for credit values

# Protocol Specification

## System Parameters

The protocol requires the following system parameters:

~~~
Parameters:
  - G: Generator of the ciphersuite's group
  - H1, H2, H3, H4: Additional generators for commitments
  - L: Bit length for credit values (configurable, must satisfy 1 <= L <= 128)
~~~

Implementations MUST enforce 1 <= L <= 128. See the Parameter Selection
section for the rationale behind this constraint.

The generators H1, H2, H3, and H4 MUST be generated deterministically from a
nothing-up-my-sleeve value to ensure they are independent of each other and of
G. This prevents attacks whereby malicious parameters could compromise security. Note that these generators are independent of the choice of L.

~~~
GenerateParameters(domain_separator):
  Input:
    - domain_separator: ByteString identifying the deployment
  Output:
    - params: System parameters (H1, H2, H3, H4)

  Steps:
    1. seed = BLAKE3(LengthPrefixed(domain_separator))
    2. counter = 0
    3. H1 = HashToGroup(seed, counter++)
    4. H2 = HashToGroup(seed, counter++)
    5. H3 = HashToGroup(seed, counter++)
    6. H4 = HashToGroup(seed, counter++)
    7. return (H1, H2, H3, H4)
~~~

The HashToGroup function is ciphersuite-dependent:

**ACT-Ristretto255-BLAKE3:**

~~~
HashToRistretto255(seed, counter):
  Input:
    - seed: 32-byte seed value
    - counter: Integer counter for domain separation
  Output:
    - P: A valid Ristretto255 point

  Steps:
    1. hasher = BLAKE3.new()
    2. hasher.update(LengthPrefixed(domain_separator))
    3. hasher.update(LengthPrefixed(seed))
    4. hasher.update(LengthPrefixed(counter.to_le_bytes(4)))
    5. uniform_bytes = hasher.finalize_xof(64)
    6. P = OneWayMap(uniform_bytes)
    7. return P
~~~

**ACT-P256-BLAKE3:**

~~~
HashToP256(seed, counter):
  Input:
    - seed: 32-byte seed value
    - counter: Integer counter for domain separation
  Output:
    - P: A valid P-256 point

  Steps:
    1. hasher = BLAKE3.new()
    2. hasher.update(LengthPrefixed(domain_separator))
    3. hasher.update(LengthPrefixed(seed))
    4. hasher.update(LengthPrefixed(counter.to_le_bytes(4)))
    5. msg = hasher.finalize(32)
    6. DST = "ACT-P256-BLAKE3_H2C_" || domain_separator
    7. P = hash_to_curve(msg, DST)
    8. return P
~~~

**ACT-secp256k1-BLAKE3:**

~~~
HashToSecp256k1(seed, counter):
  Input:
    - seed: 32-byte seed value
    - counter: Integer counter for domain separation
  Output:
    - P: A valid secp256k1 point

  Steps:
    1. hasher = BLAKE3.new()
    2. hasher.update(LengthPrefixed(domain_separator))
    3. hasher.update(LengthPrefixed(seed))
    4. hasher.update(LengthPrefixed(counter.to_le_bytes(4)))
    5. msg = hasher.finalize(32)
    6. DST = "ACT-secp256k1-BLAKE3_H2C_" || domain_separator
    7. P = hash_to_curve(msg, DST)
    8. return P
~~~

**ACT-P384-BLAKE3:**

~~~
HashToP384(seed, counter):
  Input:
    - seed: 32-byte seed value
    - counter: Integer counter for domain separation
  Output:
    - P: A valid P-384 point

  Steps:
    1. hasher = BLAKE3.new()
    2. hasher.update(LengthPrefixed(domain_separator))
    3. hasher.update(LengthPrefixed(seed))
    4. hasher.update(LengthPrefixed(counter.to_le_bytes(4)))
    5. msg = hasher.finalize(32)
    6. DST = "ACT-P384-BLAKE3_H2C_" || domain_separator
    7. P = hash_to_curve(msg, DST)
    8. return P
~~~

The hash_to_curve function for ACT-P256-BLAKE3 is defined in {{RFC9380}}
using the suite P256_XMD:SHA-256_SSWU_RO_. For ACT-secp256k1-BLAKE3 it
uses suite secp256k1_XMD:SHA-256_SSWU_RO_ ({{RFC9380}} Section 8.7),
for ACT-P384-BLAKE3 it uses suite P384_XMD:SHA-384_SSWU_RO_ ({{RFC9380}}
Section 8.3), and for ACT-P521-BLAKE3 it uses suite
P521_XMD:SHA-512_SSWU_RO_ ({{RFC9380}} Section 8.4). Each provides a
uniformly random mapping from arbitrary byte strings to curve points with
no known discrete log relationship to the generator or any other point.

**ACT-P521-BLAKE3:**

~~~
HashToP521(seed, counter):
  Input:
    - seed: 32-byte seed value
    - counter: Integer counter for domain separation
  Output:
    - P: A valid P-521 point

  Steps:
    1. hasher = BLAKE3.new()
    2. hasher.update(LengthPrefixed(domain_separator))
    3. hasher.update(LengthPrefixed(seed))
    4. hasher.update(LengthPrefixed(counter.to_le_bytes(4)))
    5. msg = hasher.finalize(32)
    6. DST = "ACT-P521-BLAKE3_H2C_" || domain_separator
    7. P = hash_to_curve(msg, DST)
    8. return P
~~~

The domain_separator MUST be unique for each deployment to ensure
cryptographic isolation between different services. The domain separator SHOULD
follow this structured format:

~~~
domain_separator = "ACT-v1:" || organization || ":" || service || ":" || deployment_id || ":" || version
~~~

Each component (organization, service, deployment_id, version) MUST NOT
contain the colon character ':'.

Where:

- `organization`: A unique identifier for the organization (e.g., "example-corp", "acme-inc")
- `service`: The specific service or application name (e.g., "payment-api", "rate-limiter")
- `deployment_id`: The deployment environment (e.g., "production", "staging", "us-west-1")
- `version`: An ISO 8601 date (YYYY-MM-DD) indicating when parameters were generated

Example: `"ACT-v1:example-corp:payment-api:production:2024-01-15"`

This structured format ensures:
1. Protocol identification through the "ACT-v1:" prefix
2. Organizational namespace isolation
3. Service-level separation within organizations
4. Environment isolation (production vs staging)
5. Version tracking for parameter updates

Using generic or unstructured domain separators creates security risks through
parameter collision and MUST NOT be used. When parameters need to be updated
(e.g., for security reasons or protocol upgrades), a new version date MUST be
used, creating entirely new parameters.

For ACT-Ristretto255-BLAKE3, the OneWayMap function is defined in {{RFC9496}}
Section 4.3.4, which provides a cryptographically secure mapping from
uniformly random byte strings to valid Ristretto255 points.

For ACT-P256-BLAKE3, ACT-secp256k1-BLAKE3, ACT-P384-BLAKE3, and
ACT-P521-BLAKE3, the hash-to-group function uses hash_to_curve from
{{RFC9380}} with the appropriate curve-specific suite. This maps inputs
to curve points such that the discrete log with respect to any known
point is infeasible to compute, which is essential for the security of
the protocol.

## Key Generation

The issuer generates a key pair as follows:

~~~
KeyGen():
  Input: None
  Output:
    - sk: Private key (Scalar)
    - pk: Public key (Group Element)

  Steps:
    1. x <- Zq
    2. W = G * x
    3. sk = x
    4. pk = W
    5. return (sk, pk)
~~~

## Token Issuance

The issuance protocol is an interactive protocol between a client and the
issuer:

### Client: Issuance Request

~~~
IssueRequest():
  Output:
    - request: Issuance request
    - state: Client state for later verification

  Steps:
    1. k <- Zq  // Nullifier (will prevent double-spending)
    2. r <- Zq  // Blinding factor
    3. K = H2 * k + H3 * r
    4. // Generate proof of knowledge of k, r
    5. k' <- Zq
    6. r' <- Zq
    7. K1 = H2 * k' + H3 * r'
    8. transcript = CreateTranscript("request")
    9. AddToTranscript(transcript, K)
    10. AddToTranscript(transcript, K1)
    11. gamma = GetChallenge(transcript)
    12. k_bar = k' + gamma * k
    13. r_bar = r' + gamma * r
    14. request = (K, gamma, k_bar, r_bar)
    15. state = (k, r)
    16. return (request, state)
~~~

### Issuer: Issuance Response

~~~
IssueResponse(sk, request, c, ctx):
  Input:
    - sk: Issuer's private key
    - request: Client's issuance request
    - c: Credit amount to issue (c > 0)
    - ctx: Request context (Scalar)
  Output:
    - response: Issuance response or INVALID
  Exceptions:
    - InvalidIssuanceRequestProof, raised when the client proof verification fails

  Steps:
    1. Parse request as (K, gamma, k_bar, r_bar)
    2. // Verify proof of knowledge
    3. K1 = H2 * k_bar + H3 * r_bar - K * gamma
    4. transcript = CreateTranscript("request")
    5. AddToTranscript(transcript, K)
    6. AddToTranscript(transcript, K1)
    7. if GetChallenge(transcript) != gamma:
    8.     raise InvalidIssuanceRequestProof
    9. // Create BBS signature on (c, ctx, k, r)
    10. e <- Zq
    11. A = (G + H1 * c + H4 * ctx + K) * (1/(e + sk))  // K = H2 * k + H3 * r
    12. // Generate proof of correct computation
    13. alpha <- Zq
    14. Y_A = A * alpha
    15. Y_G = G * alpha
    16. X_A = G + H1 * c + H4 * ctx + K
    17. X_G = G * e + pk
    18. transcript_resp = CreateTranscript("respond")
    19. AddToTranscript(transcript_resp, c)
    20. AddToTranscript(transcript_resp, ctx)
    21. AddToTranscript(transcript_resp, e)
    22. AddToTranscript(transcript_resp, A)
    23. AddToTranscript(transcript_resp, X_A)
    24. AddToTranscript(transcript_resp, X_G)
    25. AddToTranscript(transcript_resp, Y_A)
    26. AddToTranscript(transcript_resp, Y_G)
    27. gamma_resp = GetChallenge(transcript_resp)
    28. z = gamma_resp * (sk + e) + alpha
    29. response = (A, e, gamma_resp, z, c, ctx)
    30. return response
~~~

### Client: Token Verification

~~~
VerifyIssuance(pk, request, response, state):
  Input:
    - pk: Issuer's public key
    - request: The issuance request sent
    - response: Issuer's response
    - state: Client state from request generation
  Output:
    - token: Credit token
  Exceptions:
    - InvalidIssuanceResponseProof, raised when the server proof verification fails

  Steps:
    1. Parse request as (K, gamma, k_bar, r_bar)
    2. Parse response as (A, e, gamma_resp, z, c, ctx)
    3. Parse state as (k, r)
    4. // Verify proof
    5. X_A = G + H1 * c + H4 * ctx + K
    6. X_G = G * e + pk
    7. Y_A = A * z - X_A * gamma_resp
    8. Y_G = G * z - X_G * gamma_resp
    9. transcript_resp = CreateTranscript("respond")
    10. AddToTranscript(transcript_resp, c)
    11. AddToTranscript(transcript_resp, ctx)
    12. AddToTranscript(transcript_resp, e)
    13. AddToTranscript(transcript_resp, A)
    14. AddToTranscript(transcript_resp, X_A)
    15. AddToTranscript(transcript_resp, X_G)
    16. AddToTranscript(transcript_resp, Y_A)
    17. AddToTranscript(transcript_resp, Y_G)
    18. if GetChallenge(transcript_resp) != gamma_resp:
    19.     raise InvalidIssuanceResponseProof
    20. token = (A, e, k, r, c, ctx)
    21. return token
~~~

## Token Spending

The spending protocol allows a client to spend s credits from a token
containing c credits (where 0 <= s <= c).

Note: Spending s = 0 is permitted and produces a new token with the same
balance but a fresh nullifier. This "re-anonymization" operation is useful
for securely transferring a token to another party: after a zero-spend, the
original holder can no longer use the old nullifier, and the recipient
obtains a token that is cryptographically unlinkable to the original.

### Client: Spend Proof Generation

~~~
ProveSpend(token, s):
  Input:
    - token: Credit token (A, e, k, r, c, ctx)
    - s: Amount to spend (0 <= s <= c)
  Output:
    - proof: Spend proof
    - state: Client state for receiving change
  Exceptions:
    - InvalidAmount: raised when s > c or s >= 2^L or c >= 2^L

  Steps:
    1. // Validate inputs
    2. if s >= 2^L:
    3.     raise InvalidAmount
    4. if c >= 2^L:
    5.     raise InvalidAmount
    6. if s > c:
    7.     raise InvalidAmount

    8. // Randomize the signature
    9. r1, r2 <- Zq
    10. B = G + H1 * c + H2 * k + H3 * r + H4 * ctx
    11. A' = A * (r1 * r2)
    12. B_bar = B * r1
    13. r3 = 1/r1

    14. // Generate initial proof components
    15. c' <- Zq
    16. r' <- Zq
    17. e' <- Zq
    18. r2' <- Zq
    19. r3' <- Zq

    20. // Compute first round messages
    21. A1 = A' * e' + B_bar * r2'
    22. A2 = B_bar * r3' + H1 * c' + H3 * r'

    23. // Decompose c - s into bits
    24. m = c - s
    25. (i[0], ..., i[L-1]) = BitDecompose(m)  // See Section 3.7

    26. // Create commitments for each bit
    27. k* <- Zq
    28. s[0] <- Zq
    29. Com[0] = H1 * i[0] + H2 * k* + H3 * s[0]
    30. For j = 1 to L-1:
    31.     s[j] <- Zq
    32.     Com[j] = H1 * i[j] + H3 * s[j]

    33. // Initialize range proof arrays
    34. C = array[L][2]
    35. C' = array[L][2]
    36. gamma0 = array[L]
    37. z = array[L][2]

    38. // Process bit 0 (with k* component)
    39. C[0][0] = Com[0]
    40. C[0][1] = Com[0] - H1
    41. k0' <- Zq
    42. s_prime = array[L]
    43. s_prime[0] <- Zq
    44. gamma0[0] <- Zq
    45. w0 <- Zq
    46. z[0] <- Zq

    47. if i[0] == 0:
    48.     C'[0][0] = H2 * k0' + H3 * s_prime[0]
    49.     C'[0][1] = H2 * w0 + H3 * z[0] - C[0][1] * gamma0[0]
    50. else:
    51.     C'[0][0] = H2 * w0 + H3 * z[0] - C[0][0] * gamma0[0]
    52.     C'[0][1] = H2 * k0' + H3 * s_prime[0]

    53. // Process remaining bits
    54. For j = 1 to L-1:
    55.     C[j][0] = Com[j]
    56.     C[j][1] = Com[j] - H1
    57.     s_prime[j] <- Zq
    58.     gamma0[j] <- Zq
    59.     z[j] <- Zq
    60.
    61.     if i[j] == 0:
    62.         C'[j][0] = H3 * s_prime[j]
    63.         C'[j][1] = H3 * z[j] - C[j][1] * gamma0[j]
    64.     else:
    65.         C'[j][0] = H3 * z[j] - C[j][0] * gamma0[j]
    66.         C'[j][1] = H3 * s_prime[j]

    67. // Compute K' commitment
    68. K' = Sum(Com[j] * 2^j for j in [L])
    69. r* = Sum(s[j] * 2^j for j in [L])
    70. k' <- Zq
    71. s' <- Zq
    72. C_final = H1 * (-c') + H2 * k' + H3 * s'

    73. // Generate challenge using transcript
    74. transcript = CreateTranscript("spend")
    75. AddToTranscript(transcript, k)
    76. AddToTranscript(transcript, ctx)
    77. AddToTranscript(transcript, A')
    78. AddToTranscript(transcript, B_bar)
    79. AddToTranscript(transcript, A1)
    80. AddToTranscript(transcript, A2)
    81. For j = 0 to L-1:
    82.     AddToTranscript(transcript, Com[j])
    83. For j = 0 to L-1:
    84.     AddToTranscript(transcript, C'[j][0])
    85.     AddToTranscript(transcript, C'[j][1])
    86. AddToTranscript(transcript, C_final)
    87. gamma = GetChallenge(transcript)

    88. // Compute responses
    89. e_bar = -gamma * e + e'
    90. r2_bar = gamma * r2 + r2'
    91. r3_bar = gamma * r3 + r3'
    92. c_bar = -gamma * c + c'
    93. r_bar = -gamma * r + r'

    94. // Complete range proof responses
    95. z_final = array[L][2]
    96. gamma0_final = array[L]
    97.
    98. // For bit 0
    99. if i[0] == 0:
    100.    gamma0_final[0] = gamma - gamma0[0]
    101.    w00 = gamma0_final[0] * k* + k0'
    102.    w01 = w0
    103.    z_final[0][0] = gamma0_final[0] * s[0] + s_prime[0]
    104.    z_final[0][1] = z[0]
    105. else:
    106.    gamma0_final[0] = gamma0[0]
    107.    w00 = w0
    108.    w01 = (gamma - gamma0_final[0]) * k* + k0'
    109.    z_final[0][0] = z[0]
    110.    z_final[0][1] = (gamma - gamma0_final[0]) * s[0] + s_prime[0]

    111. // For remaining bits
    112. For j = 1 to L-1:
    113.     if i[j] == 0:
    114.         gamma0_final[j] = gamma - gamma0[j]
    115.         z_final[j][0] = gamma0_final[j] * s[j] + s_prime[j]
    116.         z_final[j][1] = z[j]
    117.     else:
    118.         gamma0_final[j] = gamma0[j]
    119.         z_final[j][0] = z[j]
    120.         z_final[j][1] = (gamma - gamma0_final[j]) * s[j] + s_prime[j]

    121. k_bar = gamma * k* + k'
    122. s_bar = gamma * r* + s'

    123. // Construct proof
    124. proof = (k, s, ctx, A', B_bar, Com, gamma, e_bar,
    125.          r2_bar, r3_bar, c_bar, r_bar,
    126.          w00, w01, gamma0_final, z_final,
    127.          k_bar, s_bar)
    128. state = (k*, r*, m, ctx)
    129. return (proof, state)
~~~

### Issuer: Spend Verification and Refund

~~~
VerifyAndRefund(sk, proof, t):
  Input:
    - sk: Issuer's private key
    - proof: Client's spend proof
    - t: Credits to return to the client (0 <= t <= s, t < 2^L)
  Output:
    - refund: Refund for remaining credits
  Exceptions:
    - DoubleSpendError: raised when the nullifier has been used before
    - InvalidSpendProof: raised when the spend proof verification fails

  Steps:
    1. Parse proof and extract nullifier k
    2. // Check nullifier hasn't been used
    3. if k in used_nullifiers:
    4.     raise DoubleSpendError
    5. // Verify the proof (see Section 3.5.2)
    6. if not VerifySpendProof(sk, proof):
    7.     raise InvalidSpendProof
    8. // Record nullifier
    9. used_nullifiers.add(k)
    10. // Issue refund for remaining balance
    11. K' = Sum(Com[j] * 2^j for j in [L])
    12. refund = IssueRefund(sk, K', proof.ctx, proof.s, t)
    13. return refund
~~~

### Refund Issuance {#refund-issuance}

After verifying a spend proof, the issuer creates a refund token for the
remaining balance. The issuer may optionally return t credits (where
0 <= t <= s) back to the client via a partial credit return. This enables
pre-authorization patterns where the client holds s credits but only t
are returned unused. The resulting token will have c - s + t credits.
Use t = 0 to consume the full spend amount:

~~~
IssueRefund(sk, K', ctx, s, t):
  Input:
    - sk: Issuer's private key
    - K': Commitment to remaining balance and new nullifier
    - ctx: Request context from the spend proof
    - s: The spend amount from the proof
    - t: Credits to return to the client (0 <= t <= s, t < 2^L)
  Output:
    - refund: Refund response
  Exceptions:
    - InvalidAmount: raised when t > s or t >= 2^L

  Steps:
    1. // Validate partial return amount
    2. if t >= 2^L:
    3.     raise InvalidAmount
    4. if t > s:
    5.     raise InvalidAmount

    6. // Create new BBS signature on remaining balance + partial return
    7. e* <- Zq
    8. X_A* = G + K' + H1 * t + H4 * ctx
    9. A* = X_A* * (1/(e* + sk))

    10. // Generate proof of correct computation
    11. alpha <- Zq
    12. Y_A = A* * alpha
    13. Y_G = G * alpha
    14. X_G = G * e* + pk

    15. // Create challenge using transcript
    16. transcript = CreateTranscript("refund")
    17. AddToTranscript(transcript, e*)
    18. AddToTranscript(transcript, t)
    19. AddToTranscript(transcript, ctx)
    20. AddToTranscript(transcript, A*)
    21. AddToTranscript(transcript, X_A*)
    22. AddToTranscript(transcript, X_G)
    23. AddToTranscript(transcript, Y_A)
    24. AddToTranscript(transcript, Y_G)
    25. gamma = GetChallenge(transcript)

    26. // Compute response
    27. z = gamma * (sk + e*) + alpha

    28. refund = (A*, e*, gamma, z, t)
    29. return refund
~~~

### Client: Refund Token Construction

The client verifies the refund and constructs a new credit token:

~~~
ConstructRefundToken(pk, spend_proof, refund, state):
  Input:
    - pk: Issuer's public key
    - spend_proof: The spend proof sent to issuer
    - refund: Issuer's refund response
    - state: Client state (k*, r*, m, ctx)
  Output:
    - token: New credit token or INVALID
  Exceptions:
    - InvalidRefundProof: When the refund proof verification fails

  Steps:
    1. Parse refund as (A*, e*, gamma, z, t)
    2. Parse state as (k*, r*, m, ctx)

    3. // Reconstruct commitment with partial return
    4. K' = Sum(spend_proof.Com[j] * 2^j for j in [L])
    5. X_A* = G + K' + H1 * t + H4 * ctx
    6. X_G = G * e* + pk

    7. // Verify proof
    8. Y_A = A* * z + X_A* * (-gamma)
    9. Y_G = G * z + X_G * (-gamma)

    10. // Check challenge using transcript
    11. transcript = CreateTranscript("refund")
    12. AddToTranscript(transcript, e*)
    13. AddToTranscript(transcript, t)
    14. AddToTranscript(transcript, ctx)
    15. AddToTranscript(transcript, A*)
    16. AddToTranscript(transcript, X_A*)
    17. AddToTranscript(transcript, X_G)
    18. AddToTranscript(transcript, Y_A)
    19. AddToTranscript(transcript, Y_G)
    20. if GetChallenge(transcript) != gamma:
    21.     raise InvalidRefundProof

    22. // Construct new token with remaining balance + partial return
    23. token = (A*, e*, k*, r*, m + t, ctx)
    24. return token
~~~

### Spend Proof Verification {#spend-verification}

The issuer verifies a spend proof as follows:

~~~
VerifySpendProof(sk, proof):
  Input:
    - sk: Issuer's private key
    - proof: Spend proof from client
  Output:
    - valid: Boolean indicating if proof is valid
  Exceptions:
    - IdentityPointError: raised when A' is the identity
    - InvalidClientSpendProof: raised when the challenge does not match the reconstruction

  Steps:
    1. Parse proof as (k, s, ctx, A', B_bar, Com, gamma, e_bar,
                      r2_bar, r3_bar, c_bar, r_bar, w00, w01,
                      gamma0, z, k_bar, s_bar)

    2. // Check A' is not identity
    3. if A' == Identity:
    4.     raise IdentityPointError

    5. // Compute issuer's view of signature
    6. A_bar = A' * sk
    7. H1_prime = G + H2 * k + H4 * ctx

    8. // Verify sigma protocol
    9. A1 = A' * e_bar + B_bar * r2_bar - A_bar * gamma
    10. A2 = B_bar * r3_bar + H1 * c_bar + H3 * r_bar - H1_prime * gamma

    11. // Initialize arrays for range proof verification
    12. gamma1 = array[L]
    13. C = array[L][2]
    14. C' = array[L][2]

    15. // Process bit 0 (with k* component)
    16. gamma1[0] = gamma - gamma0[0]
    17. C[0][0] = Com[0]
    18. C[0][1] = Com[0] - H1
    19. C'[0][0] = H2 * w00 + H3 * z[0][0] - C[0][0] * gamma0[0]
    20. C'[0][1] = H2 * w01 + H3 * z[0][1] - C[0][1] * gamma1[0]

    21. // Verify remaining bits
    22. For j = 1 to L-1:
    23.     gamma1[j] = gamma - gamma0[j]
    24.     C[j][0] = Com[j]
    25.     C[j][1] = Com[j] - H1
    26.     C'[j][0] = H3 * z[j][0] - C[j][0] * gamma0[j]
    27.     C'[j][1] = H3 * z[j][1] - C[j][1] * gamma1[j]

    28. // Verify final commitment
    29. K' = Sum(Com[j] * 2^j for j in [L])
    30. Com_total = H1 * s + K'
    31. C_final = H1 * (-c_bar) + H2 * k_bar + H3 * s_bar - Com_total * gamma

    32. // Recompute challenge using transcript
    33. transcript = CreateTranscript("spend")
    34. AddToTranscript(transcript, k)
    35. AddToTranscript(transcript, ctx)
    36. AddToTranscript(transcript, A')
    37. AddToTranscript(transcript, B_bar)
    38. AddToTranscript(transcript, A1)
    39. AddToTranscript(transcript, A2)
    40. For j = 0 to L-1:
    41.     AddToTranscript(transcript, Com[j])
    42. For j = 0 to L-1:
    43.     AddToTranscript(transcript, C'[j][0])
    44.     AddToTranscript(transcript, C'[j][1])
    45. AddToTranscript(transcript, C_final)
    46. gamma_check = GetChallenge(transcript)

    47. // Verify challenge matches
    48. if gamma != gamma_check:
    49.     raise InvalidVerifySpendProof

    50. return true
~~~


## Cryptographic Primitives

### Protocol Version

The protocol version string for domain separation is ciphersuite-dependent:

~~~
ACT-Ristretto255-BLAKE3:
  PROTOCOL_VERSION = "curve25519-ristretto anonymous-credits v1.0"

ACT-P256-BLAKE3:
  PROTOCOL_VERSION = "p256 anonymous-credits v1.0"

ACT-secp256k1-BLAKE3:
  PROTOCOL_VERSION = "secp256k1 anonymous-credits v1.0"

ACT-P384-BLAKE3:
  PROTOCOL_VERSION = "p384 anonymous-credits v1.0"

ACT-P521-BLAKE3:
  PROTOCOL_VERSION = "p521 anonymous-credits v1.0"
~~~

The version string MUST be used consistently across all implementations of a
given ciphersuite for interoperability. The curve specification is included to
prevent cross-curve attacks and ensure implementations using different curves
cannot accidentally interact.

### Hash Function and Fiat-Shamir Transform

The protocol uses BLAKE3 {{BLAKE3}} as the underlying hash function for the
Fiat-Shamir transform {{ORRU-FS}}. Following the sigma protocol framework
{{ORRU-SIGMA}}, challenges are generated using a transcript that accumulates
all protocol messages:

~~~
CreateTranscript(label):
  Input:
    - label: ASCII string identifying the proof type
  Output:
    - transcript: A new transcript object

  Steps:
    1. hasher = BLAKE3.new()
    2. hasher.update(LengthPrefixed(PROTOCOL_VERSION))
    3. hasher.update(LengthPrefixed(Encode(H1)))
    4. hasher.update(LengthPrefixed(Encode(H2)))
    5. hasher.update(LengthPrefixed(Encode(H3)))
    6. hasher.update(LengthPrefixed(Encode(H4)))
    7. hasher.update(LengthPrefixed(label))
    8. return transcript with hasher

AddToTranscript(transcript, value):
  Input:
    - transcript: Existing transcript
    - value: Element or Scalar to add

  Steps:
    1. encoded = Encode(value)
    2. transcript.hasher.update(LengthPrefixed(encoded))

GetChallenge(transcript):
  Input:
    - transcript: Completed transcript
  Output:
    - challenge: Scalar challenge value

  ACT-Ristretto255-BLAKE3:
    1. hash = transcript.hasher.output(64)  // 64 bytes of output
    2. challenge = from_little_endian_bytes(hash) mod q
    3. return challenge

  ACT-P256-BLAKE3:
    1. hash = transcript.hasher.output(48)  // 48 bytes of output
    2. challenge = FromOkm(hash)  // RFC 9380 Section 5.2
    3. return challenge

  ACT-secp256k1-BLAKE3:
    1. hash = transcript.hasher.output(48)  // 48 bytes of output
    2. challenge = FromOkm(hash)  // RFC 9380 Section 5.2
    3. return challenge

  ACT-P384-BLAKE3:
    1. hash = transcript.hasher.output(72)  // 72 bytes of output
    2. challenge = FromOkm(hash)  // RFC 9380 Section 5.2
    3. return challenge

  ACT-P521-BLAKE3:
    1. hash = transcript.hasher.output(98)  // 98 bytes of output
    2. challenge = FromOkm(hash)  // RFC 9380 Section 5.2
    3. return challenge
~~~

Note: For all short-Weierstrass ciphersuites, the challenge is derived via
the FromOkm algorithm ({{RFC9380}} Section 5.2), which reduces a
uniformly random byte string modulo the group order with negligible bias.
The output lengths follow the formula L = ceil((ceil(log2(q)) + k) / 8)
from {{RFC9380}} Section 5.2, with k = 128 as the security parameter:
48 bytes for ACT-P256-BLAKE3 and ACT-secp256k1-BLAKE3 (~256-bit orders),
72 bytes for ACT-P384-BLAKE3 (~384-bit order), and 98 bytes for
ACT-P521-BLAKE3 (~521-bit order).

This approach ensures:

- Domain separation through the label and protocol version
- Inclusion of all public parameters to prevent parameter substitution attacks
- Proper ordering with length prefixes to prevent ambiguity
- Deterministic challenge generation from the complete transcript

### Encoding Functions

Elements and scalars are encoded according to the ciphersuite:

~~~
Encode(value):
  Input:
    - value: Element or Scalar
  Output:
    - encoding: ByteString

  ACT-Ristretto255-BLAKE3:
    1. If value is an Element:
    2.     return value.compress()  // 32 bytes, compressed Ristretto point
    3. If value is a Scalar:
    4.     return value.to_bytes_le()  // 32 bytes, little-endian

  ACT-P256-BLAKE3:
    1. If value is an Element:
    2.     return SEC1_compressed(value)  // 33 bytes, 0x02/0x03 + 32 bytes
    3. If value is a Scalar:
    4.     return value.to_bytes_be()  // 32 bytes, big-endian

  ACT-secp256k1-BLAKE3:
    1. If value is an Element:
    2.     return SEC1_compressed(value)  // 33 bytes, 0x02/0x03 + 32 bytes
    3. If value is a Scalar:
    4.     return value.to_bytes_be()  // 32 bytes, big-endian

  ACT-P384-BLAKE3:
    1. If value is an Element:
    2.     return SEC1_compressed(value)  // 49 bytes, 0x02/0x03 + 48 bytes
    3. If value is a Scalar:
    4.     return value.to_bytes_be()  // 48 bytes, big-endian

  ACT-P521-BLAKE3:
    1. If value is an Element:
    2.     return SEC1_compressed(value)  // 67 bytes, 0x02/0x03 + 66 bytes
    3. If value is a Scalar:
    4.     return value.to_bytes_be()  // 66 bytes, big-endian
~~~

The following function provides consistent length-prefixing for hash inputs:

~~~
LengthPrefixed(data):
  Input:
    - data: ByteString to be length-prefixed
  Output:
    - prefixed: ByteString with length prefix

  Steps:
    1. length = len(data)
    2. return length.to_be_bytes(8) || data  // 8-byte big-endian length prefix
~~~

Note: Implementations MAY use standard serialization formats (e.g. CBOR) for
complex structures, but MUST ensure deterministic encoding for hash inputs.

### Binary Decomposition {#binary-decomposition}

To decompose a scalar into its binary representation:

~~~
BitDecompose(s):
  Input:
    - s: Scalar value
  Output:
    - bits: Array of L scalars (each 0 or 1)

  ACT-Ristretto255-BLAKE3:
    1. bytes = s.to_bytes_le()  // 32 bytes, little-endian
    2. For i = 0 to L-1:
    3.     byte_index = i / 8
    4.     bit_position = i % 8
    5.     bit = (bytes[byte_index] >> bit_position) & 1
    6.     bits[i] = Scalar(bit)
    7. return bits

  ACT-P256-BLAKE3:
    1. bytes = s.to_bytes_be()  // 32 bytes, big-endian
    2. For i = 0 to L-1:
    3.     byte_index = 31 - (i / 8)
    4.     bit_position = i % 8
    5.     bit = (bytes[byte_index] >> bit_position) & 1
    6.     bits[i] = Scalar(bit)
    7. return bits

  ACT-secp256k1-BLAKE3:
    1. bytes = s.to_bytes_be()  // 32 bytes, big-endian
    2. For i = 0 to L-1:
    3.     byte_index = 31 - (i / 8)
    4.     bit_position = i % 8
    5.     bit = (bytes[byte_index] >> bit_position) & 1
    6.     bits[i] = Scalar(bit)
    7. return bits

  ACT-P384-BLAKE3:
    1. bytes = s.to_bytes_be()  // 48 bytes, big-endian
    2. For i = 0 to L-1:
    3.     byte_index = 47 - (i / 8)
    4.     bit_position = i % 8
    5.     bit = (bytes[byte_index] >> bit_position) & 1
    6.     bits[i] = Scalar(bit)
    7. return bits

  ACT-P521-BLAKE3:
    1. bytes = s.to_bytes_be()  // 66 bytes, big-endian
    2. For i = 0 to L-1:
    3.     byte_index = 65 - (i / 8)
    4.     bit_position = i % 8
    5.     bit = (bytes[byte_index] >> bit_position) & 1
    6.     bits[i] = Scalar(bit)
    7. return bits
~~~

Note: Both variants produce bits in LSB-first order (i.e., `bits[0]` is the
least significant bit). See Section 3.1 for constraints on L.

### Scalar Conversion

Converting between credit amounts and scalars:

~~~
CreditToScalar(amount):
  Input:
    - amount: Integer credit amount (0 <= amount < 2^L)
  Output:
    - s: Scalar representation
  Exceptions:
    - AmountTooBigError: raised when the amount exceeds 2^L

  Steps:
    1. if amount >= 2^L:
    2.     return AmountTooBigError
    3. return Scalar(amount)

ScalarToCredit(s):
  Input:
    - s: Scalar value
  Output:
    - amount: Integer credit amount or ERROR
  Exceptions:
    - ScalarOutOfRangeError: raised when the scalar value is >= 2^L

  Steps:
    1. amount = s as integer  // Interpret scalar bytes as integer
       // (little-endian for Ristretto255, big-endian for P-256/secp256k1/P-384/P-521)
    2. if amount >= 2^L:
    3.     return ScalarOutOfRangeError
    4. return amount
~~~

# Protocol Messages and Wire Format

## Message Encoding

All protocol messages SHOULD be encoded using deterministic CBOR (RFC 8949) for
interoperability. Decoders MUST reject messages containing unknown CBOR map
keys. The following sections define the structure of each message type. Field
sizes are ciphersuite-dependent: Ns denotes the scalar size (32 bytes for
Ristretto255/P-256/secp256k1, 48 bytes for P-384, 66 bytes for P-521) and
Np denotes the compressed point size (32 bytes for Ristretto255, 33 bytes for
P-256/secp256k1, 49 bytes for P-384, 67 bytes for P-521).

### Issuance Request Message

~~~
IssuanceRequestMsg = {
    1: bstr,  ; K (compressed point, Np bytes)
    2: bstr,  ; gamma (scalar, Ns bytes)
    3: bstr,  ; k_bar (scalar, Ns bytes)
    4: bstr   ; r_bar (scalar, Ns bytes)
}
~~~

### Issuance Response Message

~~~
IssuanceResponseMsg = {
    1: bstr,  ; A (compressed point, Np bytes)
    2: bstr,  ; e (scalar, Ns bytes)
    3: bstr,  ; gamma_resp (scalar, Ns bytes)
    4: bstr,  ; z (scalar, Ns bytes)
    5: bstr,  ; c (scalar, Ns bytes)
    6: bstr   ; ctx (scalar, Ns bytes)
}
~~~

### Spend Proof Message

~~~
SpendProofMsg = {
    1: bstr,           ; k (nullifier, Ns bytes)
    2: bstr,           ; s (spend amount, Ns bytes)
    3: bstr,           ; A' (compressed point, Np bytes)
    4: bstr,           ; B_bar (compressed point, Np bytes)
    5: [* bstr],       ; Com array (L compressed points, Np bytes each)
    6: bstr,           ; gamma (scalar, Ns bytes)
    7: bstr,           ; e_bar (scalar, Ns bytes)
    8: bstr,           ; r2_bar (scalar, Ns bytes)
    9: bstr,           ; r3_bar (scalar, Ns bytes)
    10: bstr,          ; c_bar (scalar, Ns bytes)
    11: bstr,          ; r_bar (scalar, Ns bytes)
    12: bstr,          ; w00 (scalar, Ns bytes)
    13: bstr,          ; w01 (scalar, Ns bytes)
    14: [* bstr],      ; gamma0 array (L scalars, Ns bytes each)
    15: [* [bstr, bstr]], ; z array (L pairs of scalars, Ns bytes each)
    16: bstr,          ; k_bar (scalar, Ns bytes)
    17: bstr,          ; s_bar (scalar, Ns bytes)
    18: bstr           ; ctx (scalar, Ns bytes)
}
~~~

### Refund Message

~~~
RefundMsg = {
    1: bstr,  ; A* (compressed point, Np bytes)
    2: bstr,  ; e* (scalar, Ns bytes)
    3: bstr,  ; gamma (scalar, Ns bytes)
    4: bstr,  ; z (scalar, Ns bytes)
    5: bstr   ; t (partial return, scalar, Ns bytes)
}
~~~

## Error Responses

Error responses SHOULD use the following format:

~~~
ErrorMsg = {
    1: uint,   ; error_code
    2: tstr    ; error_message (for debugging only)
}
~~~

Error codes are defined in Section 5.3.

## Key Serialization

The following formats define the serialization of issuer keys. Implementations
that need to persist or transmit keys SHOULD use these formats for
interoperability.

### Public Key

~~~
PublicKey = bstr  ; W (compressed point, Np bytes)
~~~

### Private Key

~~~
PrivateKey = {
    1: bstr,  ; x (secret scalar, Ns bytes)
    2: bstr   ; W (public key point, Np bytes)
}
~~~

Decoders MUST verify that W == G * x upon deserialization to prevent use
of inconsistent key material.

## Client State Serialization

The following formats define the serialization of client-side state that
must be persisted between protocol steps. Implementations that need to
store or transmit client state SHOULD use these formats for interoperability.

### Pre-Issuance State

The client MUST persist this state after generating an issuance request
and before receiving the issuance response.

~~~
PreIssuance = {
    1: bstr,  ; r (blinding factor, scalar, Ns bytes)
    2: bstr   ; k (nullifier, scalar, Ns bytes)
}
~~~

### Credit Token

The client MUST persist the credit token after issuance or refund.

~~~
CreditToken = {
    1: bstr,  ; A (BBS signature point, Np bytes)
    2: bstr,  ; e (signature scalar, Ns bytes)
    3: bstr,  ; k (nullifier, scalar, Ns bytes)
    4: bstr,  ; r (blinding factor, scalar, Ns bytes)
    5: bstr,  ; c (credit amount, scalar, Ns bytes)
    6: bstr   ; ctx (request context, scalar, Ns bytes)
}
~~~

### Pre-Refund State

The client MUST persist this state after generating a spend proof and
before receiving the refund response.

~~~
PreRefund = {
    1: bstr,  ; r (blinding factor, scalar, Ns bytes)
    2: bstr,  ; k (nullifier, scalar, Ns bytes)
    3: bstr,  ; m (remaining balance, scalar, Ns bytes)
    4: bstr   ; ctx (request context, scalar, Ns bytes)
}
~~~

## Protocol Flow

The complete protocol flow with message types:

~~~
Client                                          Issuer
  |                                               |
  |-- IssuanceRequestMsg ------------------------>|
  |                                               |
  |<-- IssuanceResponseMsg -----------------------|
  |                                               |
  | (client creates token)                        |
  |                                               |
  |-- SpendProofMsg ----------------------------->|
  |                                               |
  |<-- RefundMsg or ErrorMsg ---------------------|
  |                                               |
~~~

### Example Usage Scenario

Consider an API service that sells credits in bundles of 1000:

1. **Purchase**: Alice buys 1000 API credits
   - Alice generates a random nullifier k and blinding factor r
   - Alice sends IssuanceRequestMsg to the service
   - Service creates a BBS signature on (1000, k, r) and returns it
   - Alice now has a token worth 1000 credits

2. **First API Call**: Alice makes an API call costing 50 credits
   - Alice creates a SpendProofMsg proving she has ≥ 50 credits
   - Alice reveals nullifier k to prevent double-spending
   - Service verifies the proof and records k as used
   - Service issues a RefundMsg for a new token worth 950 credits
   - Alice generates new nullifier k' for the refund token

3. **Subsequent Calls**: Alice continues using the API
   - Each call repeats the spend/refund process
   - Each new token has a fresh nullifier
   - The service cannot link Alice's calls together

This example demonstrates how the protocol maintains privacy while preventing double-spending and enabling flexible partial payments.

# Implementation Considerations

## Nullifier Management

Implementations MUST maintain a persistent database of used nullifiers to
prevent double-spending. The nullifier storage requirements grow linearly with
the number of spent tokens. Implementations MAY use the following strategies to
manage storage:

1. **Expiration**: If tokens have expiration dates, old nullifiers can be
   pruned.

2. **Sharding**: Nullifiers can be partitioned across multiple databases.

3. **Bloom Filters**: Probabilistic data structures can reduce memory usage
   with a small false-positive rate. WARNING: false positives cause
   legitimate spends to be rejected. Bloom filters MUST NOT be the sole
   nullifier check; a positive result MUST be confirmed against authoritative
   storage before rejecting a spend.

## Constant-Time Operations

Implementations MUST use constant-time operations for all secret-dependent
computations. See the Security Considerations section for detailed
requirements and mitigations.

## Randomness Generation

The security of the protocol critically depends on the quality of random number
generation. Implementations MUST use cryptographically secure random number
generators (CSPRNGs) for:

- Private key generation
- Blinding factors (r, k)
- Proof randomness (nonces)

### RNG Requirements

1. **Entropy Source**: Use OS-provided entropy (e.g., /dev/urandom on Unix systems)
2. **Fork Safety**: Reseed after fork() to prevent nonce reuse
3. **Backtracking Resistance**: Use forward-secure PRNGs when possible

### Nonce Generation

Following {{ORRU-SIGMA}}, nonces (the randomness used in proofs) MUST be
generated with extreme care:

1. **Fresh Randomness**: Generate new nonces for every proof
2. **No Reuse**: Never reuse nonces across different proofs
3. **Full Entropy**: Use the full security parameter (256 bits) of randomness
4. **Zeroization**: Clear nonces from memory after use

WARNING: Leakage of even a few bits of a nonce can allow complete recovery of the witness (secret values). Implementations MUST use constant-time operations and secure memory handling for all nonce-related computations.

## Point Validation

All group elements received from external sources MUST be validated:

**ACT-Ristretto255-BLAKE3:**

1. **Deserialization**: Verify the point deserializes to a valid Ristretto point
2. **Non-Identity**: Verify the point is not the identity element
3. **Subgroup Check**: Ristretto guarantees prime-order subgroup membership

**ACT-P256-BLAKE3:**

1. **Deserialization**: Verify the SEC1 compressed encoding is valid and the point lies on the P-256 curve
2. **Non-Identity**: Verify the point is not the identity element (point at infinity)
3. **Subgroup Check**: P-256 has cofactor 1, so all curve points are in the prime-order subgroup

**ACT-secp256k1-BLAKE3:**

1. **Deserialization**: Verify the SEC1 compressed encoding is valid and the point lies on the secp256k1 curve
2. **Non-Identity**: Verify the point is not the identity element (point at infinity)
3. **Subgroup Check**: secp256k1 has cofactor 1, so all curve points are in the prime-order subgroup

**ACT-P384-BLAKE3:**

1. **Deserialization**: Verify the SEC1 compressed encoding is valid and the point lies on the P-384 curve
2. **Non-Identity**: Verify the point is not the identity element (point at infinity)
3. **Subgroup Check**: P-384 has cofactor 1, so all curve points are in the prime-order subgroup

**ACT-P521-BLAKE3:**

1. **Deserialization**: Verify the SEC1 compressed encoding is valid and the point lies on the P-521 curve
2. **Non-Identity**: Verify the point is not the identity element (point at infinity)
3. **Subgroup Check**: P-521 has cofactor 1, so all curve points are in the prime-order subgroup

Example validation:

~~~
ValidatePoint(P):
  1. If P fails to deserialize:
  2.     return INVALID
  3. If P == Identity:
  4.     return INVALID
  5. // All five ciphersuites guarantee prime-order subgroup membership
  6. return VALID
~~~

All implementations MUST validate points at these locations:

- When receiving `K` in issuance request
- When receiving `A` in issuance response
- When receiving `A'` and `B_bar` in spend proof
- When receiving `Com[j]` commitments in spend proof
- When receiving `A*` in refund response

## Error Handling

Implementations SHOULD NOT provide detailed error messages that could leak
information about the verification process. A single INVALID response should be
returned for all verification failures.

### Error Codes

While detailed error messages should not be exposed to untrusted parties,
implementations MAY use the following internal error codes:

- `INVALID_PROOF`: Proof verification failed
- `NULLIFIER_REUSE`: Double-spend attempt detected
- `MALFORMED_REQUEST`: Request format is invalid
- `INVALID_AMOUNT`: Credit amount is invalid (exceeds 2^L - 1, spend exceeds balance, or partial return exceeds spend)

## Parameter Selection

Implementations MUST choose L based on their maximum credit requirements and
performance constraints. See Section 3.1 for constraints on L.

The bit length L is configurable and determines the range of credit values (0
to 2^L - 1). The choice of L involves several trade-offs:

1. **Range**: Larger L supports higher credit values
2. **Performance**: Proof size and verification time scale linearly with L

### Performance Characteristics

The protocol has the following computational complexity:

**Notation for Operations:**

- **Group Operations**: Point additions in the ciphersuite's group (e.g., P + Q)
- **Group Exponentiations**: Scalar multiplication of group elements (e.g., P * s)
- **Scalar Additions/Multiplications**: Arithmetic operations modulo the group order q

- **Issuance**:

| Operation | Group Operations | Group Exponentiations | Scalar Additions | Scalar Multiplications | Hashes |
|-----------|------------------|-----------------------|------------------|------------------------|--------|
| Client Request | 2 | 4 | 2 | 1 | 1 |
| Issuer Response | 5 | 8 | 3 | 1 | 2 |
| Client Credit Token Construction | 5 | 5 | 0 | 0 | 1 |

- **Spending**:

| Operation | Group Operations | Group Exponentiations | Scalar Additions | Scalar Multiplications | Hashes |
|-----------|------------------|-----------------------|------------------|------------------------|--------|
| Client Request | 17 + 4L | 27 + 8L | 13 + 5L | 12 + 3L | 1 |
| Issuer Response | 16 + 4L | 24 + 5L | 4 + L | 1 | 1 |
| Client Credit Token Construction | 3 | 5 | L | L | 1 |

Note: L is the configurable bit length for credit values.

- **Storage** (ACT-Ristretto255-BLAKE3):

| Component | Size |
|-----------|------|
| Token size | 192 bytes (6 × 32 bytes) |
| Spend proof size | 32 × (14 + 4L) bytes |
| Nullifier database entry | 32 bytes per spent token |

- **Storage** (ACT-P256-BLAKE3):

| Component | Size |
|-----------|------|
| Token size | 193 bytes (1 × 33 bytes + 5 × 32 bytes) |
| Spend proof size | 32 × (14 + 4L) + (2 + L) bytes |
| Nullifier database entry | 32 bytes per spent token |

- **Storage** (ACT-secp256k1-BLAKE3):

| Component | Size |
|-----------|------|
| Token size | 193 bytes (1 × 33 bytes + 5 × 32 bytes) |
| Spend proof size | 32 × (14 + 4L) + (2 + L) bytes |
| Nullifier database entry | 32 bytes per spent token |

- **Storage** (ACT-P384-BLAKE3):

| Component | Size |
|-----------|------|
| Token size | 289 bytes (1 × 49 bytes + 5 × 48 bytes) |
| Spend proof size | 48 × (14 + 4L) + (2 + L) bytes |
| Nullifier database entry | 48 bytes per spent token |

- **Storage** (ACT-P521-BLAKE3):

| Component | Size |
|-----------|------|
| Token size | 397 bytes (1 × 67 bytes + 5 × 66 bytes) |
| Spend proof size | 66 × (14 + 4L) + (2 + L) bytes |
| Nullifier database entry | 66 bytes per spent token |

Note: Compressed point sizes vary by ciphersuite: 32 bytes for Ristretto255,
33 bytes for P-256 and secp256k1, 49 bytes for P-384, and 67 bytes for P-521.
Token size is independent of L for all ciphersuites.

# Security Considerations

## Security Model and Definitions

### Threat Model

We consider a setting with:

- Multiple issuers who can operate independently, though malicious issuers may collude with each other
- Potentially malicious clients who may attempt to spend more credits than they should (whether by forging tokens, spending more credits than a token has, or double-spending a token)

### Security Properties

The protocol provides the following security guarantees:

1. **Unforgeability**: For an honest isser I, no probabilistic polynomial-time (PPT) adversary controlling a set of malicious clients and other malicious issuers can spend more credits than have been issued by I.

2. **Anonymity/Unlinkability**: For an honest client C, no adversary controlling a set of malicious issuers and other malicious clients can link a token issuance/refund to C with a token spend by C. This property is information-theoretic in nature.

## Cryptographic Assumptions

Security relies on:

1. **The q-SDH Assumption** in the ciphersuite's group (Ristretto255, P-256, secp256k1, P-384, or P-521). We refer to {{TZ23}} for the formal definition.

2. **Random Oracle Model**: The BLAKE3 hash function H is modeled as a random oracle.

## Privacy Properties

The protocol provides the following privacy guarantees:

1. **Unlinkability**: The issuer cannot link a token issuance/refund to a later spend of that token.

However, the protocol does NOT provide:

1. **Network-Level Privacy**: IP addresses and network metadata can still link transactions.
2. **Amount Privacy**: The spent amount s is revealed to the issuer.
3. **Timing Privacy**: Transaction timing patterns could potentially be used for correlation.
4. **Context Privacy**: The request context (ctx) is revealed in the clear during
   spending. If the issuer assigns distinct ctx values per issuance, the resulting
   token chain (issuance, spend, refund, subsequent spends) becomes linkable through
   the shared ctx value. This is by design for application-level context binding, but
   deployments that require full unlinkability MUST use a shared ctx across all clients
   within the same context (e.g., per-service or per-epoch), not per-client values.
   The ctx value persists across refunds: a token produced by a refund inherits the
   ctx of the original token.

## Implementation Vulnerabilities and Mitigations

### Critical Security Requirements

1. **RNG Failures**: Weak randomness can completely break the protocol's security.

   **Attack Vector**: Predictable or repeated nonces in proofs can allow complete recovery of secret values including private keys and token contents.

   **Mitigations**:

   - MUST use cryptographically secure RNGs (e.g., OS-provided entropy sources)
   - MUST reseed after fork() operations to prevent nonce reuse
   - MUST implement forward-secure RNG state management
   - SHOULD use separate RNG instances for different protocol components
   - MUST zeroize RNG state on process termination

2. **Timing Attacks**: Variable-time operations can leak information about secret values.

   **Attack Vector**: Timing variations in scalar arithmetic or bit operations can reveal secret bit patterns, potentially exposing credit balances or allowing token forgery.

   **Mitigations**:

   - MUST use constant-time scalar arithmetic libraries
   - MUST use constant-time conditional selection for range proof conditionals
   - MUST avoid early-exit conditions based on secret values
   - Critical constant-time operations include:
     * Scalar multiplication and addition
     * Binary decomposition in range proofs
     * Conditional assignments based on secret bits
     * Challenge verification comparisons

3. **Nullifier Database Attacks**: Corruption or manipulation of the nullifier database enables double-spending.

   **Attack Vectors**:

   - Database corruption allowing nullifier deletion
   - Race conditions in concurrent nullifier checks

   **Mitigations**:

   - MUST use ACID-compliant database transactions
   - MUST check nullifier uniqueness within the same transaction as insertion
   - SHOULD implement append-only audit logs for nullifier operations
   - MUST implement proper database backup and recovery procedures

4. **Eavesdropping/Message Modification Attacks**: A network-level adversary can copy spend proofs or modify messages sent between an honest client and issuer.

   **Attack Vectors**:

   - Eavesdropping and copying of proofs
   - Message modifications causing protocol failure

   **Mitigations**:

   - Client and issuer MUST use TLS 1.3 or above when communicating.

5. **State Management Vulnerabilities**: Improper state handling can lead to security breaches.

   **Attack Vectors**:

   - State confusion between protocol sessions
   - Memory disclosure of sensitive state
   - Incomplete state cleanup

   **Mitigations**:

   - MUST use separate state objects for each protocol session
   - MUST zeroize all sensitive data (keys, nonces, intermediate values) after use
   - SHOULD use memory protection mechanisms (e.g., mlock) for sensitive data
   - MUST implement proper error handling that doesn't leak state information
   - SHOULD use explicit state machines for protocol flow

6. **Concurrency and Race Conditions**: Parallel operations can introduce vulnerabilities.

   **Attack Vectors**:

   - TOCTOU (Time-of-check to time-of-use) vulnerabilities in nullifier checking
   - Race conditions in balance updates
   - Concurrent modification of shared state

   **Mitigations**:

   - MUST use appropriate locking for all shared resources
   - MUST perform nullifier check and insertion atomically
   - SHOULD document thread-safety guarantees
   - MUST ensure atomic read-modify-write for all critical operations

## Known Attack Scenarios

### 1. Parallel Spend Attack
**Scenario**: A malicious client attempts to spend the same token multiple times by initiating parallel spend operations before any nullifier is recorded.

**Prevention**: The issuer MUST ensure atomic nullifier checking and recording within a single database transaction. Network-level rate limiting can provide additional protection.

### 2. Balance Inflation Attack
**Scenario**: An attacker attempts to create a proof claiming to have more credits than actually issued by manipulating the range proof.

**Prevention**: The cryptographic soundness of the range proof prevents this attack.

### 3. Token Linking Attack
**Scenario**: An issuer attempts to link transactions by analyzing patterns in nullifiers, amounts, or timing.

**Prevention**: Nullifiers are cryptographically random and unlinkable. However, implementations MAY add random delays and amount obfuscation where possible.

## Protocol Composition and State Management

### State Management Requirements

Before they make a spend request or an issue request, the client MUST store
their private state (the nullifier, the blinding factor, and the new balance)
durably.

For the issuer, the spend and refund operations MUST be treated as an atomic
transaction. However, even more is required. If a nullifier associated with a
given spend is persisted to the database, clients MUST be able to access the
associated refund. If they cannot access this, then they can lose access to the
rest of their credits. For performance reasons, an issuer SHOULD automatically
clean these up after some expiry, but if they do so, they MUST inform the
client of this policy so the client can ensure they can retry to retrieve the
rest of their credits in time. Issuers MAY implement functionality to notify
the issuer that the refund request was processed, so they can delete the refund
record. It is not clear that this is worth the cost relative to just cleaning
them up in bulk at some specified expiration date, however if you are memory
constrained this could be useful.

### Session Management

Each protocol session (issuance or spend/refund) MUST use fresh randomness.
See the Randomness Generation section for detailed RNG requirements.

### Version Negotiation

To support protocol evolution, implementations MAY include version negotiation
in the initial handshake. All parties MUST agree on the protocol version before
proceeding.

## Quantum Resistance

This protocol is NOT quantum-resistant. The discrete logarithm problem can be
solved efficiently by quantum computers using Shor's algorithm. Organizations
requiring long-term security should consider post-quantum alternatives. However,
user privacy is preserved even in the presence of a cryptographically relevant
quantum computer.

# IANA Considerations

This document has no IANA actions.

--- back

# Test Vectors {#test-vectors}

This appendix provides test vectors for implementers to verify their
implementations. All values are encoded in hexadecimal.

## ACT-Ristretto255-BLAKE3 Test Vectors

<!-- TEST_VECTORS_START -->
The following test vector was generated deterministically using a
ChaCha20 RNG seeded with the bytes `00 01 02 ... 1e 1f` and L=8.
The domain separator is `"ACT-v1:test:vectors:v0:2025-01-01"`, credit amount
c=100, spend amount s=30, partial return t=10, and ctx=0. Values labelled `*_cbor`
are the CBOR wire-format encodings (Section 4) of each protocol
message, displayed in hexadecimal.

Implementations SHOULD verify they can deserialize these CBOR
messages and that a full protocol run with the same deterministic
RNG produces identical output.

## Parameters

~~~
domain_separator: "ACT-v1:test:vectors:v0:2025-01-01"
L: 8
c: 100
s: 30
t: 10
ctx: 0000000000000000000000000000000000000000000000000000000000000000
~~~

## Key Generation

~~~
sk_cbor:
  a201582036e5b43419551a92c809a995a3d2c817a86ce8f5dd973b06fe9cb5a3
  f012870b0258204aceeb1d507e50957db46b6bcd374614b8ea080cbbc77ad060
  666bf5788c8121

pk_cbor:
  58204aceeb1d507e50957db46b6bcd374614b8ea080cbbc77ad060666bf5788c
  8121
~~~

## Issuance

~~~
preissuance_cbor:
  a20158206102398efee33b886f4bb7042b897d83db59b71a05aff76e9b633b87
  cade7d0002582069e5d557cb6094acfa586118e602e90aa6fe6cbabd4571eeb0
  d2f63b8c8a8f07

issuance_request_cbor:
  a4015820aa9315999f76c89406fe743dc7ff12e8fab85871f8c36987c6ec25ee
  ca2cd84e025820811880b9160decfbb41006af6c39056c9b0c139f7acf647fb5
  b0b22486039504035820c319066c466ef36d08809279c02dac8430c119fae886
  7f0c235cd6f6e4514c0f0458206af5dcb3e7138eb2a0f5b523054e05137b558f
  1bb6711b10b689e3565c241506

issuance_response_cbor:
  a60158201eeda51d75404be1bdd06c31aa72bbd38470a4717e732ccf372b91bc
  77161a0e0258204778cf09b14bf78e89e5ef5bcb523863d4e70f9d84ae1fbe75
  778e60a92c290e035820e94bd324b71702e9f29a239b3a064caa4c46d85d9693
  0f75bc39eca6211d2c0f04582029002c4fa8a9f71b8c015fb7869ad64a0fc4e0
  50c7c4955ef6ebff27f722890e05582064000000000000000000000000000000
  0000000000000000000000000000000006582000000000000000000000000000
  00000000000000000000000000000000000000

credit_token_cbor:
  a60158201eeda51d75404be1bdd06c31aa72bbd38470a4717e732ccf372b91bc
  77161a0e0258204778cf09b14bf78e89e5ef5bcb523863d4e70f9d84ae1fbe75
  778e60a92c290e03582069e5d557cb6094acfa586118e602e90aa6fe6cbabd45
  71eeb0d2f63b8c8a8f070458206102398efee33b886f4bb7042b897d83db59b7
  1a05aff76e9b633b87cade7d0005582064000000000000000000000000000000
  0000000000000000000000000000000006582000000000000000000000000000
  00000000000000000000000000000000000000
~~~

## Spending

~~~
nullifier:
  69e5d557cb6094acfa586118e602e90aa6fe6cbabd4571eeb0d2f63b8c8a8f07

context:
  0000000000000000000000000000000000000000000000000000000000000000

charge:
  1e00000000000000000000000000000000000000000000000000000000000000

spend_proof_cbor:
  b201582069e5d557cb6094acfa586118e602e90aa6fe6cbabd4571eeb0d2f63b
  8c8a8f070258201e000000000000000000000000000000000000000000000000
  00000000000000035820b221966bf32eafaac154b44f6037083d01314eee2e46
  e11b5003bcd07b6bb074045820562528491b9c19a10cefd74b3e45a89fcfdd62
  440997758ae8fa34d1a8d8583d05885820581721b2e63035cfe346849bd92c2b
  937b8e9404dabe1e5ca29e77de3321852a5820448491c7d81ecc20a9705b1bdd
  4df0c71570df3ad5fd9334758f8df9f56ede32582096431dd3f6ea1d7cb43165
  8d6f0fe14795e569b731c3cbe79bf293d78b6674255820cc718e6924e761e85b
  abf7a2b2336e892bb722c36d5aad88ee962b2d8d6b003a5820349e11dd9143d4
  8cf90e62386ebcada9490ab0ebb87739c49863ddd8a984a43a5820cc635618f8
  1e27bb91252afb2d66ea443cc17e48d4f08c0041f1071e6ead92145820e6e7cd
  cde60cf3fcef195aa9c511636eb31ee52ed1a328a821f9600bc997d25d582092
  857b094af803da09df1a95db12761e860425b53cb7cd967d3c227e535b991d06
  5820c68d2efa21dce1ada7a23b30c34edce8db9d6bc71ce2e8c75921fb179f6c
  d10607582003918610c7af601b6e22c22d0861e781252a24c6f759c4cda08b8f
  1fe7a09003085820c273eff86e662b4d44bcbdb73b0e4eec7714662dd1c0db61
  5ad53260a2b7650b0958207dbd42848d4dc3cb0a5461f26a08c3761f5decf00c
  d97976302a12a1ec46dc0e0a5820e97e15f04be7008f2f1c0bc69d2d4bebfbd1
  8bcca213f1ccf6187e933166e9050b5820a19468507a55c3e47628a435e3210e
  8024dc8259a06fdf7efb8c0e70d4a07e0d0c5820786081f2c4f6061d3e313f67
  cc7f73500283ffefa13a0f829e7ce85c8b19640b0d5820b8b352e7cb2066cef5
  cbbb79ae17852b0e44c82dc29b4b9a76d3422037e14c0c0e8858209411a6afca
  a687cba25c7a3ba2e3f3e12917bce920615a6073b7dceebad92b0b58205d5690
  3268f420e1ccc725685a7be6edd935f9a1ddc0e11508d648268e198b09582046
  040cd466c38375c1811153671aeed9530a3f052ed30c660d33141252255f0458
  209aa8b4018a9a0d53701b704bcd5636b1870749f1fd45dda322764282784707
  0a5820e3c62f417f88e5b7ec2182560e0d852e50e37a1d7ac00a8f5e090a7205
  f41f0d58205f22918a53fb88546521a44238ce5608c13c6ebf0f11f6784c835a
  c531b8720a58209d04a1b04cc9f59818dbaf7d04da70d2446145f9534886bce9
  5ed2b70df7cd095820346599fabc841424884cd029f3d63ae63158c6b4c975af
  e0d1147715d462aa020f88825820677b5e013537036d2e0c11ec8117799424bc
  ee744e7b1bd9571b7c464c7b72085820ba017329a9e86ccbe5ed1c76a1362f39
  9724cc7211b77940b6c513155bb1b30e825820ab6c718a173c91b3d30670fa50
  862021895ca40c818bc9d15e4110f7c0a4640958203c36da850f85cf51fdc896
  54b0a853677308974b9ea38e6e7e49ce94560ca8018258201b7d378abce009fc
  e50133f2d77380f3492794f72b209407e155f8ed8341bd05582057aa6d5d46a6
  d3b63c1d45af5c8d66ebc78494ee94df100b6cefc775fa6db8098258205612d9
  c1afb3c81bc81860c99b18466af0797eec6ebb3c6b8207b0521ffdf20c58209f
  5184c3bd8bc8d7a3f33941a3e8126850fbc795d4809dfeb5f363a30ff2ee0482
  58204c7c14d9881aa291a136ab4979d832cf5c80b75c8fe00ca976f65b3d4c9d
  150c5820150b6c20f4b894b4d491a252b4956c72e880639b7880f25f6ad0cba1
  6dbd020f8258207b2bc0d260f1f3ac32dfa6643a721a845faf9fe8e5de52751f
  5d824fa34e770f58209fe39299e57caa120937957a8957cd6c25f14958ea8e7b
  6333a2ac501bc144068258201f19d99a4e9955cc464fe48912f51399358bc678
  4a22312a95233e592dd1070558204c666f3adfaa3806b290247faa6950bb74e2
  70c9155f5004d407d21f223c0802825820d0b1d956f1b1a4ffb3c1a447bcb22a
  0e5679b70ca98357ce0dd5b6670bdc480e582017636a9a14caef700e53785bcb
  bd98380ac45d53af06107e99911fbf4ccf24001058201c7ad54f635ebd976c1e
  4fc275d93ce2e0981bbcaacb3745deda0be61cfe9f07115820c8451b222fdf76
  abc8a76dd90d1b5526de7e510809750825eea0cce6a4fe1c0212582000000000
  00000000000000000000000000000000000000000000000000000000

prerefund_cbor:
  a40158200f9288d8ef1360d8ef4967e041bf09a716c093956464370d30dfe283
  2be71b06025820ebada4fb4050db92729a58f0ae585f76154103a2ef2166c401
  12638f006d280b03582046000000000000000000000000000000000000000000
  0000000000000000000004582000000000000000000000000000000000000000
  00000000000000000000000000
~~~

## Refund

~~~
refund_cbor:
  a5015820880974b47fd0d4d06333e2f047abc4420992bd903ed44dae86199a54
  361f9c540258208a0977b088e9d17a637f71a013c67774648f0da03b141404ae
  678a0e5e090b04035820fdcd645c0d6e13905fff07e56d63465e4cc585f3c247
  8500c96cd361a4ad01070458202c9f3110e53540738100e7e636949ce7ac08bf
  b4ac6867fb72ac6ec847a2f90e0558200a000000000000000000000000000000
  00000000000000000000000000000000
~~~

## Refund Token

~~~
refund_token_cbor:
  a6015820880974b47fd0d4d06333e2f047abc4420992bd903ed44dae86199a54
  361f9c540258208a0977b088e9d17a637f71a013c67774648f0da03b141404ae
  678a0e5e090b04035820ebada4fb4050db92729a58f0ae585f76154103a2ef21
  66c40112638f006d280b0458200f9288d8ef1360d8ef4967e041bf09a716c093
  956464370d30dfe2832be71b0605582050000000000000000000000000000000
  0000000000000000000000000000000006582000000000000000000000000000
  00000000000000000000000000000000000000

refund_token_credits:
  5000000000000000000000000000000000000000000000000000000000000000

refund_token_nullifier:
  ebada4fb4050db92729a58f0ae585f76154103a2ef2166c40112638f006d280b

remaining_balance: 80
~~~
<!-- TEST_VECTORS_END -->

## ACT-P256-BLAKE3 Test Vectors

<!-- P256_TEST_VECTORS_START -->
The following test vector was generated deterministically using a
ChaCha20 RNG seeded with the bytes `00 01 02 ... 1e 1f` and L=8.
The domain separator is `"ACT-v1:test:vectors:v0:2025-01-01"`, credit amount
c=100, spend amount s=30, partial return t=10, and ctx=0. Values labelled `*_cbor`
are the CBOR wire-format encodings (Section 4) of each protocol
message, displayed in hexadecimal.

Implementations SHOULD verify they can deserialize these CBOR
messages and that a full protocol run with the same deterministic
RNG produces identical output.

## Parameters

~~~
domain_separator: "ACT-v1:test:vectors:v0:2025-01-01"
L: 8
c: 100
s: 30
t: 10
ctx: 0000000000000000000000000000000000000000000000000000000000000000
~~~

## Key Generation

~~~
sk_cbor:
  a201582039fd2b7dd9c5196a8dbd0377b8dc4a498a35d86fbcde6accb2cc7d4c
  d8ea249202582102ceff7e162d6baee1abd2f72b83fdaa96df661e4375d87561
  c8e41936310f3dc4

pk_cbor:
  582102ceff7e162d6baee1abd2f72b83fdaa96df661e4375d87561c8e4193631
  0f3dc4
~~~

## Issuance

~~~
preissuance_cbor:
  a20158202b23cce7a26023ab3f0eef693ac87f64258235eab1f7a32dc22762a0
  485b410c02582018b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cec
  f8fc122a35755c

issuance_request_cbor:
  a4015821026e58ff0193bcbeca44fac89c2bfa10460fd6244ea2ebed87d8880f
  d400416a9b02582026e96d7da34b92ee4563f7ea7ccbb0eaf4e5dbd3c23b7b6b
  b342c64f782f357a035820e207ce3fa31ef309a6d2fd9f550cad22bfba0edd54
  33c1d4b3423ff56f4f3e4b045820777eac48c4f4f140ca186e08e2e61c50f4dc
  ca318146aa6057c8e68b31bca474

issuance_response_cbor:
  a6015821028f470643404f28577a22be26b6b6fe2c860434633c860c68767b45
  e575696c2902582084a8021b8a5c0b2494cd3c8d5b13507ec7e7a0784df4a3e2
  ea8162d261c59d230358204dd5f53c42fed5eaf04e61888f0479dd4c4365b37b
  7546ed78502bb63c02006504582071a31e0a8009b0959f3cc2ee3acf9c1b66ae
  e2e9bdc81d223a4d577baef63a9d055820000000000000000000000000000000
  0000000000000000000000000000000064065820000000000000000000000000
  0000000000000000000000000000000000000000

credit_token_cbor:
  a6015821028f470643404f28577a22be26b6b6fe2c860434633c860c68767b45
  e575696c2902582084a8021b8a5c0b2494cd3c8d5b13507ec7e7a0784df4a3e2
  ea8162d261c59d2303582018b84231ade6a6d113615c61af434e27f8b1f3f5e1
  ad5b5cecf8fc122a35755c0458202b23cce7a26023ab3f0eef693ac87f642582
  35eab1f7a32dc22762a0485b410c055820000000000000000000000000000000
  0000000000000000000000000000000064065820000000000000000000000000
  0000000000000000000000000000000000000000
~~~

## Spending

~~~
nullifier:
  18b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc122a35755c

context:
  0000000000000000000000000000000000000000000000000000000000000000

charge:
  000000000000000000000000000000000000000000000000000000000000001e

spend_proof_cbor:
  b201582018b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc12
  2a35755c02582000000000000000000000000000000000000000000000000000
  0000000000001e03582102738d8ae82048de8955c263e9c00a29567632258628
  54765a0d793afc4b2cf48104582103fb5ad1b75fe460acb1cb9cf2a24f8ada51
  42a25539a0452e3c2d48406b8ea6ae0588582102997f6ec67ba7398e93281412
  a94ddeef0e5d31bf9a756b202029e60b257d5793582103f4c046d8a7550387c0
  2f7cc1ebc91e41920ff3968435c20f5aebe7f3d2317a47582102bd494d458626
  e83c365a1c915f4d0c6cade3ce49e0ad76f3ed40b45c6717f30a582103cd8a75
  fe55aa93ac4fbb45eebfca905710e9cce3291a1803e9de7ac24f66a5a8582103
  4bc72ce6cfa743e9cc1f1dc52788be9dd19b87ecd92e35afd2771e7a62c1359c
  58210343d68b8ea1b98af1f8ce8fa76dbcf45bad67a2b28b5cc77abeda39cbf4
  578c5d582103245de90001244716e982800a1ed4e41546b6061c2eb0511289c3
  1edd059e169758210200357e013b2a536a8bf3574e723867198809c24909a434
  2c96bc58c20717b51c065820e782d1b6ba455e6df553894ec9011b04139287e9
  2fb2ca7f0787f0ab7e616bcb075820278205b5400795d405b97db55f95257351
  c2aa8b8939166494ceea243b22742d085820a23592671701f2b9d351e31e07ae
  cb8f83d650e2e5fd07521335241d1ea8d01509582078214773099b07b8a29157
  c2906948a107be7b36631a993fdfa448d772df30ca0a582073136773ea5e1da7
  2641b18fd6db7642e1f19e1059c61813b7d56621426d58930b5820f569c7c3ba
  efcb183750165fb7987ea951564ab8f671fa993f295a51ce15cfd30c58206070
  7bd2aae531a2e537ef84f1f25d02ffedcab45dbd5cf5ad9db47ffb29f5400d58
  206a9192e22167b171783edc442d1debea35c8c62cd27be25ccdd0cb887fc41b
  530e885820b16895e5640288e2ea42aef2fa64c7c2b3cf27fea5a5baecc9300e
  46fac903d25820ceca4aa2ff6d7aae8d4a8e9ad50786663932729106f437bfb4
  f735df0b52b40a58204fa9a0fbc0552298605991cea5c0600a388e83f6d065e2
  aae3666aa6e87d69e65820caebc89604ec67b5bba8217ae84c2f8f5c49add8fb
  ef66cfb71a80d4a0aa2ed458203eda012591de6843d1580c9959e61da04b035b
  7a02173f5fae657376c915c8b458204639bc6891251c1de384fd527752f8503e
  6fb621fd7d08a250dc8616f6f5d0f058209ca80e6252fae8f0bf5bbbf33157a0
  fda42ed9f25cc3fe099a2b1fbd793e1c3458200110928a6d7097e454ebd220d0
  ff675c2a53210cb97fa511ae6a963a5c4ee6b60f88825820c893c88a8e86c344
  c8230311a465ee7d945d390d163e357dd6b327f8646e6d90582021dfcb29a804
  6791dca97da2e977616065171fdca134c9e02e67fe356c70da208258207d7a20
  ccff17e7873f7f3465f6c8c70abc53d97ff7dac95f56a19a103edcd9a2582022
  02fdc0009d495b813706da05bf1c60d33eac88f474aece195a8ff1e98c07da82
  5820d45cab4cd1d9924b4bbfbaf09c34769621184923e61d8384a064d607beaa
  72b45820916ec0a1b8faf9965c435847d1dc94babb0a3d0d0b61f2f54c06fadb
  ce4e1ebf8258209c9cf1dbf1959abf9015d1c7ca8548a4b6d2a0273de30807cb
  e4cb3143aebd6b582005d644e79d25d9b4b913ad9a64826a5dd60edfa8bbf1c7
  604c77c81b8d4285358258203cf43a3a128f254e0a8e70d2605fdc741be98ada
  ed93e24dac0d32a1676776435820183588ca784a4e5606a2627b641ca044376b
  dfb7f2b3e3c8f5bc5dc1c6ff03058258205a94acd42769d36c2d5d8ebaeccf98
  c007a517ff1aad003cc133ce86d6da8eb85820bb6e37774d548b6d6a714bd84b
  fdfbc94074836079640e86d6998877c9716a59825820d44d65d01b23b9c3789e
  75b5b5a34751f269d2d81d80bc7d33d2e41a71b2424158203afcba9e60ad6d51
  89ee582a8b560ac448da1625ddf79437a7df8896a3adc611825820b03cc81b71
  8f0c1a5242dc3988434f0300c0fdfee993fe65e58d7d0f7a3553e25820627d76
  64c5fd194f8f1b38539167d77bcc036beed2f47005e69a940ccf52b239105820
  3d933d30ba8f597bbc8661419cf06f9119ea26506f92e0c4284a16d941d6b778
  115820905736a05a44f2866cca5f33600347b88d62d79385d1351d117b05e7d7
  0131361258200000000000000000000000000000000000000000000000000000
  000000000000

prerefund_cbor:
  a4015820a7173d05ed1dcb97392f4e8da31fbf2fae2856706441f486418dffd1
  7794fefd025820185838beabf85b1605467c46149350e877815eefc73f7d9b3d
  94b198d7fef9c903582000000000000000000000000000000000000000000000
  0000000000000000004604582000000000000000000000000000000000000000
  00000000000000000000000000
~~~

## Refund

~~~
refund_cbor:
  a5015821020e4bae5552fa1869c6f4ce8b1a02af205b497d1d67047175fd4514
  95adfe21de025820608f22735090d5bc4c5008960d409643e95e2fbbac5573d3
  8961045c80dc83fb0358207f00027065f6f2677dfcb88364c08424ed8e4ef968
  f4963b90a72a7044f02c0a0458200c3fc80af252eae45b0b3e2d3863d53cf149
  efb29a2db79b060d98126f6e3fb1055820000000000000000000000000000000
  000000000000000000000000000000000a
~~~

## Refund Token

~~~
refund_token_cbor:
  a6015821020e4bae5552fa1869c6f4ce8b1a02af205b497d1d67047175fd4514
  95adfe21de025820608f22735090d5bc4c5008960d409643e95e2fbbac5573d3
  8961045c80dc83fb035820185838beabf85b1605467c46149350e877815eefc7
  3f7d9b3d94b198d7fef9c9045820a7173d05ed1dcb97392f4e8da31fbf2fae28
  56706441f486418dffd17794fefd055820000000000000000000000000000000
  0000000000000000000000000000000050065820000000000000000000000000
  0000000000000000000000000000000000000000

refund_token_credits:
  0000000000000000000000000000000000000000000000000000000000000050

refund_token_nullifier:
  185838beabf85b1605467c46149350e877815eefc73f7d9b3d94b198d7fef9c9

remaining_balance: 80
~~~
<!-- P256_TEST_VECTORS_END -->

## ACT-secp256k1-BLAKE3 Test Vectors

<!-- SECP256K1_TEST_VECTORS_START -->
The following test vector was generated deterministically using a
ChaCha20 RNG seeded with the bytes `00 01 02 ... 1e 1f` and L=8.
The domain separator is `"ACT-v1:test:vectors:v0:2025-01-01"`, credit amount
c=100, spend amount s=30, partial return t=10, and ctx=0. Values labelled `*_cbor`
are the CBOR wire-format encodings (Section 4) of each protocol
message, displayed in hexadecimal.

Implementations SHOULD verify they can deserialize these CBOR
messages and that a full protocol run with the same deterministic
RNG produces identical output.

## Parameters

~~~
domain_separator: "ACT-v1:test:vectors:v0:2025-01-01"
L: 8
c: 100
s: 30
t: 10
ctx: 0000000000000000000000000000000000000000000000000000000000000000
~~~

## Key Generation

~~~
sk_cbor:
  a201582039fd2b7dd9c5196a8dbd0377b8dc4a498a35d86fbcde6accb2cc7d4c
  d8ea24920258210301302fa089e8355da29cc6d17fd7f19de9312ce145a457bf
  399d9bced806be42

pk_cbor:
  58210301302fa089e8355da29cc6d17fd7f19de9312ce145a457bf399d9bced8
  06be42
~~~

## Issuance

~~~
preissuance_cbor:
  a20158202b23cce7a26023ab3f0eef693ac87f64258235eab1f7a32dc22762a0
  485b410c02582018b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cec
  f8fc122a35755c

issuance_request_cbor:
  a40158210233591f3a5c791a422b27b5e795e3abe33438b75a12c91ee9a7b4fe
  13a7bd4c2502582033029bfd21f72d9595951761e00c6c8a9f42be24c8636707
  a721a98adf8061010358204affafb35e774352c143d2633e874d2a727a7de1fb
  9c3a0a81442210ae837ad204582039b2879940dd4dd323009991c88328119d92
  52300958942bffa025321c35368d

issuance_response_cbor:
  a60158210353ad23d990da86086e7174de8872e211c4074dfb3806c694d02e34
  1f30e1018902582084a8021b8a5c0b2494cd3c8d5b13507ec7e7a0784df4a3e2
  ea8162d261c59d230358209b1fcf4a2abd433def37ab844120bb18dad7958784
  b1c097aa4b654baca7ae630458201cb4188584a7961b64e867824abd2e4e6b1b
  4450eb64dc159bfc12be5ed46add055820000000000000000000000000000000
  0000000000000000000000000000000064065820000000000000000000000000
  0000000000000000000000000000000000000000

credit_token_cbor:
  a60158210353ad23d990da86086e7174de8872e211c4074dfb3806c694d02e34
  1f30e1018902582084a8021b8a5c0b2494cd3c8d5b13507ec7e7a0784df4a3e2
  ea8162d261c59d2303582018b84231ade6a6d113615c61af434e27f8b1f3f5e1
  ad5b5cecf8fc122a35755c0458202b23cce7a26023ab3f0eef693ac87f642582
  35eab1f7a32dc22762a0485b410c055820000000000000000000000000000000
  0000000000000000000000000000000064065820000000000000000000000000
  0000000000000000000000000000000000000000
~~~

## Spending

~~~
nullifier:
  18b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc122a35755c

context:
  0000000000000000000000000000000000000000000000000000000000000000

charge:
  000000000000000000000000000000000000000000000000000000000000001e

spend_proof_cbor:
  b201582018b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc12
  2a35755c02582000000000000000000000000000000000000000000000000000
  0000000000001e035821027017582a4451a02f86235a18382fb18882eab36d6a
  a6d88af4e70551abde0de8045821034f0e16a404e3397e2e8fd051dcc90dfc68
  fb542af63fa628fde531c51a6350b60588582103a87031706ff4a8eaa3b847e3
  37ecfdc4a1d466d0b1825a1ef1f2b5058cb3b2c858210285eae1a685949147f3
  f360ca096eb6b946045fb1318f26c8d41fd3dfe0961be858210360620f2a0217
  25bf8f2d6053216451ad738735bb8e58ebee34b6365d88550188582102e8fe1c
  16109af904956a43744de751a48b7f5babf223a7d9d4d806875cec2eda582103
  5d70250f1ba3974daaa56ee0a54ae53756a2990602b76dc7b33313701c23308a
  5821033bd90dfe3a0a9ad44bc093e5476457b207a16ba2aa12212e469c009bad
  b44864582103fb80424145bfee4510b0daa66c9a3610d6f8a77f9460808aba6a
  35a2e2dc788258210354e7cdc20d6ce47e7a0cd9604c14ad27c11f4e2ce4d00a
  f5ab840de359266fd6065820b1148d93a9bc491b8e16aa2e0550dca20bc3442b
  bdf0274c4df23c6410dba2740758206f045da12aae89c0d0fb75ea926ffd017b
  61752999ca0beaabbcd87d2e3165b40858201665e39e44f79fb8736b0f7aa51e
  93b0b18f198af4773d947240c02f3ffa580a095820606415390f9c72225f500d
  112c46461983b6ef5581c51eb2a281018ae95362960a5820b62605805fea717d
  7a08da5c47b3d44dd6d57d314a134d413ab2056f6e74769a0b5820608191b7e5
  dc82e184164d90df231a3110687ef2ef53d122faefecb73949a96a0c58206df6
  42d946a55f875b9f0860a06e4108131372e7ce52a218ae56e7b573ab83440d58
  206a9192e22167b171783edc442d1debea35c8c62cd27be25ccdd0cb887fc41b
  530e8858207afa51c2537973908305cfd236b48960abffe44133e317ba0f9a59
  ff8d433a7b5820ceca4aa2ff6d7aae8d4a8e9ad50786663932729106f437bfb4
  f735df0b52b40a58204fa9a0fbc0552298605991cea5c0600a388e83f6d065e2
  aae3666aa6e87d69e65820947d8472f4635263546b425a249bf12d547a6a1b8a
  2cc39cfd84cc8d3324657d5820086bbd02815552f16a1b2d789635df3e433417
  bc90549c2cf4cfbf2f5b8fff5d58200fcb7845809c06cb7c481e31b3a2b9ee36
  a072648bba656f9746d1cf8970079958209ca80e6252fae8f0bf5bbbf33157a0
  fda42ed9f25cc3fe099a2b1fbd793e1c345820caa24e675ce78291edaef3000d
  4f28f8dd32ba35f705a21ab4a7407fbeff5ea00f8882582003abed40e708604f
  04669dbbdbda04f007daec46aabbcd1e27371b357e64e50c582021dfcb29a804
  6791dca97da2e977616065171fdca134c9e02e67fe356c70da208258207d7a20
  ccff17e7873f7f3465f6c8c70abc53d97ff7dac95f56a19a103edcd9a2582054
  bbfbd16238d2888005f0ff4b41f2ca2dcfabbbee9cdcd66a9f0a3ef534d6cd82
  5820d45cab4cd1d9924b4bbfbaf09c34769621184923e61d8384a064d607beaa
  72b4582006c5453ed8dfd826021c4b84cd53180203a4b3b5eee1f0c371d6aa87
  fe786631825820d1ccc19d18e0e53e87e00e3576a07408ffbead81c83130fcdf
  893189c465c6e1582005d644e79d25d9b4b913ad9a64826a5dd60edfa8bbf1c7
  604c77c81b8d428535825820d66ff214e18271898115abbe62af0470c20a3d7e
  60142b4f28c7ce41178d08595820183588ca784a4e5606a2627b641ca044376b
  dfb7f2b3e3c8f5bc5dc1c6ff0305825820a9aa1b4a62b657c10374aa35b1d301
  ac3153025c130e8968de1b67e9e81a92ae5820bb6e37774d548b6d6a714bd84b
  fdfbc94074836079640e86d6998877c9716a59825820d44d65d01b23b9c3789e
  75b5b5a34751f269d2d81d80bc7d33d2e41a71b24241582074d75e48f7fc13e3
  1e3f116c4806121bb93ad7a7c027ffccad2da8e55edfe0f4825820ef1e3b797e
  5dbdeeb57ed5847abb260f890ce5bd8320d3ee9da54405bfddd1a15820627d76
  64c5fd194f8f1b38539167d77bcc036beed2f47005e69a940ccf52b239105820
  dbd24ffdcb566c16dd8cf66e6882f941830f9b3c10ad4debec0ae2d10bc3e03c
  115820b49c3b0eaac33ef2b56e7b8e34a900bbc983d4c390f469b88bc67b21d2
  32c7cd1258200000000000000000000000000000000000000000000000000000
  000000000000

prerefund_cbor:
  a4015820a7173cbaed1dcbe2392f4e8da31fbf7b54990fbafde673f8765ab3b0
  68bbcfad025820185838beabf85b1605467c46149350e877815eefc73f7d9b3d
  94b198d7fef9c903582000000000000000000000000000000000000000000000
  0000000000000000004604582000000000000000000000000000000000000000
  00000000000000000000000000
~~~

## Refund

~~~
refund_cbor:
  a501582103132603f95005e506212da5c8bec0ed1b18f0aea1752e529db15fc8
  d21dc78eda025820608f22735090d5bc4c5008960d409643e95e2fbbac5573d3
  8961045c80dc83fb0358204e85fe14a0be99fe2b99867002f83c72cdd2c55786
  9ca112ad97beb72d989d3b0458206eb0f315bcf6e17702a8bca3c584c3bfe413
  0554c55220b6989bad80823b4173055820000000000000000000000000000000
  000000000000000000000000000000000a
~~~

## Refund Token

~~~
refund_token_cbor:
  a601582103132603f95005e506212da5c8bec0ed1b18f0aea1752e529db15fc8
  d21dc78eda025820608f22735090d5bc4c5008960d409643e95e2fbbac5573d3
  8961045c80dc83fb035820185838beabf85b1605467c46149350e877815eefc7
  3f7d9b3d94b198d7fef9c9045820a7173cbaed1dcbe2392f4e8da31fbf7b5499
  0fbafde673f8765ab3b068bbcfad055820000000000000000000000000000000
  0000000000000000000000000000000050065820000000000000000000000000
  0000000000000000000000000000000000000000

refund_token_credits:
  0000000000000000000000000000000000000000000000000000000000000050

refund_token_nullifier:
  185838beabf85b1605467c46149350e877815eefc73f7d9b3d94b198d7fef9c9

remaining_balance: 80
~~~
<!-- SECP256K1_TEST_VECTORS_END -->

## ACT-P384-BLAKE3 Test Vectors

<!-- P384_TEST_VECTORS_START -->
The following test vector was generated deterministically using a
ChaCha20 RNG seeded with the bytes `00 01 02 ... 1e 1f` and L=8.
The domain separator is `"ACT-v1:test:vectors:v0:2025-01-01"`, credit amount
c=100, spend amount s=30, partial return t=10, and ctx=0. Values labelled `*_cbor`
are the CBOR wire-format encodings (Section 4) of each protocol
message, displayed in hexadecimal.

Implementations SHOULD verify they can deserialize these CBOR
messages and that a full protocol run with the same deterministic
RNG produces identical output.

## Parameters

~~~
domain_separator: "ACT-v1:test:vectors:v0:2025-01-01"
L: 8
c: 100
s: 30
t: 10
ctx: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
~~~

## Key Generation

~~~
sk_cbor:
  a201583039fd2b7dd9c5196a8dbd0377b8dc4a498a35d86fbcde6accb2cc7d4c
  d8ea24922b23cce7a26023ab3f0eef693ac87f640258310263d8397072540c4f
  654ea4ce5975630c7067b519107a81c7030e349c8b331517be27199568faed4b
  9f16671b6cb99835

pk_cbor:
  58310263d8397072540c4f654ea4ce5975630c7067b519107a81c7030e349c8b
  331517be27199568faed4b9f16671b6cb99835
~~~

## Issuance

~~~
preissuance_cbor:
  a2015830258235eab1f7a32dc22762a0485b410c18b84231ade6a6d113615c61
  af434e27f8b1f3f5e1ad5b5cecf8fc122a35755c0258307208086dd1ee3c5d9d
  815824640e003c9ba0f65ede5d59ce0d2a4a7f31955acd42f22ddca74a92d56c
  a78aef298e723b

issuance_request_cbor:
  a4015831026e0bd2b2a4d6a164bf836f49424b0dfac89575c5154bae176e5f8b
  ddba16f0021e26a169c853e22238e9d1296bc6251902583094f40eb51f9b07c6
  989a27104c33bda89da9f17d8b6ffc3b90f0d0d4c43d1bd587b679c83d095f1d
  4ccc6a5d447912330358306fd0884850269492ce3a1f28ddf3f6f0b6aa8de5f5
  170e8bdca0c86eda3fefaa89b92c762f69582054f6ef73e217a458045830be6c
  82d5bfb23f9fe122a5592da119d4f60bd3d5243e234055a78dcbaf3906616bc1
  c0d6c07652cabef2f50284ec81f5

issuance_response_cbor:
  a6015831030e2419259bc1f3244fddc601e0c3e731d7f891b589a0a2def9b606
  38de861ead79c88ec43856ad48d49cf3cb5ad4f3ce0258304acbf8ff1fd1a7c8
  06d81ca8e4ae3b2cffdba11827588c438f5434eac956be8f95a043ad04cdfd0a
  97d7fa49d40d099e035830daabd3bf03f27de80cdee2b5f1228ce1e16b5e9bdd
  db7f7a3ffd89558e91eadc05f6ed2b510c2fb1fa112ef1110dfe4d045830dbab
  9bfc9cf5689f8b3726648abf7953734d32ef6343ae515d962da90c51eb35149d
  cde0665ca601918755f17f3426ee055830000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  6406583000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000

credit_token_cbor:
  a6015831030e2419259bc1f3244fddc601e0c3e731d7f891b589a0a2def9b606
  38de861ead79c88ec43856ad48d49cf3cb5ad4f3ce0258304acbf8ff1fd1a7c8
  06d81ca8e4ae3b2cffdba11827588c438f5434eac956be8f95a043ad04cdfd0a
  97d7fa49d40d099e0358307208086dd1ee3c5d9d815824640e003c9ba0f65ede
  5d59ce0d2a4a7f31955acd42f22ddca74a92d56ca78aef298e723b0458302582
  35eab1f7a32dc22762a0485b410c18b84231ade6a6d113615c61af434e27f8b1
  f3f5e1ad5b5cecf8fc122a35755c055830000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  6406583000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000
~~~

## Spending

~~~
nullifier:
  7208086dd1ee3c5d9d815824640e003c9ba0f65ede5d59ce0d2a4a7f31955acd42f22ddca74a92d56ca78aef298e723b

context:
  000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

charge:
  00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e

spend_proof_cbor:
  b20158307208086dd1ee3c5d9d815824640e003c9ba0f65ede5d59ce0d2a4a7f
  31955acd42f22ddca74a92d56ca78aef298e723b025830000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000001e035831036296e1aed312204c396288d2f99f7bbc6a4717ef1e
  c5b97b4be73322c75f9aab70539cbcab21f124e2b3d5d1a5f9c31404583103e5
  364a37d75aaa65b02f3e11f9e427df29ac0344b9b52401141efcacba6266af1d
  d6a4e1a7498ceeeaf7bd7a15e71a2005885831038278a69e56cc22343ebf02d3
  ed9335e39ba9796cc1764c6a247399d54c5790bc055694b53481beb92f20c138
  1d31278c583103bfb1d3b5777f7745a64eb594e061ea1fe191e7635fd9582bb1
  ca177192ab43552ee03a63d8bb39103385ab469de21fd8583103eb0798861c9b
  488a7922747c22d7a237a1265ce17e7e01a6d34f2ced91e0d8d321c2497d5c8b
  5966c813737df094fc04583102d2fd906a5aba6789a67224c37447b0711d2e4c
  65bf74adb351ccf9780312ae292e5e283d6629e6f7db6cd79f41c6e4cb583102
  ace9728aa318f26dbfe0b8ee909d3fc653a30d48f383a64dd934bd0a3b9f60d1
  7e9b020db9b141b780cfc79e01713ba9583102dd2ea82fc4c2c3e203841f3761
  1656e1ccd1b7f6e5df4ed790c067854b73f99f556cd3ec35a256b2b79b5f18db
  4dbcd2583102daa44b9179c2cff850625f8249e536bbbaa3e8d8d2381dccc612
  0e06f16847291199a6b1ef837650fdb6d003cfae920b5831034a7e5472342c50
  8a334e283cd7db6378fb266b01037209bef85481f57fdafd8432280b78526dbf
  02d69f9e7e6a7b0f310658301a410efe60766c174b4a8f4054d9c68b94381d72
  172409246f9dcc429a9421e60087d5bb1a32538bee3532be6b100c30075830e2
  c075df6052fc5466e475c9e47a7954a969319b14cb31545f4895c121f12a6893
  840136ac0293d6ef24a4d986a8aaa208583076e2325b3b1b91c075cac39838b5
  89f2df963e0261922745201f4690564ea694f8550b796f441f4e27357288a6ee
  21630958309fdd9c7586e5caea4bec00589e7c9c69d06ee8d8875e61144f7a11
  cb4e820a8e0804d3def875220280e8c802a09795fe0a5830d8ed702215be6dac
  ac925cfab5241aa9326cb82da1e4c8d7fce706d731150ba90b907882ab2e0d3a
  5ef1f6cdd232fefa0b5830ae319e6c5f2d943d3307af34919f624921273b8661
  7231960612df3886e2d5c3b53f09a2b97aba5342b4b0663f26657d0c583073c4
  ca0b6998564c4ee93008bba12b805f6adab8e46d06c6af15bab101e29fbfe351
  7bb7decb8788e67629f9d17051030d58300b48a8c0cb0ae7abeffc0590d41306
  efae441736ed447b25cb4545737b3b2500a00961ad005939216625863b9053a7
  740e885830b7c398999a7952c7bc2f56ecc371ef0fc834b183442f991e506685
  b7bf789d8bb765a27942e25394515ce97dbc4d9bf85830cc23010d4abf0a047a
  fed5404716edc61e3096f7979b18ce28703f44a58bb3acbb7d34963797654502
  d2fa065a6d41b85830608f22735090d5bc4c5008960d409643e95e2fbbac5573
  d38961045c80dc83fb8328e6c432e205bb41d3dd422d5f264f5830252c199782
  2af8fa9c298af2432236782d3e88bc9cad5659d3e502b76aa4760cf869da4456
  9590a0116eaa7267df9fd65830b087d2bc167da4874fca54a6e754c6d38cec53
  c7184749294e766585c75b84c2dc8fad07ae257ead95ffc06fe7a3df8858301e
  08a0d7e6180558408f46e440cda16bb5535e7e7294e7849ff12f8de3db43ff8b
  87271e51da1e84d917a7df10102a205830a4697a8d626a333693e5b318baf83d
  4e4c91c300271e53f819b02d2a3dae07319a61da49f48e65f6b4ab2bdb59677b
  39583043796cbaf6fcdcf91a986f1a97dbdf4bf32e68e955586bfd5be0f8cfb3
  72ad3d0abea6d3a640a0e2d313fa90b434be020f8882583081855f1def5035fa
  d8f540245351cfb24c16699f37390386854a8a096310f5e2b588d442d333fa0d
  5ff8403547506ea35830a4144478d893392a42c79609ff78ecd4c8ddcd9a265d
  62302c1d5fc5ad298e450085e8368c1654aaa6981a57b1fadb538258303d4980
  07b3ae70f022bee08accdb2122382d0876e0917392b843c4b31fd64373ff1df8
  6b6ddc8e08f8619bdc2028ba61583049a2bd5520a2367badc6e79aa55d87f820
  48168e151667e7e63338a0fccb2e43fac4c5c6f02bc0dc6a1797de0eec06e282
  58302aaf5eca3cbe45770cb6a7458a6fd047eec0e4dfa6720114e1fea30f7002
  5dfe04e6a8815a6ec715d75fe23cbc7dd27b58306c5e50a4d57fd541341b0f11
  91519d7ce13c8d3db24653d823b2a16a3e0166754be888119c27ed30b0b08110
  c9c0801d825830889d8de226dd46990e712659c4f9b4d4b4d5dd0446b584626d
  d44c8d1f7b398be545ad964ed4be32f00ac94b53982a3e5830ead4b239547b0a
  2214f49e19643d4da7c0d7993d18f4aac7f14486db5480a924fb2b8c3d3e2eff
  bd50d8e661f2a11b30825830f977b645937ec4436c8ef94a2c33d4855feb3515
  044ca44f366a904a6b6512137efd17e16b64a60aeddb35f007a03c625830eeae
  fe61aedec9d1b54453bcc37198bdd442690814c688f44b84674f729828a55cc1
  07dcda3bdb1589226fb506af2db4825830a6705c616a401f8489534e14f62964
  61f4d8393eb2f0e5312bad2c70ed4125151001db798653784c8733dc0125a590
  6e5830361e223c8309364fd60e8340138a38632de3eb7850ab7c644308338df5
  9564dd519a30176f266a532c53c4da81a89352825830697a98d2cbc64f2860bb
  7d5cf6e72bd155bd92eea8167a80683d8e6fa048f9ef8e05c16050d13ec8532d
  89ee05054b6058302051c11e84b7c1e321c4389b9a6e4f1d1453a05eddffb268
  c1b1d1c2443ad544b31692b6a765865e3677884bf4f3b73682583033ca622e29
  624b6387bfd4ea1f75ddd9e3bcc45e4a3ca02ee5e562f2d4e4457484c62373f0
  a998712bc579c48af21f7e58300414f19c59adf415baefe2f58b6e305e38d549
  c10c4bdf8d90934c3a69d8a5a06c1cfc7bf8bdee06bce4756ef324af81105830
  f9ebd4cbf2dac31ae9ad9ac33c931f7e6edd819382d5febe2d43b115d9de3acd
  38d75ad069644f9a4e0615f21c770e9511583078ae5f283679f873537cf5ed75
  34332181a5181226cfcfb4c4f9a10bbedec25a23b5a26454a43d8f9bf21e4c63
  18b3ce1258300000000000000000000000000000000000000000000000000000
  00000000000000000000000000000000000000000000

prerefund_cbor:
  a4015830d56c1ee7f0ca1e3e8e08b0150ca2693117ec9fa46561a2d63cbdfff5
  d30aa3ab8adb5542d6dc452630f224e8619dec13025830426faedde352ae3915
  c9a9d4a4c0573f956e6018d65ee23197594b12437425fa40ca8cc5ac1254adef
  8d17424395631903583000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000046045830000000
  0000000000000000000000000000000000000000000000000000000000000000
  00000000000000000000000000
~~~

## Refund

~~~
refund_cbor:
  a5015831030c7354b41acf1c0a1a2a48b8abf831218dae6f99012605c7646d41
  e67a7a3b87628a89ed92313ec9b0f3a224f979cccd02583044cc72ceb77e4824
  ef568678064c3a183b8621284405a706e789a6e7a22d64207e69fb0b8515ce8a
  b878ca7a07ebab00035830481b2c90e0753dd9c90909a7ef8e9fa78d63ce045e
  64f962ef1e433991fa040ae503ad0a81754c1e67262db0832bb3be0458300076
  ef18fab64d3e967c8435409a2c051f9658bc66fbf0d73bb94bbc23803daa3025
  5971a8dccbbd25a34727e1a931df055830000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0a
~~~

## Refund Token

~~~
refund_token_cbor:
  a6015831030c7354b41acf1c0a1a2a48b8abf831218dae6f99012605c7646d41
  e67a7a3b87628a89ed92313ec9b0f3a224f979cccd02583044cc72ceb77e4824
  ef568678064c3a183b8621284405a706e789a6e7a22d64207e69fb0b8515ce8a
  b878ca7a07ebab00035830426faedde352ae3915c9a9d4a4c0573f956e6018d6
  5ee23197594b12437425fa40ca8cc5ac1254adef8d174243956319045830d56c
  1ee7f0ca1e3e8e08b0150ca2693117ec9fa46561a2d63cbdfff5d30aa3ab8adb
  5542d6dc452630f224e8619dec13055830000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  5006583000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000

refund_token_credits:
  000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050

refund_token_nullifier:
  426faedde352ae3915c9a9d4a4c0573f956e6018d65ee23197594b12437425fa40ca8cc5ac1254adef8d174243956319

remaining_balance: 80
~~~
<!-- P384_TEST_VECTORS_END -->

## ACT-P521-BLAKE3 Test Vectors

<!-- P521_TEST_VECTORS_START -->
The following test vector was generated deterministically using a
ChaCha20 RNG seeded with the bytes `00 01 02 ... 1e 1f` and L=8.
The domain separator is `"ACT-v1:test:vectors:v0:2025-01-01"`, credit amount
c=100, spend amount s=30, partial return t=10, and ctx=0. Values labelled `*_cbor`
are the CBOR wire-format encodings (Section 4) of each protocol
message, displayed in hexadecimal.

Implementations SHOULD verify they can deserialize these CBOR
messages and that a full protocol run with the same deterministic
RNG produces identical output.

## Parameters

~~~
domain_separator: "ACT-v1:test:vectors:v0:2025-01-01"
L: 8
c: 100
s: 30
t: 10
ctx: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
~~~

## Key Generation

~~~
sk_cbor:
  a201584201befaead7d149884a0b3f7e38cff16702d3668b7e9fa1556d545ad8
  a06339c94e42d0802a4aa38a0327e8f401f047c799f9084e99f6af19385c65b4
  453f0121dcb0025843030142f404e66e481d1ecbb4de97fc07cb2898474c979b
  dec8858de8ceb4eb625107af489e37c8e9cb6809b62fea5332937966e1e25acc
  7e493f33e45d3d6b681aa0a4

pk_cbor:
  5843030142f404e66e481d1ecbb4de97fc07cb2898474c979bdec8858de8ceb4
  eb625107af489e37c8e9cb6809b62fea5332937966e1e25acc7e493f33e45d3d
  6b681aa0a4
~~~

## Issuance

~~~
preissuance_cbor:
  a201584200cd3d331035754fcd8e7b105925786510efb8bc1302a8f2dc08ac91
  c64d20738b3d31b30d77f921617430c70ff94d761880b95ca944610f83aceaa1
  10f630c3685502584201de9af6a86567a837119225e4983962a9b61ae65faa00
  9f596b09d9605816535474c51c196779fa2f8cd1f69e887bd51b9baaf4f96a40
  cbe7513dc7286f34da7847

issuance_request_cbor:
  a401584303005ad4ec8051a905bec5442a1682ba5d4a6e08ab9ee6cd0bcb4e49
  43f42b740f59b2f0b8b5a6bc8cd5848bac08399884cde90fbc658f92aa208920
  fc31981b4e663302584200d29989f20e0b320f2d80abaf5c200c0538ce4a3c27
  3b2f2ab44241c633cd192cf0342fe30ff0f2838ed2780bfcd8c0329956713c42
  9137c939922ef14a0c81b7f003584201aef9949b8092d5f481976029921efcc6
  a27509ee0a78f2188fa8d482d4d54b6e92ac48af9094ff1c3e86f5589607862f
  ffffa0c046a070a7ca61236ac9939c750c04584201aff5cf27806ca4a725e50b
  b36af028251c9c1997db13a6cd0c163b8b44c165a9000fe4c3060147cb2a5ac1
  8bbbf19556ca372019f1c343d5e7f5e02c01d2484e56

issuance_response_cbor:
  a60158430200dc5c6fcfd51a26f0885b14bd520a7ce4eaa5c42372c758d788b1
  57034a9d73601c25b1f2aabb06da6fdbbf7577a104e6d8a3027b644be4b79b4f
  efe30494c2a5940258420150f60a980d35d7e9b45078236789ba8ff32550304b
  c04e33df13e407c3114b20f3f1b8ea6c623e600b336d17f556fdb9c9a2f828f5
  77352961dd665abaae26354703584201b4418a119ef7ff0be33a0d00f436078c
  ea60caee7abc0b68ef4b5601ef1e89bd4a057903a2d98fca306aeb120c92216d
  78934978cc0c3a05e8bbfab9465759282a045842019dc4c5f7342bae111987f6
  8481d361af19cbc2114c25a0f1ce109656bcaa0409484a05b13abded3487f3f4
  ee9c3535927c95b4b291dda4693ed4c4522a31c2b32805584200000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000640658420000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000

credit_token_cbor:
  a60158430200dc5c6fcfd51a26f0885b14bd520a7ce4eaa5c42372c758d788b1
  57034a9d73601c25b1f2aabb06da6fdbbf7577a104e6d8a3027b644be4b79b4f
  efe30494c2a5940258420150f60a980d35d7e9b45078236789ba8ff32550304b
  c04e33df13e407c3114b20f3f1b8ea6c623e600b336d17f556fdb9c9a2f828f5
  77352961dd665abaae26354703584201de9af6a86567a837119225e4983962a9
  b61ae65faa009f596b09d9605816535474c51c196779fa2f8cd1f69e887bd51b
  9baaf4f96a40cbe7513dc7286f34da784704584200cd3d331035754fcd8e7b10
  5925786510efb8bc1302a8f2dc08ac91c64d20738b3d31b30d77f921617430c7
  0ff94d761880b95ca944610f83aceaa110f630c3685505584200000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000640658420000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
~~~

## Spending

~~~
nullifier:
  01de9af6a86567a837119225e4983962a9b61ae65faa009f596b09d9605816535474c51c196779fa2f8cd1f69e887bd51b9baaf4f96a40cbe7513dc7286f34da7847

context:
  000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

charge:
  00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e

spend_proof_cbor:
  b201584201de9af6a86567a837119225e4983962a9b61ae65faa009f596b09d9
  605816535474c51c196779fa2f8cd1f69e887bd51b9baaf4f96a40cbe7513dc7
  286f34da78470258420000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  000000000000000000001e0358430200b3c697109ce6aa66f1e65d6aad841650
  17e2e2cfbd2a7178ec4a3c8410f8e132495100e9a2e2b38618f85e36ecfb9d18
  e1200282dd52c958b46630be5ba808343e045843030006b484acdbbf867c770c
  7cd28726163f0d3013881e1e18811261b4e1046e3dd84d7851c2753df1671357
  7318dc2a35b4be55526dbb84d446ca21a0bc5fec54e9e90588584303018c12f6
  b9231bd8cc808a1d3b9621afc283c981c371c2be8c358bbdc32685bb4afffb48
  125bc1592458c5af8b4725799f5e85c6cce53434b79fcb9c983c03d8640e5843
  02010606b32b004402d710b07ce7e2c8cedfe10d5420d79a12dc2174b7e96695
  784a8c7ef343e7c98a64decf25eb0c464287b2d741e80caacf19e99edaf73dc4
  9e9eaf584302009b2e147004f882783d3bfe9033c8b098a3ad44664f182391b8
  23a6697757ac8180bd0adc17175f91d3f5332c5b6155fa14b9596b00ef41a563
  1132d77ad670b8095843020009f8bdaba82adc7826dacc478cf9992a1757be05
  a3f9169d847d1fcdb8514c620c26a17b4c1c03b6cb3027be8b8efceeec5a5b98
  6682bc52bd20e3148b8940a7a8584302007f8951f501dbc1dfed736bd0f9414f
  0c07b69af1fc13bba648b091946a4230b62fdbaa542a08b349930c7361b536b4
  3881fd6a1264888bcff817232e47345eb67f5843020096012242dcd7e3d77d65
  37ead2b0aa42442fb3e265845a9b02d570c344b0c166031fec2e0d45d1453238
  cf20fb59b038c1c0769610000595cfd79863a5f3d6a87d5843020054b38e6944
  1762303e638e54289a4aaf93658730807ffef08ad96be10bc1ba13c6ae3fc80c
  b50eac7fcd28ee39a7c06c0800f2f6cad517d15487a374685d26f42e58430200
  01827d9c19161d8ec81d3f99c31a415f7d62eca0a42af542104eed2ac4e40f3b
  2f0de7181bd592ce3a74a92cdcf8767636e8eff9ba6590dd7bed2dc1a22837f1
  8b0658420150f9e2c7a8b930280c3ef278419abf3b3140e7ef73b6c63fc8b0b7
  ed9c18446c7b578a7b86c473c2de82967d2a65af83d8fc0899005388119ad7b5
  a956a3230251075842016debbb51df327aabdd525badad9be11b2c318ea08c39
  9d43ee81e9e1bd9a17968c13ff8fb5b8aa6c7a53c3009476f611c1350c951321
  0816055541edae12f263fd0858420116b37f5a266254650c74c301ad166966b6
  65d0d7356959659f875f5f2d90cde8cb3788349cd39f1d85d0ce91d351db6744
  2f3ec0d9d84957be74d42662fb8d17be095842000263e21d4ba8f96ef11cdefc
  491658f47a526e40c6d56d21ce2d1dad84b898a4f2a0270afc96ae38da65e862
  b83a3b869f91acdf72bc11c45b0b335c6c130bc4890a584201cd225fa754e231
  965597825557839f0ac6b233eed87eb0b0892bd069ee8045451ef10e89fe7240
  8c7e0cf4e472367b0b5ae68aac2642e53b49db7bc0fd5d90ce150b584201744f
  3d64eb82224f7cadbd4b2aa4d6c8f516e5cee162329e31d687db06ec6dc3fcb6
  809082697c058a88fee599a8162915844bcdc43d57de5fd02642c00a94a43f0c
  584200f4f46cb0e6ba946bd5498f53942cff65baab07abfb7f743f82bad0fcdb
  e39c066635d3bfb0ce73d5c2294d13b35a4cdd6ef016f9d0a6d40f21e04cc3b0
  193fc24f0d584200332687fe0f448f005589e0072b4a910e81fb5a80baf6d8b9
  2384a3400d1db56528bfb84e5dbfc8e1315d82f7240eec08d8ad13c361b1ae19
  2cf1559d7042e07ccc0e88584200c3fd9e5ae7a1a8331123b22f10891ea1d0bd
  dbab795e43a440e2e8a3b045949c3d04a89c49237a157ea4f8d7c69b333ce176
  caa15a636eb82609026a2f4dbbb348584201b556ba9acb1021a6b6f6f35bc502
  03cab9b27f20a4ca8caaf655ca17eaf91049a82139d506ec044e85cc78f09ef5
  4ab3758b02578070527befbd4dbf03e22214285842019d57f6d23450219bf6a5
  1c6480adf62bf2cc9129a09fc764383a04e0edfe69b814a947f7ca2b337d79cb
  39011f7960ea3cae7d6fe75d3400e863cc12886233fa985842006008825a5f50
  3d067846930719b90d2058d0872f6160cb0ff0950b4d33429ef624ab8ea949cc
  8882f2a5b0b41f6115c45ace1b1b25d2dae52397cf1607464dd538584200df37
  974d11b012d42dcb491568f373b604cbdc046ad9db2bdc8d3702d026ddda7e82
  b1aa4d934c3134cbfb46d7edd4e0bb56a004be9fe095e4d383544a4826ee8e58
  42011db367a3dad89ddd099da6544ebd78745ba3e6dad90b2eef0a97fd23f5d8
  6f9b3d35c7a1cdf142d39c89ec5629d999f36b7ef8b13606cd72e0d118b5bb28
  e3c2f5584201d370bd0faea3faa51d29ce50ec8734580f400a3bc877df21b2f0
  3f35c0dcfeea1b471da83d94c81e62acfaf1155ef22c64d1807ea317e068aec3
  075c81dd8e94c3584200e2147a4bbf4177aef5eaeb1913facbf5f365f15380b3
  bd1107b7c2f0ccb54974a3067e1ddd590946b2e71ac3a1ceaabc0d6a2cdf45b9
  5c04b9ac4c8a780858190d0f8882584201c794f31e17e989408ce3fea4409900
  bcc57bc1205969ce840a526fa2f7d0bbfc9cb6212868df5337ee73806957d0c1
  e2619328bcab0b36b2936716abaec31ef198584200e8afe0efe99f08f6580cb1
  e67807ecb57281bfcf0a53240859c95e1dc09c7cc2df155fff84ba110056bdf7
  74006fca32fad8da9d1b79017dda2a7c325eebb24da8825842007af29d6c8f68
  dce0d30e47d9447ddafc6f00793136262d55568137b8caabd507653cbfc9cfdb
  7fc33380bc4a4367f3b5e974cf66a531f2d21cb8dbb1b42004bbb4584201f7c0
  c7b4189892b1c65c7667070f9d5e0290031746357e0ef197be21adeabd6ebc96
  9355525e6ae1d944a4f26d95c5a13dde536dc9adaad6a694ed30385a57273f82
  584200436e9460eb1672ddd522d3751c97a03c94086dfa428e20d5aa973c5bad
  49dd36542108192b506352063cc36f3b8e696b6a03b789aac5f0cc6050bd60a6
  04382fdb584201121bdfe1e4e1be3b7cfa6a6bd97e68a90ac5f9c648b98439d2
  a0ca296ed2d5f2dfc1c914af3e5e809ea59ffddc2aff5bae470a9defbe9fac1d
  619355d20851345f825842009a54d3073c75b14442d38dc5a61b81f455646fe1
  9f6864f5257074c858699e4977fc06b6518cd113401394e69ba49404060f102e
  9832dac1f66e8d09bdeb6c540158420016a9f19190f7f59190c90833762c0707
  39b71493b8b91e690b1366398ff5f1cb65ee210fb9564aad01387f48e4ca8cbf
  a28ee9d65735d2361c5b7493b34102c69382584200a0268d0d1c98270b30271f
  b453451c53875cb4a980c88a6cfc8992181a6eff3ef2cf1839683eddeaca1a4c
  2be7a1f09c7d8cf7d3be4591ad9c21e398ec28d331d7584200637b18682031f5
  e1c5aac8c0034a950529b0374e02f48a85721f4a1df3a08f38fa0cb898383d92
  fb0ab99350de725a2920efb5646886110f9cd0c5a42ce54394cb82584201dd73
  fa0accd074d0ca5f730a40ded2760aa64df0509614ee872127d9b72e1c500b75
  09011de6c2f61b0b6bfd8a4a1fcaac85d5e4eb95635f80acf82cb608758a1b58
  4200a0db7cc1853c4130044d7dd3214b23bbd194fee3a0ccd8d261ac3cdd61e0
  4a9562a1b31a8955a4842d340227786c90c46859938f0f6b3c581ec9b99cbced
  7a66e2825842007fe62fe3da03b0a078e957997ae06fddda7c1dd9452ea8ef3c
  49672c673f1698097dab24532d1c9edb5cbf182c8b7f31dfe0398b4e6b6f17a9
  1925b608f62d4d74584201bd184bfcae930cb155f9c4e424783129cdca6480f0
  91b3e0b8c7b471477b92ec31da443a64cd6910d649458133427bb1e8766bdea2
  e22ede6747e0cecefa2bb91a8258420035bb2850b2359f7e12391eefc3860e8a
  fad0e5c41f58bde263bd8eb4dac706ee3e7712acb618bdf07e6eb01842a1d029
  d9e5e6369e5c276c23a3415ff14f7773fb584200ca56271a0aa5ffdbd60cdc06
  00589d9ca82b98250fdcf1bffb0e7b750374f04f7236de6103088fa853e32ec5
  90e3b5ea11290eae2de64c9fde2d95d055a236e96f10584200817e368f0c2519
  92c021916d0a66918ca2dc8f0be73a7569a7fa1d353e38733603f7e1071e1f69
  b16639560ab88df8017ae58b6bff8873a37074b22ba43efaabff11584201f07d
  5f47d37111edcbabc14c365df1cf0c52a3720f6c77003725373a80aba8869d61
  7ac501d43087d17b953d675f1a9f8a6dca0e8a80f7d2f31323bcd0d5ac586212
  5842000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  00000000

prerefund_cbor:
  a4015842005a1158f8cab152e1dc4ec0a3dbccb973f4b36184b0986e241e84f8
  3806cd77d64dc6552ca88e6c58f824144405cea9ffa332fced6ed16a8ba90899
  b86e550b03f102584200b5c5ff5d82cd8f2a78e8c6ab81c32c3899727eb25cf7
  ef9d8d5a82ab6352e5657539d30b31c78285fac8f26e4c7e3a23ad89e2b2ce80
  910632e36544cb58092e1b035842000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000004604584200000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  000000000000000000000000000000000000000000
~~~

## Refund

~~~
refund_cbor:
  a50158430300984f1ff8b3de97475468f543054ff3fdd84b27231363ae78df42
  b54c0bf7fa4c1085ba31cf7deb6809b8ff905dbc982d4495875f219a3d0be84e
  9ac55111761f3402584201e8c72e3cd4c95faecf4cef3b1a34b16a55cda50a16
  a0d4fc279a93837db43abf12f2632ea30d37a2d2e75aa3f7d72d66fb0b27f3d5
  d2a52a6d1153ada3cb133fcf03584200f9d3d070f8c4ea9aa912e44026c34b7f
  9c0ec05c78527e554c229bd10740d9944712747eb31d0b2f2eaa846f06dd95ae
  74f8938fe858be3af1ee52d3a3ba01fdb6045842003390a0ba686db6ab46d3ad
  ccc534f59a82b02364a649305619aeea58b50c8b536ec4e5c30e65704ec67b13
  2157cddefd54492bfb8949d1bc4cdf2a1d93d7120e4d05584200000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000000000a
~~~

## Refund Token

~~~
refund_token_cbor:
  a60158430300984f1ff8b3de97475468f543054ff3fdd84b27231363ae78df42
  b54c0bf7fa4c1085ba31cf7deb6809b8ff905dbc982d4495875f219a3d0be84e
  9ac55111761f3402584201e8c72e3cd4c95faecf4cef3b1a34b16a55cda50a16
  a0d4fc279a93837db43abf12f2632ea30d37a2d2e75aa3f7d72d66fb0b27f3d5
  d2a52a6d1153ada3cb133fcf03584200b5c5ff5d82cd8f2a78e8c6ab81c32c38
  99727eb25cf7ef9d8d5a82ab6352e5657539d30b31c78285fac8f26e4c7e3a23
  ad89e2b2ce80910632e36544cb58092e1b045842005a1158f8cab152e1dc4ec0
  a3dbccb973f4b36184b0986e241e84f83806cd77d64dc6552ca88e6c58f82414
  4405cea9ffa332fced6ed16a8ba90899b86e550b03f105584200000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000500658420000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000

refund_token_credits:
  000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050

refund_token_nullifier:
  00b5c5ff5d82cd8f2a78e8c6ab81c32c3899727eb25cf7ef9d8d5a82ab6352e5657539d30b31c78285fac8f26e4c7e3a23ad89e2b2ce80910632e36544cb58092e1b

remaining_balance: 80
~~~
<!-- P521_TEST_VECTORS_END -->

# Implementation Status

This section records the status of known implementations of the protocol
defined by this specification at the time of posting of this Internet-Draft,
and is based on a proposal described in RFC 7942.

## anonymous-credit-tokens

Organization: Google

Description: Reference implementation in Rust

Maturity: Beta

Coverage: Complete protocol implementation

License: Apache 2.0

Contact: sgschlesinger@gmail.com

URL: https://github.com/SamuelSchlesinger/anonymous-credit-tokens

# Terminology Glossary

This glossary provides quick definitions of key terms used throughout this document:

**ACT (Anonymous Credit Tokens)**: The privacy-preserving authentication protocol specified in this document.

**Blind Signature**: A cryptographic signature where the signer signs a message without seeing its content.

**Refund**: The refund issued for the remaining balance after a partial spend.

**Credit**: A numerical unit of authorization that can be spent by clients.

**Domain Separator**: A unique string used to ensure cryptographic isolation between different deployments.

**Element**: A point in the ciphersuite's prime-order elliptic curve group (Ristretto255, P-256, secp256k1, P-384, or P-521).

**Issuer**: The entity that creates and signs credit tokens.

**Nullifier**: A unique value revealed during spending that prevents double-spending of the same token.

**Partial Spending**: The ability to spend less than the full value of a token and receive change.

**Scalar**: An integer modulo the group order q, used in cryptographic operations.

**Sigma Protocol**: An interactive zero-knowledge proof protocol following a commit-challenge-response pattern.

**Token**: A cryptographic credential containing a BBS signature and associated data (A, e, k, r, c, ctx).

**Unlinkability**: The property that transactions cannot be correlated with each other or with token issuance.

# Acknowledgments

The authors would like to thank the Crypto Forum Research Group for their
valuable feedback and suggestions. Special thanks to the contributors who
provided implementation guidance and security analysis.

This work builds upon the foundational research in anonymous credentials and
zero-knowledge proofs by numerous researchers in the cryptographic community,
particularly the work on BBS signatures by Boneh, Boyen, and Shacham, and
keyed-verification anonymous credentials by Chase, Meiklejohn, and Zaverucha.
