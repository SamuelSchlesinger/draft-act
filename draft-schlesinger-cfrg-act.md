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
  RFC8174:
  RFC8949:
  RFC9380:
  RFC9496:
  BLAKE3:
    title: "BLAKE3: One Function, Fast Everywhere"
    target: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
    date: 2020-01-09
  BLS12-381:
    title: "BLS12-381: Design and Implementation"
    target: https://electriccoin.co/blog/new-snark-curve/
    date: 2017-03-11

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
anonymous credentials and BBS-style signatures, the protocol allows
issuers to grant tokens containing credits that clients can later
spend anonymously.

Two ciphersuites are defined. ACT-Ristretto255-BLAKE3 uses
Ristretto255 with privately verifiable BBS-style signatures, where
only the issuer can verify spend proofs. ACT-BLS12381-G1-BLAKE3 uses
BLS12-381 pairings, enabling publicly verifiable spend proofs that
anyone with the issuer's public key can verify.

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
without client tracking. Built on anonymous credentials {{KVAC}} and
BBS-style signatures {{BBS}}, the protocol allows services to issue,
track, and spend credits while maintaining client privacy.

The protocol is defined in terms of two ciphersuites:

- **ACT-Ristretto255-BLAKE3**: Uses Ristretto255 {{RFC9496}} with
  keyed-verification (privately verifiable) BBS-style signatures. Only
  the issuer, who holds the secret key, can verify spend proofs.

- **ACT-BLS12381-G1-BLAKE3**: Uses BLS12-381 {{BLS12-381}} pairings
  with publicly verifiable BBS-style signatures. Anyone with the
  issuer's public key can verify spend proofs, enabling third-party
  verification without revealing the issuer's secret key.

Both ciphersuites share the same protocol structure, range proof
machinery, and Fiat-Shamir transcript framework. They differ in the
underlying group, key generation, signature verification method, and
encoding sizes.

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

- **Third-Party Auditing** (ACT-BLS12381-G1-BLAKE3 only): With
  publicly verifiable spend proofs, external auditors or relay
  services can verify that spend proofs are valid without access to
  the issuer's secret key.

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

In the publicly verifiable ciphersuite (ACT-BLS12381-G1-BLAKE3),
spend proof verification can additionally be performed by any third
party holding the issuer's public key, without requiring the issuer's
secret key.

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
  proofs of possession. The ACT-Ristretto255-BLAKE3 ciphersuite uses a
  privately verifiable variant that avoids pairings. The ACT-BLS12381-G1-BLAKE3
  ciphersuite uses the standard pairing-based variant, enabling public
  verification.

- **Sigma Protocols** {{ORRU-SIGMA}}: The zero-knowledge proof framework used
  for spending proofs.

- **Fiat-Shamir Transform** {{ORRU-FS}}: The technique to make the interactive
  proofs non-interactive.

The protocol can be viewed as a specialized instantiation of anonymous
credentials {{KVAC}} optimized for numerical values and partial
spending.

# Ciphersuites

This document defines two ciphersuites that instantiate the ACT
protocol. Both share the same protocol structure but differ in the
underlying group operations and verification mechanisms.

## ACT-Ristretto255-BLAKE3 (Private Verification) {#ciphersuite-ristretto}

~~~
Ciphersuite: ACT-Ristretto255-BLAKE3
  - Group: Ristretto255 (RFC 9496)
  - Group element encoding: 32 bytes (compressed Ristretto point)
  - Scalar encoding: 32 bytes (little-endian)
  - Group order q: 2^252 + 27742317777372353535851937790883648493
  - Generator: G (standard Ristretto255 generator)
  - Hash-to-group: HashToRistretto255 (Section 4.4.1)
  - Public key: Element in same group (W = G * x)
  - Signature verification: DLEQ proof
  - Protocol version: "curve25519-ristretto anonymous-credits v1.0"
  - Domain separator prefix: "ACT-v1:"
  - Spend proof verifiability: Issuer only (requires secret key)
~~~

In this ciphersuite, issuance and refund responses include DLEQ
(Discrete Log Equality) proofs that allow the client to verify
correct signature computation. Spend proofs can only be verified by
the issuer using the secret key.

## ACT-BLS12381-G1-BLAKE3 (Public Verification) {#ciphersuite-bls}

~~~
Ciphersuite: ACT-BLS12381-G1-BLAKE3
  - Group G1: BLS12-381 G1 (48-byte compressed elements)
  - Group G2: BLS12-381 G2 (96-byte compressed, for public key only)
  - Scalar encoding: 32 bytes (little-endian)
  - Group order q: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  - Generator G1_gen: Standard BLS12-381 G1 generator
  - Generator G2_gen: Standard BLS12-381 G2 generator
  - Hash-to-group: HashToG1 (Section 4.4.2)
  - Public key: G2 element (W = G2_gen * x)
  - Signature verification: Pairing check
  - Protocol version: "bls12-381 anonymous-credits-public v1.0"
  - Domain separator prefix: "ACT-public-v1:"
  - Spend proof verifiability: Anyone with public key
~~~

In this ciphersuite, the issuer's public key is a G2 element, while
all token computations use G1. Signature verification uses the
BLS12-381 pairing `e: G1 x G2 -> GT`. Because verification requires
only the public key (not the secret key), spend proofs can be
verified by any third party. Issuance and refund responses omit DLEQ
proofs since the client verifies via pairing checks instead.

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

- `e(P, Q)`: Bilinear pairing of G1 element P and G2 element Q
  (ACT-BLS12381-G1-BLAKE3 only)

## Data Types

The protocol uses the following data types:

- **Scalar**: An integer modulo the group order q
- **G1Element**: An element of the primary group (Ristretto255 or BLS12-381 G1)
- **G2Element**: An element of BLS12-381 G2 (ACT-BLS12381-G1-BLAKE3 only)
- **ByteString**: A sequence of bytes

In the ACT-Ristretto255-BLAKE3 ciphersuite, "Element" refers to a
Ristretto255 group element. In the ACT-BLS12381-G1-BLAKE3 ciphersuite,
token computations use G1 elements, and the public key is a G2 element.

## Cryptographic Parameters

Both ciphersuites use prime-order groups. The key parameters are:

- **q**: The prime order of the group
- **G**: The standard generator (Ristretto255 generator or BLS12-381 G1 generator)
- **L**: The bit length for credit values

For ACT-BLS12381-G1-BLAKE3, additionally:

- **G2_gen**: The standard generator of BLS12-381 G2

# Protocol Specification

## System Parameters

The protocol requires the following system parameters:

~~~
Parameters:
  - G: Generator of the primary group
  - H1, H2, H3, H4: Additional generators for commitments (in G1)
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
    3. H1 = HashToGroup(domain_separator, seed, counter++)
    4. H2 = HashToGroup(domain_separator, seed, counter++)
    5. H3 = HashToGroup(domain_separator, seed, counter++)
    6. H4 = HashToGroup(domain_separator, seed, counter++)
    7. return (H1, H2, H3, H4)
~~~

Where `HashToGroup` is `HashToRistretto255` (Section 4.4.1) for
ACT-Ristretto255-BLAKE3, or `HashToG1` (Section 4.4.2) for
ACT-BLS12381-G1-BLAKE3.

The domain_separator MUST be unique for each deployment to ensure
cryptographic isolation between different services. The domain separator SHOULD
follow this structured format:

~~~
For ACT-Ristretto255-BLAKE3:
  domain_separator = "ACT-v1:" || organization || ":" || service
                     || ":" || deployment_id || ":" || version

For ACT-BLS12381-G1-BLAKE3:
  domain_separator = "ACT-public-v1:" || organization || ":" || service
                     || ":" || deployment_id || ":" || version
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
1. Protocol identification through the prefix (including ciphersuite distinction)
2. Organizational namespace isolation
3. Service-level separation within organizations
4. Environment isolation (production vs staging)
5. Version tracking for parameter updates

Using generic or unstructured domain separators creates security risks through
parameter collision and MUST NOT be used. When parameters need to be updated
(e.g., for security reasons or protocol upgrades), a new version date MUST be
used, creating entirely new parameters.

## Key Generation

### ACT-Ristretto255-BLAKE3

The issuer generates a key pair where the public key is in the same group:

~~~
KeyGen():
  Input: None
  Output:
    - sk: Private key (Scalar)
    - pk: Public key (G1Element)

  Steps:
    1. x <- Zq
    2. W = G * x
    3. sk = x
    4. pk = W
    5. return (sk, pk)
~~~

### ACT-BLS12381-G1-BLAKE3

The issuer generates a key pair where the public key is a G2 element:

~~~
KeyGen():
  Input: None
  Output:
    - sk: Private key (Scalar)
    - pk: Public key (G2Element)

  Steps:
    1. x <- Zq
    2. W = G2_gen * x
    3. sk = x
    4. pk = W
    5. return (sk, pk)
~~~

## Token Issuance

The issuance protocol is an interactive protocol between a client and the
issuer.

### Client: Issuance Request

This step is identical for both ciphersuites:

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

The issuer verifies the client's request and creates a BBS+ signature. The
signature computation is shared between ciphersuites, but the response
differs in whether a DLEQ proof is included.

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
    9. // Create BBS+ signature on (c, ctx, k, r)
    10. e <- Zq
    11. A = (G + H1 * c + H4 * ctx + K) * (1/(e + sk))  // K = H2 * k + H3 * r
~~~

The remaining steps differ by ciphersuite:

**ACT-Ristretto255-BLAKE3** (with DLEQ proof):

~~~
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

**ACT-BLS12381-G1-BLAKE3** (no DLEQ proof needed):

~~~
    12. response = (A, e, c, ctx)
    13. return response
~~~

### Client: Token Verification

The client verifies the issuer's response and constructs a credit token.
The verification method differs by ciphersuite.

**ACT-Ristretto255-BLAKE3** (DLEQ proof verification):

~~~
VerifyIssuance(pk, request, response, state):
  Input:
    - pk: Issuer's public key (G1Element)
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

**ACT-BLS12381-G1-BLAKE3** (pairing check verification):

~~~
VerifyIssuance(pk, request, response, state):
  Input:
    - pk: Issuer's public key (G2Element)
    - request: The issuance request sent
    - response: Issuer's response
    - state: Client state from request generation
  Output:
    - token: Credit token
  Exceptions:
    - InvalidIssuanceResponseProof, raised when the pairing check fails

  Steps:
    1. Parse request as (K, gamma, k_bar, r_bar)
    2. Parse response as (A, e, c, ctx)
    3. Parse state as (k, r)
    4. if A == Identity:
    5.     raise InvalidIssuanceResponseProof
    6. X_A = G + H1 * c + H4 * ctx + K
    7. // Pairing check: e(A, pk) == e(X_A - e*A, G2_gen)
    8. if e(A, pk) != e(X_A - A * e, G2_gen):
    9.     raise InvalidIssuanceResponseProof
    10. token = (A, e, k, r, c, ctx)
    11. return token
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

The following algorithm is shared between both ciphersuites, with
ciphersuite-specific additions noted inline for ACT-BLS12381-G1-BLAKE3.

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

    // [ACT-BLS12381-G1-BLAKE3 only] Compute a_bar for public verification:
    13a. a_bar = B_bar * r2 - A' * e

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
    25. (i[0], ..., i[L-1]) = BitDecompose(m)  // See Section 4.5

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
    // [ACT-BLS12381-G1-BLAKE3 only]:
    78a. AddToTranscript(transcript, a_bar)
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

    // Construct proof
    // For ACT-Ristretto255-BLAKE3:
    123. proof = (k, s, ctx, A', B_bar, Com, gamma, e_bar,
    124.          r2_bar, r3_bar, c_bar, r_bar,
    125.          w00, w01, gamma0_final, z_final,
    126.          k_bar, s_bar)
    // For ACT-BLS12381-G1-BLAKE3 (includes a_bar):
    123'. proof = (k, s, ctx, A', B_bar, a_bar, Com, gamma, e_bar,
    124'.          r2_bar, r3_bar, c_bar, r_bar,
    125'.          w00, w01, gamma0_final, z_final,
    126'.          k_bar, s_bar)

    127. state = (k*, r*, m, ctx)
    128. return (proof, state)
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
    5. // Verify the proof (see Section 3.5.5 or 3.5.6)
    6. if not VerifySpendProof(sk_or_pk, proof):
    7.     raise InvalidSpendProof
    8. // Record nullifier
    9. used_nullifiers.add(k)
    10. // Issue refund for remaining balance
    11. K' = Sum(Com[j] * 2^j for j in [L])
    12. refund = IssueRefund(sk, K', proof.ctx, proof.s, t)
    13. return refund
~~~

Note: In ACT-Ristretto255-BLAKE3, `VerifySpendProof` takes `sk` (the
secret key). In ACT-BLS12381-G1-BLAKE3, the issuer's `VerifyAndRefund`
still uses `sk` internally (for issuing the refund), but the spend
proof verification itself can use either `sk` or `pk`.

### Refund Issuance {#refund-issuance}

After verifying a spend proof, the issuer creates a refund token for the
remaining balance. The issuer may optionally return t credits (where
0 <= t <= s) back to the client via a partial credit return. This enables
pre-authorization patterns where the client holds s credits but only t
are returned unused. The resulting token will have c - s + t credits.
Use t = 0 to consume the full spend amount.

The BBS+ signature computation is shared between ciphersuites:

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

    6. // Create new BBS+ signature on remaining balance + partial return
    7. e* <- Zq
    8. X_A* = G + K' + H1 * t + H4 * ctx
    9. A* = X_A* * (1/(e* + sk))
~~~

The remaining steps differ by ciphersuite:

**ACT-Ristretto255-BLAKE3** (with DLEQ proof):

~~~
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

**ACT-BLS12381-G1-BLAKE3** (no DLEQ proof needed):

~~~
    10. refund = (A*, e*, t)
    11. return refund
~~~

### Client: Refund Token Construction

The client verifies the refund and constructs a new credit token.

**ACT-Ristretto255-BLAKE3** (DLEQ proof verification):

~~~
ConstructRefundToken(pk, spend_proof, refund, state):
  Input:
    - pk: Issuer's public key (G1Element)
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

**ACT-BLS12381-G1-BLAKE3** (pairing check verification):

~~~
ConstructRefundToken(pk, spend_proof, refund, state):
  Input:
    - pk: Issuer's public key (G2Element)
    - spend_proof: The spend proof sent to issuer
    - refund: Issuer's refund response
    - state: Client state (k*, r*, m, ctx)
  Output:
    - token: New credit token or INVALID
  Exceptions:
    - InvalidRefundProof: When the pairing check fails

  Steps:
    1. Parse refund as (A*, e*, t)
    2. Parse state as (k*, r*, m, ctx)

    3. if A* == Identity:
    4.     raise InvalidRefundProof

    5. // Reconstruct commitment with partial return
    6. K' = Sum(spend_proof.Com[j] * 2^j for j in [L])
    7. X_A* = G + K' + H1 * t + H4 * ctx

    8. // Pairing check: e(A*, pk) == e(X_A* - e* * A*, G2_gen)
    9. if e(A*, pk) != e(X_A* - A* * e*, G2_gen):
    10.     raise InvalidRefundProof

    11. // Construct new token with remaining balance + partial return
    12. token = (A*, e*, k*, r*, m + t, ctx)
    13. return token
~~~

### Spend Proof Verification: ACT-Ristretto255-BLAKE3 {#spend-verification-private}

The issuer verifies a spend proof using the secret key:

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

    5. // Compute issuer's view of signature using secret key
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

### Spend Proof Verification: ACT-BLS12381-G1-BLAKE3 {#spend-verification-public}

In the publicly verifiable ciphersuite, spend proof verification
requires only the issuer's public key. This enables any third party
to verify spend proofs.

~~~
VerifySpendProof(pk, proof):
  Input:
    - pk: Issuer's public key (G2Element)
    - proof: Spend proof from client
  Output:
    - valid: Boolean indicating if proof is valid
  Exceptions:
    - IdentityPointError: raised when A' is the identity
    - InvalidClientSpendProof: raised when the verification fails

  Steps:
    1. Parse proof as (k, s, ctx, A', B_bar, a_bar, Com, gamma, e_bar,
                      r2_bar, r3_bar, c_bar, r_bar, w00, w01,
                      gamma0, z, k_bar, s_bar)

    2. // Check A' is not identity
    3. if A' == Identity:
    4.     raise IdentityPointError

    5. // Pairing check: e(A', pk) == e(a_bar, G2_gen)
    6. if e(A', pk) != e(a_bar, G2_gen):
    7.     raise InvalidClientSpendProof

    8. H1_prime = G + H2 * k + H4 * ctx

    9. // Verify sigma protocol (same as private, but using provided a_bar)
    10. A1 = A' * e_bar + B_bar * r2_bar - a_bar * gamma
    11. A2 = B_bar * r3_bar + H1 * c_bar + H3 * r_bar - H1_prime * gamma

    12. // Range proof verification (identical to private variant)
    13. gamma1 = array[L]
    14. C = array[L][2]
    15. C' = array[L][2]

    16. gamma1[0] = gamma - gamma0[0]
    17. C[0][0] = Com[0]
    18. C[0][1] = Com[0] - H1
    19. C'[0][0] = H2 * w00 + H3 * z[0][0] - C[0][0] * gamma0[0]
    20. C'[0][1] = H2 * w01 + H3 * z[0][1] - C[0][1] * gamma1[0]

    21. For j = 1 to L-1:
    22.     gamma1[j] = gamma - gamma0[j]
    23.     C[j][0] = Com[j]
    24.     C[j][1] = Com[j] - H1
    25.     C'[j][0] = H3 * z[j][0] - C[j][0] * gamma0[j]
    26.     C'[j][1] = H3 * z[j][1] - C[j][1] * gamma1[j]

    27. K' = Sum(Com[j] * 2^j for j in [L])
    28. Com_total = H1 * s + K'
    29. C_final = H1 * (-c_bar) + H2 * k_bar + H3 * s_bar - Com_total * gamma

    30. // Recompute challenge using transcript
    31. transcript = CreateTranscript("spend")
    32. AddToTranscript(transcript, k)
    33. AddToTranscript(transcript, ctx)
    34. AddToTranscript(transcript, A')
    35. AddToTranscript(transcript, B_bar)
    36. AddToTranscript(transcript, a_bar)
    37. AddToTranscript(transcript, A1)
    38. AddToTranscript(transcript, A2)
    39. For j = 0 to L-1:
    40.     AddToTranscript(transcript, Com[j])
    41. For j = 0 to L-1:
    42.     AddToTranscript(transcript, C'[j][0])
    43.     AddToTranscript(transcript, C'[j][1])
    44. AddToTranscript(transcript, C_final)
    45. gamma_check = GetChallenge(transcript)

    46. if gamma != gamma_check:
    47.     raise InvalidVerifySpendProof

    48. return true
~~~

Note: The key difference from the private variant is step 5-6 (pairing
check instead of `A_bar = A' * sk`) and step 36 (a_bar included in
transcript). The range proof verification (steps 12-29) is identical.

## Cryptographic Primitives

### Protocol Version

Each ciphersuite uses a distinct protocol version string for domain
separation:

~~~
ACT-Ristretto255-BLAKE3:
  PROTOCOL_VERSION = "curve25519-ristretto anonymous-credits v1.0"

ACT-BLS12381-G1-BLAKE3:
  PROTOCOL_VERSION = "bls12-381 anonymous-credits-public v1.0"
~~~

These version strings MUST be used consistently across all implementations for
interoperability. The curve specification is included to prevent cross-curve
attacks and ensure implementations using different curves cannot accidentally
interact.

### Hash Function and Fiat-Shamir Transform

The Fiat-Shamir transform is shared between both ciphersuites. The protocol
uses BLAKE3 {{BLAKE3}} as the underlying hash function, following the sigma
protocol framework {{ORRU-SIGMA}}. Challenges are generated using a transcript
that accumulates all protocol messages:

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

  Steps:
    1. hash = transcript.hasher.output(64)  // 64 bytes of output
    2. challenge = from_little_endian_bytes(hash) mod q
    3. return challenge
~~~

This approach ensures:

- Domain separation through the label, protocol version, and ciphersuite
- Inclusion of all public parameters to prevent parameter substitution attacks
- Proper ordering with length prefixes to prevent ambiguity
- Deterministic challenge generation from the complete transcript

Note: The PROTOCOL_VERSION string differs between ciphersuites (Section 4.1),
which ensures that transcripts from different ciphersuites produce different
challenges even with identical inputs.

### Encoding Functions

Elements and scalars are encoded according to the ciphersuite:

**ACT-Ristretto255-BLAKE3:**

~~~
Encode(value):
  Input:
    - value: Element or Scalar
  Output:
    - encoding: ByteString

  Steps:
    1. If value is an Element:
    2.     return value.compress()  // 32 bytes, compressed Ristretto point
    3. If value is a Scalar:
    4.     return value.to_bytes_le()  // 32 bytes, little-endian
~~~

**ACT-BLS12381-G1-BLAKE3:**

~~~
Encode(value):
  Input:
    - value: G1Element, G2Element, or Scalar
  Output:
    - encoding: ByteString

  Steps:
    1. If value is a G1Element:
    2.     return value.to_compressed()  // 48 bytes, compressed G1 point
    3. If value is a G2Element:
    4.     return value.to_compressed()  // 96 bytes, compressed G2 point
    5. If value is a Scalar:
    6.     return value.to_bytes_le()  // 32 bytes, little-endian
~~~

The following function provides consistent length-prefixing for hash inputs
(shared between both ciphersuites):

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

### Hash-to-Group

#### HashToRistretto255 (ACT-Ristretto255-BLAKE3) {#hash-to-ristretto}

~~~
HashToRistretto255(domain_separator, seed, counter):
  Input:
    - domain_separator: ByteString
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

The OneWayMap function is defined in {{RFC9496}} Section 4.3.4, which provides a
cryptographically secure mapping from uniformly random byte strings to valid
Ristretto255 points.

#### HashToG1 (ACT-BLS12381-G1-BLAKE3) {#hash-to-g1}

~~~
HashToG1(domain_separator, seed, counter):
  Input:
    - domain_separator: ByteString
    - seed: 32-byte seed value
    - counter: Integer counter for domain separation
  Output:
    - P: A valid BLS12-381 G1 point

  Steps:
    1. hasher = BLAKE3.new()
    2. hasher.update(LengthPrefixed(domain_separator))
    3. hasher.update(LengthPrefixed(seed))
    4. hasher.update(LengthPrefixed(counter.to_le_bytes(4)))
    5. uniform_bytes = hasher.finalize_xof(64)
    6. s = from_little_endian_bytes(uniform_bytes) mod q
    7. P = G1_gen * s
    8. return P
~~~

This method produces a G1 point with unknown discrete logarithm relative
to the G1 generator (assuming the hash function behaves as a random oracle).
The resulting point is guaranteed to be in the prime-order subgroup since
it is a scalar multiple of the generator.

### Binary Decomposition {#binary-decomposition}

This algorithm is shared between both ciphersuites.

To decompose a scalar into its binary representation:

~~~
BitDecompose(s):
  Input:
    - s: Scalar value
  Output:
    - bits: Array of L scalars (each 0 or 1)

  Steps:
    1. bytes = s.to_bytes_le()  // 32 bytes, little-endian
    2. For i = 0 to L-1:
    3.     byte_index = i / 8
    4.     bit_position = i % 8
    5.     bit = (bytes[byte_index] >> bit_position) & 1
    6.     bits[i] = Scalar(bit)
    7. return bits
~~~

Note: This algorithm produces bits in LSB-first order (i.e., `bits[0]` is the
least significant bit). See Section 3.1 for constraints on L.

### Scalar Conversion

This algorithm is shared between both ciphersuites.

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
    1. amount = s as integer  // Interpret little-endian scalar bytes as integer
    2. if amount >= 2^L:
    3.     return ScalarOutOfRangeError
    4. return amount
~~~

# Protocol Messages and Wire Format

## Message Encoding

All protocol messages SHOULD be encoded using deterministic CBOR (RFC 8949) for
interoperability. Decoders MUST reject messages containing unknown CBOR map
keys. The following sections define the structure of each message type for
each ciphersuite.

In the format descriptions below, point sizes depend on the ciphersuite:

- ACT-Ristretto255-BLAKE3: Ristretto point = 32 bytes
- ACT-BLS12381-G1-BLAKE3: G1 point = 48 bytes, G2 point = 96 bytes
- Both ciphersuites: Scalar = 32 bytes

### Issuance Request Message

The issuance request is identical in structure for both ciphersuites (point
sizes differ):

~~~
IssuanceRequestMsg = {
    1: bstr,  ; K (compressed point, 32 or 48 bytes)
    2: bstr,  ; gamma (scalar, 32 bytes)
    3: bstr,  ; k_bar (scalar, 32 bytes)
    4: bstr   ; r_bar (scalar, 32 bytes)
}
~~~

### Issuance Response Message

**ACT-Ristretto255-BLAKE3** (includes DLEQ proof):

~~~
IssuanceResponseMsg = {
    1: bstr,  ; A (compressed Ristretto point, 32 bytes)
    2: bstr,  ; e (scalar, 32 bytes)
    3: bstr,  ; gamma_resp (scalar, 32 bytes)
    4: bstr,  ; z (scalar, 32 bytes)
    5: bstr,  ; c (scalar, 32 bytes)
    6: bstr   ; ctx (scalar, 32 bytes)
}
~~~

**ACT-BLS12381-G1-BLAKE3** (no DLEQ proof):

~~~
IssuanceResponseMsg = {
    1: bstr,  ; A (compressed G1 point, 48 bytes)
    2: bstr,  ; e (scalar, 32 bytes)
    3: bstr,  ; c (scalar, 32 bytes)
    4: bstr   ; ctx (scalar, 32 bytes)
}
~~~

### Spend Proof Message

**ACT-Ristretto255-BLAKE3:**

~~~
SpendProofMsg = {
    1: bstr,           ; k (nullifier, 32 bytes)
    2: bstr,           ; s (spend amount, 32 bytes)
    3: bstr,           ; A' (compressed point, 32 bytes)
    4: bstr,           ; B_bar (compressed point, 32 bytes)
    5: [* bstr],       ; Com array (L compressed points)
    6: bstr,           ; gamma (scalar, 32 bytes)
    7: bstr,           ; e_bar (scalar, 32 bytes)
    8: bstr,           ; r2_bar (scalar, 32 bytes)
    9: bstr,           ; r3_bar (scalar, 32 bytes)
    10: bstr,          ; c_bar (scalar, 32 bytes)
    11: bstr,          ; r_bar (scalar, 32 bytes)
    12: bstr,          ; w00 (scalar, 32 bytes)
    13: bstr,          ; w01 (scalar, 32 bytes)
    14: [* bstr],      ; gamma0 array (L scalars)
    15: [* [bstr, bstr]], ; z array (L pairs of scalars)
    16: bstr,          ; k_bar (scalar, 32 bytes)
    17: bstr,          ; s_bar (scalar, 32 bytes)
    18: bstr           ; ctx (scalar, 32 bytes)
}
~~~

**ACT-BLS12381-G1-BLAKE3** (adds a_bar field):

~~~
SpendProofMsg = {
    1: bstr,           ; k (nullifier, 32 bytes)
    2: bstr,           ; s (spend amount, 32 bytes)
    3: bstr,           ; A' (compressed G1 point, 48 bytes)
    4: bstr,           ; B_bar (compressed G1 point, 48 bytes)
    5: bstr,           ; a_bar (compressed G1 point, 48 bytes)
    6: [* bstr],       ; Com array (L compressed G1 points)
    7: bstr,           ; gamma (scalar, 32 bytes)
    8: bstr,           ; e_bar (scalar, 32 bytes)
    9: bstr,           ; r2_bar (scalar, 32 bytes)
    10: bstr,          ; r3_bar (scalar, 32 bytes)
    11: bstr,          ; c_bar (scalar, 32 bytes)
    12: bstr,          ; r_bar (scalar, 32 bytes)
    13: bstr,          ; w00 (scalar, 32 bytes)
    14: bstr,          ; w01 (scalar, 32 bytes)
    15: [* bstr],      ; gamma0 array (L scalars)
    16: [* [bstr, bstr]], ; z array (L pairs of scalars)
    17: bstr,          ; k_bar (scalar, 32 bytes)
    18: bstr,          ; s_bar (scalar, 32 bytes)
    19: bstr           ; ctx (scalar, 32 bytes)
}
~~~

### Refund Message

**ACT-Ristretto255-BLAKE3** (includes DLEQ proof):

~~~
RefundMsg = {
    1: bstr,  ; A* (compressed Ristretto point, 32 bytes)
    2: bstr,  ; e* (scalar, 32 bytes)
    3: bstr,  ; gamma (scalar, 32 bytes)
    4: bstr,  ; z (scalar, 32 bytes)
    5: bstr   ; t (partial return, scalar, 32 bytes)
}
~~~

**ACT-BLS12381-G1-BLAKE3** (no DLEQ proof):

~~~
RefundMsg = {
    1: bstr,  ; A* (compressed G1 point, 48 bytes)
    2: bstr,  ; e* (scalar, 32 bytes)
    3: bstr   ; t (partial return, scalar, 32 bytes)
}
~~~

## Error Responses

Error responses SHOULD use the following format (shared between both
ciphersuites):

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

**ACT-Ristretto255-BLAKE3:**

~~~
PublicKey = bstr  ; W (compressed Ristretto point, 32 bytes)
~~~

**ACT-BLS12381-G1-BLAKE3:**

~~~
PublicKey = bstr  ; W (compressed G2 point, 96 bytes)
~~~

### Private Key

**ACT-Ristretto255-BLAKE3:**

~~~
PrivateKey = {
    1: bstr,  ; x (secret scalar, 32 bytes)
    2: bstr   ; W (public key, compressed Ristretto point, 32 bytes)
}
~~~

Decoders MUST verify that W == G * x upon deserialization to prevent use
of inconsistent key material.

**ACT-BLS12381-G1-BLAKE3:**

~~~
PrivateKey = {
    1: bstr,  ; x (secret scalar, 32 bytes)
    2: bstr   ; W (public key, compressed G2 point, 96 bytes)
}
~~~

Decoders MUST verify that W == G2_gen * x upon deserialization to prevent use
of inconsistent key material.

## Client State Serialization

The following formats define the serialization of client-side state that
must be persisted between protocol steps. Implementations that need to
store or transmit client state SHOULD use these formats for interoperability.

### Pre-Issuance State

The client MUST persist this state after generating an issuance request
and before receiving the issuance response. This format is identical for
both ciphersuites.

~~~
PreIssuance = {
    1: bstr,  ; r (blinding factor, scalar, 32 bytes)
    2: bstr   ; k (nullifier, scalar, 32 bytes)
}
~~~

### Credit Token

The client MUST persist the credit token after issuance or refund.

~~~
CreditToken = {
    1: bstr,  ; A (BBS signature point, compressed, 32 or 48 bytes)
    2: bstr,  ; e (signature scalar, 32 bytes)
    3: bstr,  ; k (nullifier, scalar, 32 bytes)
    4: bstr,  ; r (blinding factor, scalar, 32 bytes)
    5: bstr,  ; c (credit amount, scalar, 32 bytes)
    6: bstr   ; ctx (request context, scalar, 32 bytes)
}
~~~

### Pre-Refund State

The client MUST persist this state after generating a spend proof and
before receiving the refund response. This format is identical for both
ciphersuites.

~~~
PreRefund = {
    1: bstr,  ; r (blinding factor, scalar, 32 bytes)
    2: bstr,  ; k (nullifier, scalar, 32 bytes)
    3: bstr,  ; m (remaining balance, scalar, 32 bytes)
    4: bstr   ; ctx (request context, scalar, 32 bytes)
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

In ACT-BLS12381-G1-BLAKE3, a third-party verifier can additionally verify
spend proofs:

~~~
Client                                          Issuer
  |                                               |
  |-- SpendProofMsg ----------------------------->|
  |                   \                            |
  |                    \--- SpendProofMsg -------->| Third-Party
  |                                               | Verifier
  |                                               | (has pk only)
~~~

### Example Usage Scenario

Consider an API service that sells credits in bundles of 1000:

1. **Purchase**: Alice buys 1000 API credits
   - Alice generates a random nullifier k and blinding factor r
   - Alice sends IssuanceRequestMsg to the service
   - Service creates a BBS+ signature on (1000, k, r) and returns it
   - Alice now has a token worth 1000 credits

2. **First API Call**: Alice makes an API call costing 50 credits
   - Alice creates a SpendProofMsg proving she has >= 50 credits
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

### ACT-Ristretto255-BLAKE3

All Ristretto points received from external sources MUST be validated:

1. **Deserialization**: Verify the point deserializes to a valid Ristretto point
2. **Non-Identity**: Verify the point is not the identity element
3. **Subgroup Check**: Ristretto guarantees prime-order subgroup membership

Example validation:

~~~
ValidatePoint(P):
  1. If P fails to deserialize:
  2.     return INVALID
  3. If P == Identity:
  4.     return INVALID
  5. // Ristretto ensures prime-order subgroup membership
  6. return VALID
~~~

### ACT-BLS12381-G1-BLAKE3

All G1 and G2 points received from external sources MUST be validated:

1. **Deserialization**: Verify the point deserializes to a valid compressed
   G1 or G2 point (including on-curve check)
2. **Non-Identity**: Verify the point is not the identity element
3. **Subgroup Check**: BLS12-381 G1 has cofactor h = 1 (prime-order),
   so standard `from_compressed` deserialization suffices. G2 has a
   non-trivial cofactor, so implementations MUST perform a subgroup check
   for G2 points (public keys) or use a deserializer that verifies
   subgroup membership.

All implementations MUST validate points at these locations:

- When receiving `K` in issuance request
- When receiving `A` in issuance response
- When receiving `A'`, `B_bar`, and `a_bar` (ACT-BLS12381-G1-BLAKE3) in spend proof
- When receiving `Com[j]` commitments in spend proof
- When receiving `A*` in refund response
- When receiving a public key (G2 element, ACT-BLS12381-G1-BLAKE3)

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

- **Group Operations**: Point additions in the group (e.g., P + Q)
- **Group Exponentiations**: Scalar multiplication of group elements (e.g., P * s)
- **Scalar Additions/Multiplications**: Arithmetic operations modulo the group order q

- **Issuance**:

| Operation | Group Operations | Group Exponentiations | Scalar Additions | Scalar Multiplications | Hashes |
|-----------|------------------|-----------------------|------------------|------------------------|--------|
| Client Request | 2 | 4 | 2 | 1 | 1 |
| Issuer Response (Ristretto) | 5 | 8 | 3 | 1 | 2 |
| Issuer Response (BLS12-381) | 2 | 3 | 0 | 0 | 1 |
| Client Verify (Ristretto) | 5 | 5 | 0 | 0 | 1 |
| Client Verify (BLS12-381) | 1 | 1 | 0 | 0 | 2P |

Note: "2P" denotes two pairing computations.

- **Spending**:

| Operation | Group Operations | Group Exponentiations | Scalar Additions | Scalar Multiplications | Hashes |
|-----------|------------------|-----------------------|------------------|------------------------|--------|
| Client Request | 17 + 4L | 27 + 8L | 13 + 5L | 12 + 3L | 1 |
| Issuer Response (Ristretto) | 16 + 4L | 24 + 5L | 4 + L | 1 | 1 |
| Issuer Response (BLS12-381) | 16 + 4L | 24 + 5L | 4 + L | 1 | 1 + 2P |
| Client Refund (Ristretto) | 3 | 5 | L | L | 1 |
| Client Refund (BLS12-381) | 2 | 2 | L | L | 2P |

Note: The BLS12-381 spend verification includes 2 pairing computations plus
the sigma protocol verification. Pairings are computationally expensive
(~1ms each) but enable third-party verification.

- **Storage**:

| Component | Ristretto | BLS12-381 |
|-----------|-----------|-----------|
| Token size | 192 bytes (6 x 32) | 240 bytes (48 + 5 x 32 + 48 padding) |
| Spend proof size | 32 x (14 + 4L) bytes | 32 x (14 + 4L) + 3 x 48 bytes |
| Nullifier database entry | 32 bytes | 32 bytes |
| Public key | 32 bytes | 96 bytes |

Note: Token size is independent of L. The BLS12-381 spend proof is larger
due to the a_bar field and larger point encodings.

# Security Considerations

## Security Model and Definitions

### Threat Model

We consider a setting with:

- Multiple issuers who can operate independently, though malicious issuers may collude with each other
- Potentially malicious clients who may attempt to spend more credits than they should (whether by forging tokens, spending more credits than a token has, or double-spending a token)

### Security Properties

The protocol provides the following security guarantees:

1. **Unforgeability**: For an honest issuer I, no probabilistic polynomial-time (PPT) adversary controlling a set of malicious clients and other malicious issuers can spend more credits than have been issued by I.

2. **Anonymity/Unlinkability**: For an honest client C, no adversary controlling a set of malicious issuers and other malicious clients can link a token issuance/refund to C with a token spend by C. This property is information-theoretic in nature.

3. **Public Verifiability** (ACT-BLS12381-G1-BLAKE3 only): Any party holding
   the issuer's public key can verify that a spend proof is valid. This is a
   weaker form of verification than the issuer's (which also checks the
   nullifier database), but it cryptographically guarantees that the spending
   party holds a valid token with sufficient balance.

## Cryptographic Assumptions

Security relies on:

1. **The q-SDH Assumption**:

   - For ACT-Ristretto255-BLAKE3: The q-SDH assumption in the Ristretto255
     group. We refer to {{TZ23}} for the formal definition.

   - For ACT-BLS12381-G1-BLAKE3: The q-SDH assumption in both the G1 and G2
     subgroups of BLS12-381. This is a standard assumption in the pairing
     setting, used in the security proof of BBS+ signatures.

2. **Random Oracle Model**: The BLAKE3 hash function H is modeled as a random oracle.

3. **Bilinear Pairing Security** (ACT-BLS12381-G1-BLAKE3 only): The security
   of the pairing-based verification relies on the computational Diffie-Hellman
   assumption holding in both G1 and G2, and the bilinear pairing being
   non-degenerate.

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

### Public Verifiability Implications

In the ACT-BLS12381-G1-BLAKE3 ciphersuite, the `a_bar` value in the spend proof
enables any holder of the public key to verify the proof. This has the following
implications:

- **Relay Safety**: Spend proofs can be forwarded to third parties for
  verification without compromising the issuer's secret key.
- **Audit Trail**: Third-party auditors can verify that spend proofs accepted
  by a service were cryptographically valid.
- **No Additional Privacy Loss**: The `a_bar` value does not reveal any
  additional information about the token or client beyond what is already
  in the spend proof, because it is computationally bound to the randomized
  signature values.

The security of the `a_bar` computation relies on the prover not knowing
discrete log relations that could fool the pairing check. This is ensured
by the BBS+ unforgeability guarantee: a valid `a_bar` can only be computed
by someone who knows a valid BBS+ signature.

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
in the initial handshake. All parties MUST agree on the protocol version and
ciphersuite before proceeding.

## Quantum Resistance

This protocol is NOT quantum-resistant. The discrete logarithm problem can be
solved efficiently by quantum computers using Shor's algorithm. Organizations
requiring long-term security should consider post-quantum alternatives. However,
user privacy is preserved even in the presence of a cryptographically relevant
quantum computer.

# IANA Considerations

This document has no IANA actions.

--- back

# Test Vectors: ACT-Ristretto255-BLAKE3 {#test-vectors-ristretto}

This appendix provides test vectors for the ACT-Ristretto255-BLAKE3
ciphersuite. All values are encoded in hexadecimal.

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

# Test Vectors: ACT-BLS12381-G1-BLAKE3 {#test-vectors-bls}

This appendix provides test vectors for the ACT-BLS12381-G1-BLAKE3
ciphersuite. All values are encoded in hexadecimal.

<!-- BLS_TEST_VECTORS_START -->
The following test vector was generated deterministically using a
ChaCha20 RNG seeded with the bytes `00 01 02 ... 1e 1f` and L=8.
The domain separator is `"ACT-public-v1:test:vectors:v0:2025-01-01"`, credit amount
c=100, spend amount s=30, partial return t=10, and ctx=0. Values labelled `*_cbor`
are the CBOR wire-format encodings of each protocol
message, displayed in hexadecimal.

Implementations SHOULD verify they can deserialize these CBOR
messages and that a full protocol run with the same deterministic
RNG produces identical output.

## Parameters

~~~
domain_separator: "ACT-public-v1:test:vectors:v0:2025-01-01"
L: 8
c: 100
s: 30
t: 10
ctx: 0000000000000000000000000000000000000000000000000000000000000000
~~~

## Key Generation

~~~
sk_cbor:
  a2015820e7139050f82508d7ba932cfeec58b23f24d0f21c454995b9d79db78c
  4a2f154d025860a73d2e3c757c283688a7cb7c4e79953a3588c99a47a7d9b82f
  e8958126968d26a26312728f29ae262029fc24ede69a2b0d51ab6775c3ae9146
  bb2bfe4824c85d94c00550be19dd4a4632533c4f9c1d6b89bc842d632690468a
  9f5872300fd7c9

pk_cbor:
  5860a73d2e3c757c283688a7cb7c4e79953a3588c99a47a7d9b82fe895812696
  8d26a26312728f29ae262029fc24ede69a2b0d51ab6775c3ae9146bb2bfe4824
  c85d94c00550be19dd4a4632533c4f9c1d6b89bc842d632690468a9f5872300f
  d7c9
~~~

## Issuance

~~~
preissuance_cbor:
  a2015820ec19a163a8e44acc21fb4b7592cdac1fdbcdead1a8946e101a6734ac
  2bb4974a02582045b8221338f3a591f41df327c582305c92b0a3debe4b420b37
  f939c88820f518

issuance_request_cbor:
  a4015830929ea9decd2955d576b693db4669dd583feb5a98c7420860b9930b0e
  277cbeb9fe9a14eab8db62f7f46eb2c66555cbc00258208dd940529808e6c10f
  7703f69432afc98eccdbfb1575e8013f7d750e6b5b261603582006fece0263b4
  04292fb75e405c81df4834be3a26164564ea59f2bfef5c68e82c04582049dff6
  416a34759e3d57665f783884ccaae486f6c2c7e08ddc9dcac8e3158146

issuance_response_cbor:
  a4015830ae446fcc8c380160b92aa115b9046d12601a88849f8815d7701910af
  ad9cd180ba6d46beb7d3e28503555869347f296a02582078b3c5981568274ebc
  5744b64a889d5c3fd1b398f142e9e1678b0e641a64fe09035820640000000000
  0000000000000000000000000000000000000000000000000000045820000000
  0000000000000000000000000000000000000000000000000000000000

credit_token_cbor:
  a6015830ae446fcc8c380160b92aa115b9046d12601a88849f8815d7701910af
  ad9cd180ba6d46beb7d3e28503555869347f296a02582078b3c5981568274ebc
  5744b64a889d5c3fd1b398f142e9e1678b0e641a64fe0903582045b8221338f3
  a591f41df327c582305c92b0a3debe4b420b37f939c88820f518045820ec19a1
  63a8e44acc21fb4b7592cdac1fdbcdead1a8946e101a6734ac2bb4974a055820
  6400000000000000000000000000000000000000000000000000000000000000
  0658200000000000000000000000000000000000000000000000000000000000
  000000
~~~

## Spending

~~~
nullifier:
  45b8221338f3a591f41df327c582305c92b0a3debe4b420b37f939c88820f518

context:
  0000000000000000000000000000000000000000000000000000000000000000

charge:
  1e00000000000000000000000000000000000000000000000000000000000000

spend_proof_cbor:
  b301582045b8221338f3a591f41df327c582305c92b0a3debe4b420b37f939c8
  8820f5180258201e000000000000000000000000000000000000000000000000
  00000000000000035830b8396aaba4a1647be30aa8829a87546deec16b45f344
  8fa0b9b1e7d85cb02a45fac2a03606991bd72f5170baf012ee4204583094ba10
  d60406de84066b54fb765f980aa553474dfd1a88eca5ed351a16a4c4f259f88a
  18a23a7bb647c4091a9e5416cc05885830986edb380f07ff4bb12a1f81537d2c
  96def7ebc055c6099ad2cd0d8fc5243084e3ebaf9803611a04a491d280f676ea
  3f5830847d58b1f5448ffdbe9e0282e7d062e5a1c188c5f21a6435f15eea9a9e
  eaf0c5d6f20d8795563cf60113a9eba5982059583084d8c53abf6077b08a96a2
  903135c2b3f8fed7d4e47f5c66e6a3062abcc25c139c1ce35389791e27538dff
  9b02a0590d58308f3cd52e40e70135bb3ebd10e9d1163cb5044b71420b5410d1
  e08f80aa92668f48b6d497fdfcfd8e6b2efae02f5a7a045830932d80a328fbd9
  57687e27c5f7deb1c14ea7b0638998eaa2bb6c52b280602fed16b1fa7c38940a
  fd93f41a96dac0daca5830b1db0418c65f3c5a67543a1c04689afcb4c25b10a8
  7bb669c4335aa32bbd22461bd9c5d91e9aa525c2c8e8fe15b4e1fd5830ae6b74
  60fc30b1d159710cea87e9b699e41f6d6e91f4e3019e75632d2d671d198dfcc2
  929ead3847c2bcfe08f6f4c30758309088f2e03e84527e245c317bde51c96eed
  0330c1398eb35d2fd9717ffb3bb52a2370555de70c13b40dd4fcc71362b02306
  5820790172cb521373e0686afd808b03a28e4600fc88ed9cbd65c3e7e1cc4be6
  de0f07582077dba11364efd4b5420585373d5d3ce6f32e2a27f9e49cc2089c2c
  dad4973866085820a71c6595ef97ae52818ebf8d913d6739fc0a854799c75b51
  15d756ec35722e6c09582064e9a6e68b686a7a8f8eeaec3cf392b45449a56e87
  e5de75811b5b89621039520a5820ecba7e7edb973c6e5d1eb701843d9c2e7cb6
  c1913fed9ef5da5123db8a86a41c0b582087f306aba0229794c69cea61fb6f89
  67462d24db1922cc0966cb77f3f40e0b5d0c58208dc0d6847a7b082eb9deeaac
  96a08ad6b19c90ec2d299dcc8b78a24f370486430d5820b6b90471329140bc17
  af8640507f4b01b6503a558dd43d94de4737abd7bdc25e0e885820d4dc68896c
  2ca6e1bb17cf78457731f6abcaf57140370603d1f5eeca5d5c000258207ea76e
  e6dff08ea5c3765d108f3ee3f92a7c56d7138f818c93e6a349ef5e2960582033
  d5fe1c392f1f175d52371527f8f3ff32666d698072726fdec39283725ec95358
  20337dfca2be4617734b5b85d7e703b8c4e17893977c1d62798128d12f551edb
  4f58201dcd773c15bc91ab2e355c2e7f3e42a8051d1c6efc36d61aba2f4d4f5f
  2fb1565820550a49a554476a568fe402813150716e32f0696f5bc67505a1a91a
  70a5fd936158208cd25f1bf8fc9208854891a2dd92ea8b8f4be2896c2d6b223d
  edaa95ae9b0c3458200d739181c1ba901a692a0c813cef0f539a9fd5c2b95c87
  ccf234bf7e5204e75d0f88825820f6af1fbefcbabaa6dc86a7efc92bd8a91bd8
  5bd5e2901e3045d8f7ce75d458495820f556172aa50e5028cca8ca8d362e92ba
  e2879426850f858945bbf804c86d2d0a8258209312b5bfd2f73800346ee51097
  669d79bc8c0b04e0ff4efe26451be6f3b11a29582068f29e19a7bde06cab4db4
  3bce5ce4c79e94a3536ec3577c28542caa0a53984f8258201ac717b3f3522a70
  4749b6180c4fa7cbc970e22fc1a5331860013cd323ad55415820cbd85ff4f354
  69beb63cfefc457ea74115c12f9e339df9762a9488ad55f4e556825820d012d5
  de03d2e7e597f948887efffd0c42b32689d9e193947d021892957d773958207f
  a47bd2d5f7279a66771e2bdbff6e7e22bb020a27902267c896198772a87c5482
  58207c31c7a12c2c5c0c19c5ee94225e81248ed1d7c94cdcaf1dab105ee3d2b8
  dd1c5820040a70fb958bae35e1faf5cf04876f09a2c91263aeb6ba4bf53feb42
  7abb5f128258207dc2ec224d20047cea2f97175730642f53a9210a55c5ba52e4
  6826be4675d3295820d3957b2cdb5c63f04b05c14be7e7ff995fe15c6bb4daba
  22aab770a45b8de35a825820391c27b8d6c19e0863a83b0303d7ebfbf2d2b503
  881b556601730ccdd3cc60645820e3e77e2f2cb578617d3023502bf68654231d
  fecaff8e6202eacc07ad2fa2b0188258206ad71d955f2b6c66586fd65f98d355
  193f867c006ffc0b3d61bcff04e2ef0f465820fb5704a4a172aa91ebdc1a4bea
  478b06b3086e881998e716a5406604586880091058202e0b3d66989e72b6e9e8
  6f3c5183efe590373f7a0b8e390d0822234a6666cd1511582016c07e92895ef1
  0a5f11cb0ba6ff2de2534620e696b7a0b27d17bd8ccecaa56812582000000000
  00000000000000000000000000000000000000000000000000000000135830a4
  0f5387ee2854b0f8180e889eabb57341781ac362ec791d7a18c8816336b0471b
  6c961b5ea9ae4307bd100d50ea0fea

prerefund_cbor:
  a40158209a05b907693a143f7202c1b45a9905e6012507dab7013ce7b29f47e3
  fbd9733c0258202ba2b4c18641bb32cabc53dbc1bb32dd21419cb892d33deb7d
  2c8c2819d9370303582046000000000000000000000000000000000000000000
  0000000000000000000004582000000000000000000000000000000000000000
  00000000000000000000000000
~~~

## Refund

~~~
refund_cbor:
  a3015830b3d1b635966e2a55efc2166dda5ac4a4cbad09410558862972eed4f8
  6056485cee3718452f7f27e908f7d1de5c47b233025820d0b9164f71c07c656e
  a24791e3280055bdaf2eb803e14cb46b78610617de98550358200a0000000000
  0000000000000000000000000000000000000000000000000000
~~~

## Refund Token

~~~
refund_token_cbor:
  a6015830b3d1b635966e2a55efc2166dda5ac4a4cbad09410558862972eed4f8
  6056485cee3718452f7f27e908f7d1de5c47b233025820d0b9164f71c07c656e
  a24791e3280055bdaf2eb803e14cb46b78610617de98550358202ba2b4c18641
  bb32cabc53dbc1bb32dd21419cb892d33deb7d2c8c2819d937030458209a05b9
  07693a143f7202c1b45a9905e6012507dab7013ce7b29f47e3fbd9733c055820
  5000000000000000000000000000000000000000000000000000000000000000
  0658200000000000000000000000000000000000000000000000000000000000
  000000

refund_token_credits:
  5000000000000000000000000000000000000000000000000000000000000000

refund_token_nullifier:
  2ba2b4c18641bb32cabc53dbc1bb32dd21419cb892d33deb7d2c8c2819d93703

remaining_balance: 80
~~~
<!-- BLS_TEST_VECTORS_END -->

# Implementation Status

This section records the status of known implementations of the protocol
defined by this specification at the time of posting of this Internet-Draft,
and is based on a proposal described in RFC 7942.

## anonymous-credit-tokens (ACT-Ristretto255-BLAKE3)

Organization: Google

Description: Reference implementation in Rust

Maturity: Beta

Coverage: Complete protocol implementation

License: Apache 2.0

Contact: sgschlesinger@gmail.com

URL: https://github.com/SamuelSchlesinger/anonymous-credit-tokens

## anonymous-credit-tokens-public (ACT-BLS12381-G1-BLAKE3)

Organization: Google

Description: Reference implementation in Rust using BLS12-381

Maturity: Experimental

Coverage: Complete protocol implementation

License: Apache 2.0

Contact: sgschlesinger@gmail.com

URL: https://github.com/SamuelSchlesinger/anonymous-credit-tokens

# Terminology Glossary

This glossary provides quick definitions of key terms used throughout this document:

**ACT (Anonymous Credit Tokens)**: The privacy-preserving authentication protocol specified in this document.

**Blind Signature**: A cryptographic signature where the signer signs a message without seeing its content.

**Ciphersuite**: A specific instantiation of the ACT protocol with a chosen group, hash function, and verification method.

**DLEQ Proof**: A Discrete Log Equality proof demonstrating that two group elements have the same discrete log relationship. Used in the Ristretto255 ciphersuite for issuance and refund verification.

**Refund**: The refund issued for the remaining balance after a partial spend.

**Credit**: A numerical unit of authorization that can be spent by clients.

**Domain Separator**: A unique string used to ensure cryptographic isolation between different deployments and ciphersuites.

**G1Element**: A point in the primary group used for token computations (Ristretto255 or BLS12-381 G1).

**G2Element**: A point in BLS12-381 G2, used for the public key in the ACT-BLS12381-G1-BLAKE3 ciphersuite.

**Issuer**: The entity that creates and signs credit tokens.

**Nullifier**: A unique value revealed during spending that prevents double-spending of the same token.

**Pairing**: A bilinear map `e: G1 x G2 -> GT` used in BLS12-381 for signature verification without the secret key.

**Partial Spending**: The ability to spend less than the full value of a token and receive change.

**Public Verifiability**: The property (ACT-BLS12381-G1-BLAKE3 only) that spend proofs can be verified by anyone with the issuer's public key.

**Scalar**: An integer modulo the group order q, used in cryptographic operations.

**Sigma Protocol**: An interactive zero-knowledge proof protocol following a commit-challenge-response pattern.

**Token**: A cryptographic credential containing a BBS+ signature and associated data (A, e, k, r, c, ctx).

**Unlinkability**: The property that transactions cannot be correlated with each other or with token issuance.

# Acknowledgments

The authors would like to thank the Crypto Forum Research Group for their
valuable feedback and suggestions. Special thanks to the contributors who
provided implementation guidance and security analysis.

This work builds upon the foundational research in anonymous credentials and
zero-knowledge proofs by numerous researchers in the cryptographic community,
particularly the work on BBS signatures by Boneh, Boyen, and Shacham, and
keyed-verification anonymous credentials by Chase, Meiklejohn, and Zaverucha.
