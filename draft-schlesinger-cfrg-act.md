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
 -
    fullname: Armando Faz-Hernandez
    organization: Cloudflare, Inc.
    email: armfazh@cloudflare.com

normative:
  FIPS186: DOI.10.6028/NIST.FIPS.186-5
  FIPS202: DOI.10.6028/NIST.FIPS.202
  SIGMA: I-D.irtf-cfrg-sigma-protocols-02
  FIAT-SHAMIR: I-D.irtf-cfrg-fiat-shamir-02

informative:
  FST: DOI.10.1007/3-540-47721-7_12
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
multiple spends by the same client, (2) flexible balance updates -
clients can spend a portion of their credits and receive anonymous
change, and may add issuer-authorized credits to their balance in
the same operation, and (3) double-spend prevention through
cryptographic nullifiers that preserve privacy while ensuring each
token is used only once.

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

Anonymous Credit Tokens (ACT) help resolve this tension by
providing a cryptographic protocol that enables credit-based systems
without client tracking. Built on keyed-verification anonymous
credentials {{KVAC}} and privately verifiable BBS-style signatures
{{BBS}}, the protocol allows services to issue, manage, and spend
credits while maintaining client privacy.

## Key Properties

The protocol provides the following properties:

1. **Unlinkability**: The issuer cannot link credit issuance to
   spending, or connect multiple transactions by the same client.
   This property is information-theoretic, not merely computational.

2. **Partial Spending**: Clients can spend any amount up to their
   balance and receive anonymous change without revealing their
   previous or current balance, enabling flexible spending.

3. **Balance Adjustments**: Each spend returns a token with an
   updated balance. The client can include an issuer-authorized
   top-up in the spend itself, and at refund time the issuer can
   move the final balance anywhere between the post-spend balance
   and the topped-up balance, granting the top-up, clawing it back,
   or refunding part of the spent amount; the issuer never learns
   the original or updated balance.

4. **Double-Spend Prevention**: Cryptographic nullifiers ensure each
   token is used only once, without linking it to issuance.

5. **Balance Privacy**: During spending, only the amount being spent
   is revealed, not the total balance in the token, protecting
   clients from balance-based profiling.

The design of the protocol also takes efficiency and simplicity into
consideration, making it suitable for high-volume web services and
straightforward to implement.

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
   balance. The new token's balance also reflects an issuer-chosen
   return amount, which can grant a client-requested top-up, claw
   it back, or refund part of the spent amount.

## Relation to Existing Work

This protocol builds upon several cryptographic primitives:

- **BBS Signatures** {{BBS}}: The core signature scheme that enables efficient
  proofs of possession. We use a variant that is privately verifiable, which
  avoids the need for pairings and makes our protocol more efficient.

- **Sigma Protocols** {{SIGMA}}: The zero-knowledge proof framework used for issuing and spending credits.

- **Fiat-Shamir Transform** {{FIAT-SHAMIR}}: The technique to make the interactive
  proofs non-interactive.

The protocol can be viewed as a specialized instantiation of keyed-verification
anonymous credentials {{KVAC}} optimized for numerical values and partial
spending.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Notation

This document uses the following notation:

- `||`: Concatenation of byte arrays.

- `x <- S`: Uniformly sampling x from the set S using `rng.random_scalar()`.

- `x = y`: Assignment of the value y to the variable x.

- `[n]`: The set of integers {0, 1, ..., n-1}.

- `|x|`: The length of byte array x.

- `0x` is a prefix to denote integer values in hexadecimal base.

- We use additive notation for group operations, so group elements are added
  together like `a + b` and scalar multiplication of a group element by a scalar
  is written as `a * n`, with group element `a` and scalar `n`.

The protocol uses the following data types:

- **Byte Array**: A sequence of bytes.
- **Group**: An interface of a prime-order group as defined
in {{Section 2.1 of !RFC9497}}.
- **Group Element**: An element of the group.
- **Scalar**: An element from the scalar field of the group.
- **PRNG**: An interface for a cryptographically secure pseudorandom
number generator with a `random_scalar() -> Scalar` method. The PRNG
MUST be backed by a CSPRNG in accordance with {{FIPS186}}.
See {{prng-appendix}} for the abstract interface definition.
- **LinearRelation**: An interface for building an interactive sigma
protocol as defined in {{Section 2.2.3 of SIGMA}}.
- **NISigmaProtocol**: An interface that implements the Fiat-Shamir
transform as defined in {{Section 6 of FIAT-SHAMIR}}.
This interface is parametrized with a SigmaProtocol, a Codec that
encodes prover messages and verifier challenges, and
a duplex sponge used to compute challenges.
See {{FIAT-SHAMIR}} for requirements of these parameters.

The specific parameters and implementations are defined in {{suites}}.

## Zero-knowledge Proofs of Knowledge {#zk-pok}

Proofs of knowledge are based on interactive sigma protocols, which
are made non-interactive through the Fiat-Shamir transform {{FST}}.
The concrete proofs use the LinearRelation and NISigmaProtocol
interfaces defined above.

The NISigmaProtocol requires a session identifier that
uniquely identifies the session being proven.
Once initialized, the Prover can generate proofs of knowledge
of a witness satisfying the statement, while the Verifier can validate
these proofs.

### Pedersen Proof

A proof of knowledge derived from a Pedersen commitment shows that
the prover knows witness scalars `(k0, k1)` such that `R = k0*P + k1*Q`,
for group elements `P`, `Q`, and `R`.

The {{append_pedersen}}{:format="title"} function appends linear relations
to the statement to instantiate a Pedersen proof,
as shown in {{Section 2.2.9 of SIGMA}}.

~~~ pseudocode
append_pedersen(statement, P, Q, R):
  Input:
    - statement: LinearRelation.
    - P: Group Element.
    - Q: Group Element.
    - R: Group Element.

  Steps:
    1. k0_var, k1_var = statement.allocate_scalars(2)
    2. P_var, Q_var, R_var = statement.allocate_elements(3)
    3. statement.append_equation(R_var, [(k0_var, P_var), (k1_var, Q_var)])
    4. statement.set_elements([(P_var, P), (Q_var, Q), (R_var, R)])
~~~
{: #append_pedersen }

### DLEQ Proof

A proof of knowledge of a Discrete Logarithm Equivalence (DLEQ) shows that
the prover knows a witness scalar `k` such that `X = k*P` and `Y = k*Q`,
for group elements `P`, `Q`, `X`, and `Y`.

The {{append_dleq}}{:format="title"} function appends linear relations
to the statement to instantiate a DLEQ proof,
as shown in {{Section 2.2.8 of SIGMA}}.

~~~ pseudocode
append_dleq(statement, P, Q, X, Y):
  Input:
    - statement: LinearRelation.
    - P: Group Element.
    - Q: Group Element.
    - X: Group Element.
    - Y: Group Element.

  Steps:
    1. k_var = statement.allocate_scalars(1)
    2. P_var, Q_var, X_var, Y_var = statement.allocate_elements(4)
    3. statement.append_equation(X_var, [(k_var, P_var)])
    4. statement.append_equation(Y_var, [(k_var, Q_var)])
    5. statement.set_elements([(P_var, P), (Q_var, Q), (X_var, X), (Y_var, Y)])
~~~
{: #append_dleq }

### Range Proof

A range proof shows that a committed value lies in the range
`[0, 3^D)` by decomposing it into base-3 digits and proving each
digit is in {0, 1, 2}. Base 3 minimizes proof size among digit
decompositions in this framework (see {{radix}}).

For each digit `j`, the prover sends a digit commitment `Com[j]`
and an auxiliary commitment `T[j]`. The verifier checks a proof
of knowledge of scalars `d[j]`, `s[j]`, `rho[j]`, and `w[j]`
satisfying three linear equations per digit:

1. **Opening**: `Com[j] = d[j]*H1 + s[j]*H3`.
2. **Auxiliary opening**: `T[j] + Com[j] = d[j]*Com[j] + rho[j]*H3`.
3. **Zero constraint**: `T[j]*2 = d[j]*T[j] + w[j]*H3`.

An honest prover assigns the digit `d[j]`, samples the blinding
scalars `s[j]` and `rho[j]`, computes
`T[j] = (d[j]-1)*Com[j] + rho[j]*H3`, and sets the derived
witness `w[j] = (2-d[j])*((d[j]-1)*s[j] + rho[j])`.

Verifying these equations forces `d[j] in {0, 1, 2}`, as follows.
Equation 1 opens `Com[j]` to the digit `d[j]`, so the
`H1`-component of `Com[j]` is `d[j]`. Equation 2, rearranged,
states `T[j] = (d[j]-1)*Com[j] + rho[j]*H3`, so the
`H1`-component of `T[j]` is `d[j]*(d[j]-1)`. Equation 3,
rearranged, states that `(d[j]-2)*T[j]` has no `H1`-component.
Together they imply `d[j]*(d[j]-1)*(d[j]-2) = 0` in the scalar
field, which holds exactly when `d[j] in {0, 1, 2}`; satisfying
the equations with any other digit value would require knowing a
discrete-logarithm relation between `H1` and `H3`.

This construction is a linear-relation encoding of a three-way OR
proof that each committed digit is 0, 1, or 2. A disjunctive (OR)
presentation would have the same proof size (see {{radix}}) but
requires composition beyond the linear framework of {{SIGMA}} on
which this document builds.

The digit equations carry no other witnesses: in particular, the
new token's nullifier is committed separately (see
{{token-spending}}), so all D digits are treated uniformly.

The {{append_range_proof}}{:format="title"} function appends linear
relations to the statement to instantiate a range proof. The caller
supplies the element variables holding `H1` and `H3`, so that
repeated invocations against the same statement share them.

~~~ pseudocode
append_range_proof(statement, H1_var, H3_var, Com, T, D):
  Input:
    - statement: LinearRelation.
    - H1_var: Element variable handle assigned the value H1.
    - H3_var: Element variable handle assigned the value H3.
    - Com: Array of D Group Elements (digit commitments).
    - T: Array of D Group Elements (auxiliary commitments).
    - D: Integer (digit count).
  Output:
    - d_vars: Array of D scalar variable handles.
    - s_vars: Array of D scalar variable handles.
    - rho_vars: Array of D scalar variable handles.
    - w_vars: Array of D scalar variable handles.

  Steps:
    // Allocate scalar variables
    1. d_vars = statement.allocate_scalars(D)
    2. s_vars = statement.allocate_scalars(D)
    3. rho_vars = statement.allocate_scalars(D)
    4. w_vars = statement.allocate_scalars(D)

    // Allocate element variables
    5. Com_vars = statement.allocate_elements(D)
    6. T_vars = statement.allocate_elements(D)
    7. TC_vars = statement.allocate_elements(D)  // T[j] + Com[j]
    8. T2_vars = statement.allocate_elements(D)  // T[j] * 2

    // Set element values
    9. For j = 0 to D-1:
   10.     statement.set_elements([(Com_vars[j], Com[j]),
             (T_vars[j], T[j]), (TC_vars[j], T[j] + Com[j]),
             (T2_vars[j], T[j] * 2)])

    // Per-digit equations
   11. For j = 0 to D-1:
         // Opening equation: Com[j] = d[j]*H1 + s[j]*H3
   12.     statement.append_equation(Com_vars[j],
             [(d_vars[j], H1_var), (s_vars[j], H3_var)])
         // Auxiliary opening: T[j] + Com[j] = d[j]*Com[j] + rho[j]*H3
   13.     statement.append_equation(TC_vars[j],
             [(d_vars[j], Com_vars[j]), (rho_vars[j], H3_var)])
         // Zero constraint: T[j]*2 = d[j]*T[j] + w[j]*H3
   14.     statement.append_equation(T2_vars[j],
             [(d_vars[j], T_vars[j]), (w_vars[j], H3_var)])

   15. return (d_vars, s_vars, rho_vars, w_vars)
~~~
{: #append_range_proof }

Implementations of the LinearRelation interface may require that each
group element value is assigned to at most one element variable, since
element variables are deduplicated or checked when the statement is
put into canonical form. The pseudocode in this document therefore
allocates the element variables for `H1`, `H2`, `H3`, and the shared
`3^j` coefficient elements once per statement and passes or reuses
the handles instead of assigning the same value to a second variable.

# Protocol Specification

## System Parameters

Each instance of the protocol defines the following parameters:

- `domain_separator` is a non-empty byte array that uniquely identifies
an instance of the protocol.
It ensures cryptographic separation between different ACT instances.
- `D` is the number of base-3 digits used to represent credit
values, such that `D <= MAX_DIGITS`, where `MAX_DIGITS` is defined
per suite. Credit values lie in the range `[0, 3^D)`.
- `H1`, `H2`, `H3`, `H4` are auxiliary group generators used for commitments.
`H4` is used for binding a request context.
The {{SetGenerators}}{:format="title"} function deterministically
generates them through hashing.
The discrete-logarithm relations between any pair of these generators
and the main generator MUST NOT be known to any party.
The {{SetGenerators}}{:format="title"} function achieves this by
deriving each generator independently via `HashToGroup` with distinct
domain separation tags and verifying pairwise distinctness.
This prevents attacks whereby malicious parameters could compromise security.

~~~ pseudocode
SetGenerators(G, domain_separator):
  Input:
    - G: Group.
    - domain_separator: Byte Array.
  Output:
    - H1, H2, H3, H4: Group Element.

  Steps:
    1. G0 = G.Generator()
    2. H1, H2, H3, H4 = [G0]*4
    3. counter = 0
    4. while len({G0, H1, H2, H3, H4}) < 5:
    5.   ctr = I2OSP(counter, 1)
    6.   H1 = G.HashToGroup("GenH1" || ctr || domain_separator)
    7.   H2 = G.HashToGroup("GenH2" || ctr || domain_separator)
    8.   H3 = G.HashToGroup("GenH3" || ctr || domain_separator)
    9.   H4 = G.HashToGroup("GenH4" || ctr || domain_separator)
   10.   counter += 1
   11. return H1, H2, H3, H4
~~~
{: #SetGenerators }

The `domain_separator` SHOULD follow this structured format:

~~~
domain_separator = "ACT-v1:" || organization || ":" || service || ":" || deployment_id || ":" || version
~~~

where:

- `organization`: A unique identifier for the organization (e.g., "example-corp", "acme-inc").
- `service`: The specific service or application name (e.g., "payment-api", "rate-limiter").
- `deployment_id`: The deployment environment (e.g., "production", "staging", "us-west-1").
- `version`: An ISO 8601 date (YYYY-MM-DD) indicating when parameters were generated.

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

## Key Generation

The issuer generates a key pair as follows:

~~~ pseudocode
KeyGen(G, rng):
  Input:
    - G: Group.
    - rng: PRNG.
  Output:
    - sk: Scalar.        # Private key
    - pk: Group Element. # Public key

  Steps:
    1. sk = rng.random_scalar()
    2. pk = sk * G.Generator()
    3. return sk, pk
~~~
{: #KeyGen }

## Token Issuance

The issuance protocol is an interactive protocol between a client and the
issuer:

### Client: Issuance Request

~~~
IssueRequest(rng):
  Input:
    - rng: PRNG.
  Output:
    - request: Issuance request
    - state: Client state for later verification

  Steps:
    1. k <- Zq  // Nullifier (will prevent double-spending)
    2. r <- Zq  // Blinding factor
    3. K = H2 * k + H3 * r

    // Generate proof of knowledge of (k, r) such that K = H2 * k + H3 * r
    4. statement = LinearRelation(group)
    5. append_pedersen(statement, H2, H3, K)
    6. session_id = domain_separator + "request"
    7. prover = NISigmaProtocol(session_id, statement)
    8. witness = [k, r]
    9. pok = prover.prove(witness, rng)
   10. request = (K, pok)
   11. state = (k, r, K)
   12. return (request, state)
~~~

### Issuer: Issuance Response

~~~
IssueResponse(sk, request, c, ctx, rng):
  Input:
    - sk: Issuer's private key
    - request: Client's issuance request
    - c: Credit amount to issue (0 <= c < 3^D)
    - ctx: Request context scalar
    - rng: PRNG.
  Output:
    - response: Issuance response
  Exceptions:
    - InvalidIssuanceRequestProof, raised when the client proof verification fails
    - AmountTooBigError, raised when c does not fit in the credit range [0, 3^D)

  Steps:
    // Validate the credit amount. This bounds every issued balance below
    // 3^D and is REQUIRED for the wraparound soundness argument (see the
    // Amount Validation and Modular Wraparound security considerations).
    1. if c >= 3^D:
    2.     raise AmountTooBigError

    // Verify proof of knowledge of (k, r) such that K = H2 * k + H3 * r
    3. Parse request as (K, pok)
    4. statement = LinearRelation(group)
    5. append_pedersen(statement, H2, H3, K)
    6. session_id = domain_separator + "request"
    7. verifier = NISigmaProtocol(session_id, statement)
    8. if not verifier.verify(pok):
    9.     raise InvalidIssuanceRequestProof

    // Create BBS signature on (c, ctx, k, r)
   10. e <- Zq
   11. X_A = G.Generator() + H1 * c + H4 * ctx + K    // K = H2 * k + H3 * r
   12. A = X_A * (1/(e + sk))
   13. X_G = G.Generator() * (e + sk)

   // Generate proof of knowledge of (e+sk) such that X_A = A * (e+sk) and X_G = G.Generator() * (e+sk)
   14. statement = LinearRelation(group)
   15. append_dleq(statement, A, G.Generator(), X_A, X_G)
   16. session_id = domain_separator + "respond" + Encode(c) + Encode(ctx)
   17. prover = NISigmaProtocol(session_id, statement)
   18. witness = [e + sk]
   19. pok = prover.prove(witness, rng)
   20. response = (A, e, c, pok)
   21. return response
~~~

Note: The `ctx` parameter is not included in the response because
both parties derive it from shared application context (e.g.,
TokenChallenge fields). The client MUST provide `ctx` separately
when calling `VerifyIssuance`.

### Client: Token Verification

~~~
VerifyIssuance(pk, response, ctx, state):
  Input:
    - pk: Issuer's public key
    - response: Issuer's response
    - ctx: Request context scalar
    - state: Client state from request generation
  Output:
    - token: Credit token
  Exceptions:
    - InvalidIssuanceResponseProof, raised when the server proof verification fails

  Steps:
    1. Parse response as (A, e, c, pok)
    2. Parse state as (k, r, K)

    // Verify proof of knowledge of (e+sk) such that X_A = A * (e+sk) and X_G = G.Generator() * (e+sk)
    3. X_A = G.Generator() + H1 * c + H4 * ctx + K
    4. X_G = G.Generator() * e + pk
    5. statement = LinearRelation(group)
    6. append_dleq(statement, A, G.Generator(), X_A, X_G)
    7. session_id = domain_separator + "respond" + Encode(c) + Encode(ctx)
    8. verifier = NISigmaProtocol(session_id, statement)
    9. if not verifier.verify(pok):
   10.     raise InvalidIssuanceResponseProof
   11. token = (A, e, k, r, c, ctx)
   12. return token
~~~

## Token Spending {#token-spending}

The spending protocol allows a client to spend `s` credits from a
token containing `c` credits (`0 <= s <= c`), optionally adding an
issuer-authorized top-up of `a` credits in the same operation
(`c + a < 3^D`). The spend proof carries two range proofs over the
hidden balance:

- the post-spend balance `v1 = c - s` lies in `[0, 3^D)`, so the
  token covers the spend on its own, and
- the topped-up balance `v2 = c + a` lies in `[0, 3^D)`, so the
  top-up fits under the credit ceiling.

The new balance is `v = c - s + a`. Plain spends set `a = 0`. The
new token's nullifier is carried in a dedicated commitment `K_n`
rather than inside a digit commitment, so the two range proofs stay
uniform.

The top-up amount `a` is a public input bound by the spend proof: a
proof generated for one value of `a` fails to verify under any
other, so an issuer authorizes a top-up by verifying the spend proof
with that value. How the client obtains authorization for a top-up
(e.g., an out-of-band payment) is application-defined and SHOULD be
bound to the request context `ctx`. Issuers that do not support
top-ups MUST reject spend proofs with `a != 0`.

The top-up is distinct from the return amount `t` of
{{refund-issuance}}. A top-up is covered by the second range proof,
so the issuer can authorize an addition of any size that fits under
the ceiling. The return amount is added homomorphically to the
post-spend balance `v1` after verification, without a range proof,
and is therefore bounded by `0 <= t <= s + a`: the two range proofs
certify exactly the endpoints of this window, since `t = 0` leaves
the balance at `v1 = c - s >= 0` and `t = s + a` raises it to
`c + a < 3^D`. The issuer thus retains full discretion at refund
time to land the final balance `c - s + t` anywhere in
`[c - s, c + a]`: `t = a` grants exactly the authorized top-up,
`t < a` claws back part or all of it, and `t > a` also refunds
part of the spent amount.

### Client: Spend Proof Generation

~~~
ProveSpend(token, s, a, rng):
  Input:
    - token: Credit token (A, e, k, r, c, ctx)
    - s: Amount to spend (0 <= s <= c)
    - a: Top-up amount (c + a < 3^D); 0 for a plain spend
    - rng: PRNG.
  Output:
    - proof: Spend proof
    - state: Client state for receiving change
  Exceptions:
    - InvalidAmount: raised when s or a is not in [0, 3^D), when
      s > c, or when c + a >= 3^D

  Steps:
    // Validate amounts and compute the proven values (as integers)
    1. if s >= 3^D or a >= 3^D:
    2.     raise InvalidAmount
    3. v1 = c - s          // post-spend balance
    4. if v1 < 0:
    5.     raise InvalidAmount
    6. v2 = c + a          // topped-up balance
    7. if v2 >= 3^D:
    8.     raise InvalidAmount

    // Randomize the signature
    9. r1, r2 <- Zq
   10. B = G.Generator() + H1 * c + H2 * k + H3 * r + H4 * ctx
   11. A' = A * (r1 * r2)
   12. B_bar = B * r1
   13. r3 = 1/r1

    // Decompose v1 and v2 into base-3 digits and create commitments
   14. (d1[0], ..., d1[D-1]) = TritDecompose(v1)
   15. (d2[0], ..., d2[D-1]) = TritDecompose(v2)
   16. For j = 0 to D-1:
   17.     s1[j] <- Zq
   18.     Com1[j] = H1 * d1[j] + H3 * s1[j]
   19.     s2[j] <- Zq
   20.     Com2[j] = H1 * d2[j] + H3 * s2[j]

    // Create auxiliary commitments for the range proofs
   21. For j = 0 to D-1:
   22.     rho1[j] <- Zq
   23.     T1[j] = Com1[j] * (d1[j] - 1) + H3 * rho1[j]
   24.     rho2[j] <- Zq
   25.     T2[j] = Com2[j] * (d2[j] - 1) + H3 * rho2[j]

    // Commit to the new token's nullifier
   26. kstar, rn <- Zq
   27. K_n = H2 * kstar + H3 * rn

    // Compute derived public values
   28. A_bar = B_bar * r2 - A' * e  // Equivalent to A' * sk
   29. H1_prime = G.Generator() + H2 * k + H4 * ctx

    // Build LinearRelation statement
   30. statement = LinearRelation(group)

    // Eq 1: A_bar = e*(-A') + r2*B_bar
    // (Rearranged BBS signature validity)
   31. e_var, r2_var = statement.allocate_scalars(2)
   32. negA_var, B_bar_var, A_bar_var = statement.allocate_elements(3)
   33. statement.append_equation(A_bar_var,
         [(e_var, negA_var), (r2_var, B_bar_var)])
   34. statement.set_elements([(negA_var, -A'),
         (B_bar_var, B_bar), (A_bar_var, A_bar)])

    // Eq 2: H1_prime = r3*B_bar + c*(-H1) + r*(-H3)
    // (Credential structure)
   35. r3_var, c_var, r_var = statement.allocate_scalars(3)
   36. negH1_var, negH3_var, H1p_var = statement.allocate_elements(3)
   37. statement.append_equation(H1p_var,
         [(r3_var, B_bar_var), (c_var, negH1_var), (r_var, negH3_var)])
   38. statement.set_elements([(negH1_var, -H1),
         (negH3_var, -H3), (H1p_var, H1_prime)])

    // Shared generator element variables
   39. H1_var, H2_var, H3_var = statement.allocate_elements(3)
   40. statement.set_elements([(H1_var, H1), (H2_var, H2),
         (H3_var, H3)])

    // Eqs 3..2+3D: Range proof over v1 (3D equations)
   41. (d1_vars, s1_vars, rho1_vars, w1_vars) =
         append_range_proof(statement, H1_var, H3_var, Com1, T1, D)

    // Eqs 3+3D..2+6D: Range proof over v2 (3D equations)
   42. (d2_vars, s2_vars, rho2_vars, w2_vars) =
         append_range_proof(statement, H1_var, H3_var, Com2, T2, D)

    // Eq 6D+3: Nullifier commitment opening
    // K_n = kstar*H2 + rn*H3
   43. kstar_var, rn_var = statement.allocate_scalars(2)
   44. Kn_var = statement.allocate_elements(1)
   45. statement.set_elements([(Kn_var, K_n)])
   46. statement.append_equation(Kn_var,
         [(kstar_var, H2_var), (rn_var, H3_var)])

    // Eqs 6D+4, 6D+5: Commitment consistency, tying both
    // decompositions to the same hidden balance c:
    //   Com_total1 = c*H1 + sum(s1[j]*3^j*H3)   (v1 = c - s)
    //   Com_total2 = c*H1 + sum(s2[j]*3^j*H3)   (v2 = c + a)
    // The 3^j coefficient elements are shared between the two
    // equations; the 3^0 = 1 coefficient element is H3_var itself.
   47. Com_total1 = H1 * s + Sum(Com1[j] * 3^j for j in [D])
   48. Com_total2 = H1 * (-a) + Sum(Com2[j] * 3^j for j in [D])
   49. CT1_var, CT2_var = statement.allocate_elements(2)
   50. statement.set_elements([(CT1_var, Com_total1),
         (CT2_var, Com_total2)])
   51. coeff_vars[0] = H3_var
   52. For j = 1 to D-1:
   53.     coeff_vars[j] = statement.allocate_elements(1)
   54.     statement.set_elements([(coeff_vars[j], H3 * (3^j))])
   55. statement.append_equation(CT1_var, [(c_var, H1_var)]
         + [(s1_vars[j], coeff_vars[j]) for j in [D]])
   56. statement.append_equation(CT2_var, [(c_var, H1_var)]
         + [(s2_vars[j], coeff_vars[j]) for j in [D]])

    // Assemble witness (indexed by allocated scalar variables)
   57. witness[e_var] = e
   58. witness[r2_var] = r2
   59. witness[r3_var] = r3
   60. witness[c_var] = c
   61. witness[r_var] = r
   62. For j = 0 to D-1:
   63.     witness[d1_vars[j]] = d1[j]
   64.     witness[s1_vars[j]] = s1[j]
   65.     witness[rho1_vars[j]] = rho1[j]
   66.     witness[w1_vars[j]] = (2 - d1[j]) * ((d1[j] - 1) * s1[j] + rho1[j])
   67. For j = 0 to D-1:
   68.     witness[d2_vars[j]] = d2[j]
   69.     witness[s2_vars[j]] = s2[j]
   70.     witness[rho2_vars[j]] = rho2[j]
   71.     witness[w2_vars[j]] = (2 - d2[j]) * ((d2[j] - 1) * s2[j] + rho2[j])
   72. witness[kstar_var] = kstar
   73. witness[rn_var] = rn

    // Generate non-interactive proof.
    // The public amounts s and a are each constrained by their own
    // consistency equation and also bound into the session
    // identifier.
   74. session_id = domain_separator + "spend" + Encode(k) + Encode(s)
         + Encode(a) + Encode(ctx)
   75. prover = NISigmaProtocol(session_id, statement)
   76. pok = prover.prove(witness, rng)

    // Construct output. The state carries the post-spend balance
    // v1; the return amount t added at refund time (which includes
    // any top-up grant) completes the new balance v1 + t.
   77. r_star = rn + sum(s1[j] * 3^j for j in [D])
   78. proof = (k, s, a, ctx, A', B_bar, Com1, T1, Com2, T2, K_n, pok)
   79. state = (kstar, r_star, v1, ctx)
   80. return (proof, state)
~~~

### Issuer: Spend Verification and Refund

~~~
VerifyAndRefund(sk, proof, t, rng):
  Input:
    - sk: Issuer's private key
    - proof: Client's spend proof
    - t: Return amount (0 <= t <= s + a); t = a grants exactly the
      authorized top-up, t < a claws part of it back, t > a also
      refunds part of the spent amount
    - rng: PRNG.
  Output:
    - refund: Refund for remaining credits
  Exceptions:
    - DoubleSpendError: raised when the nullifier has been used before
    - IdentityPointError: raised when A' is the identity (see VerifySpendProof)
    - InvalidClientSpendProof: raised when the spend proof verification fails
    - ScalarOutOfRangeError: raised when s or a does not decode as a credit
      amount (see ScalarToCredit)
    - InvalidAmount: raised when s or a is not a valid credit amount
      in [0, 3^D)
    - InvalidRefundAmount: raised when t > s + a

  Steps:
    1. Parse proof and extract nullifier k, spend amount s,
       top-up amount a, and ctx
    // Validate the public amounts as integers; ScalarToCredit
    // raises on out-of-range scalars. These checks are REQUIRED
    // for soundness (see the Amount Validation and Modular
    // Wraparound security considerations).
    2. s = ScalarToCredit(s); a = ScalarToCredit(a)
    3. if s >= 3^D or a >= 3^D:
    4.     raise InvalidAmount
    // Apply application policy to authorize the top-up; issuers
    // that do not support top-ups MUST reject proofs with a != 0.
    // Validate the return amount
    5. if t > s + a:
    6.     raise InvalidRefundAmount
    // The following steps (7-15) MUST be performed as a single
    // atomic transaction: the nullifier check, proof verification,
    // nullifier recording, and refund issuance either all commit or
    // all roll back. This prevents double-spending via race
    // conditions and ensures a recorded nullifier always has a
    // retrievable refund (see the State Management Requirements).
    7. // Check nullifier hasn't been used
    8. if k in used_nullifiers:
    9.     raise DoubleSpendError
    // Verify the proof; raises IdentityPointError or
    // InvalidClientSpendProof on failure (see VerifySpendProof)
   10. VerifySpendProof(sk, proof)
   11. // Record nullifier
   12. used_nullifiers.add(k)
   13. // Issue refund for the post-spend balance plus the return
   14. K' = K_n + Sum(Com1[j] * 3^j for j in [D])
   15. refund = IssueRefund(sk, K', t, ctx, rng)
   16. return refund
~~~

### Refund Issuance {#refund-issuance}

After verifying a spend proof, the issuer creates a refund token for
the remaining balance. The commitment `K'` commits to the post-spend
balance `v1 = c - s` and the new nullifier; the issuer adds the
return amount `t` homomorphically. The addition is safe without a
range proof over the result because `v1 + t <= c + a`, which the
spend proof showed is below `3^D`:

~~~
IssueRefund(sk, K', t, ctx, rng):
  Input:
    - sk: Issuer's private key
    - K': Commitment to the post-spend balance and new nullifier
    - t: Return amount
    - ctx: Request context scalar
    - rng: PRNG.
  Output:
    - refund: Refund response

  Steps:
    // Create new BBS signature on the new balance
    1. e <- Zq
    2. X_A = G.Generator() + K' + H1 * t + H4 * ctx
    3. A = X_A * (1/(e + sk))
    4. X_G = G.Generator() * (e + sk)

    // Generate proof of knowledge of (e + sk) such that X_A = A * (e + sk) and X_G = G.Generator() * (e + sk)
    5. statement = LinearRelation(group)
    6. append_dleq(statement, A, G.Generator(), X_A, X_G)
    7. session_id = domain_separator + "refund" + Encode(e) + Encode(t) + Encode(ctx)
    8. prover = NISigmaProtocol(session_id, statement)
    9. witness = [e + sk]
   10. pok = prover.prove(witness, rng)
   11. refund = (A, e, t, pok)
   12. return refund
~~~

### Client: Refund Token Construction

The client verifies the refund and constructs a new credit token:

~~~
ConstructRefundToken(pk, spend_proof, refund, state):
  Input:
    - pk: Issuer's public key
    - spend_proof: The spend proof sent to issuer
    - refund: Issuer's refund response
    - state: Client state (k*, r*, v1, ctx)
  Output:
    - token: New credit token or INVALID
  Exceptions:
    - InvalidRefundProof: When the refund proof verification fails
    - InvalidRefundAmount: When t > s + a or v1 + t is not in
      [0, 3^D)

  Steps:
    1. Parse refund as (A, e, t, pok)
    2. Parse state as (k*, r*, v1, ctx)

    // Validate the return amount against the spend proof's public
    // amounts
    3. if t > spend_proof.s + spend_proof.a:
    4.     raise InvalidRefundAmount

    // Compute new balance
    5. new_balance = v1 + t

    // Validate new balance is a valid credit amount
    6. if new_balance >= 3^D:
    7.     raise InvalidRefundAmount

    // Reconstruct commitment
    8. K' = spend_proof.K_n
         + Sum(spend_proof.Com1[j] * 3^j for j in [D])
    9. X_A = G.Generator() + K' + H1 * t + H4 * ctx
   10. X_G = G.Generator() * e + pk

    // Verify proof of knowledge of (e + sk) such that X_A = A * (e + sk) and X_G = G.Generator() * (e + sk)
   11. statement = LinearRelation(group)
   12. append_dleq(statement, A, G.Generator(), X_A, X_G)
   13. session_id = domain_separator + "refund" + Encode(e) + Encode(t) + Encode(ctx)
   14. verifier = NISigmaProtocol(session_id, statement)
   15. if not verifier.verify(pok):
   16.     raise InvalidRefundProof

   // Construct new token
   17. token = (A, e, k*, r*, new_balance, ctx)
   18. return token
~~~

### Spend Proof Verification {#spend-verification}

The issuer verifies a spend proof as follows:

~~~
VerifySpendProof(sk, proof):
  Input:
    - sk: Issuer's private key
    - proof: Spend proof from client
  Exceptions:
    - IdentityPointError: raised when A' is the identity
    - InvalidClientSpendProof: raised when the proof verification fails

  Steps:
    1. Parse proof as (k, s, a, ctx, A', B_bar, Com1, T1, Com2, T2,
       K_n, pok)

    // Check A' is not identity
    2. if A' == Identity:
    3.     raise IdentityPointError

    // Compute issuer's view
    4. A_bar = A' * sk
    5. H1_prime = G.Generator() + H2 * k + H4 * ctx
    6. Com_total1 = H1 * s + Sum(Com1[j] * 3^j for j in [D])
    7. Com_total2 = H1 * (-a) + Sum(Com2[j] * 3^j for j in [D])

    // Build the same LinearRelation as ProveSpend
    8. statement = LinearRelation(group)

    // Eq 1: A_bar = e*(-A') + r2*B_bar
    9. e_var, r2_var = statement.allocate_scalars(2)
   10. negA_var, B_bar_var, A_bar_var = statement.allocate_elements(3)
   11. statement.append_equation(A_bar_var,
         [(e_var, negA_var), (r2_var, B_bar_var)])
   12. statement.set_elements([(negA_var, -A'),
         (B_bar_var, B_bar), (A_bar_var, A_bar)])

    // Eq 2: H1_prime = r3*B_bar + c*(-H1) + r*(-H3)
   13. r3_var, c_var, r_var = statement.allocate_scalars(3)
   14. negH1_var, negH3_var, H1p_var = statement.allocate_elements(3)
   15. statement.append_equation(H1p_var,
         [(r3_var, B_bar_var), (c_var, negH1_var), (r_var, negH3_var)])
   16. statement.set_elements([(negH1_var, -H1),
         (negH3_var, -H3), (H1p_var, H1_prime)])

    // Shared generator element variables
   17. H1_var, H2_var, H3_var = statement.allocate_elements(3)
   18. statement.set_elements([(H1_var, H1), (H2_var, H2),
         (H3_var, H3)])

    // Eqs 3..2+3D: Range proof over v1 (3D equations)
   19. (d1_vars, s1_vars, rho1_vars, w1_vars) =
         append_range_proof(statement, H1_var, H3_var, Com1, T1, D)

    // Eqs 3+3D..2+6D: Range proof over v2 (3D equations)
   20. (d2_vars, s2_vars, rho2_vars, w2_vars) =
         append_range_proof(statement, H1_var, H3_var, Com2, T2, D)

    // Eq 6D+3: Nullifier commitment opening
   21. kstar_var, rn_var = statement.allocate_scalars(2)
   22. Kn_var = statement.allocate_elements(1)
   23. statement.set_elements([(Kn_var, K_n)])
   24. statement.append_equation(Kn_var,
         [(kstar_var, H2_var), (rn_var, H3_var)])

    // Eqs 6D+4, 6D+5: Commitment consistency
    // The 3^j coefficient elements are shared between the two
    // equations; the 3^0 = 1 coefficient element is H3_var itself.
   25. CT1_var, CT2_var = statement.allocate_elements(2)
   26. statement.set_elements([(CT1_var, Com_total1),
         (CT2_var, Com_total2)])
   27. coeff_vars[0] = H3_var
   28. For j = 1 to D-1:
   29.     coeff_vars[j] = statement.allocate_elements(1)
   30.     statement.set_elements([(coeff_vars[j], H3 * (3^j))])
   31. statement.append_equation(CT1_var, [(c_var, H1_var)]
         + [(s1_vars[j], coeff_vars[j]) for j in [D]])
   32. statement.append_equation(CT2_var, [(c_var, H1_var)]
         + [(s2_vars[j], coeff_vars[j]) for j in [D]])

    // Verify non-interactive proof
   33. session_id = domain_separator + "spend" + Encode(k) + Encode(s)
         + Encode(a) + Encode(ctx)
   34. verifier = NISigmaProtocol(session_id, statement)
   35. if not verifier.verify(pok):
   36.     raise InvalidClientSpendProof
~~~


## Cryptographic Primitives

### Encoding Functions

Elements and scalars are encoded using the suite-specific serialization
functions. For the ACT(ristretto255, SHAKE128) suite ({{suites}}):

~~~
Encode(value):
  Input:
    - value: Element or Scalar
  Output:
    - encoding: ByteString

  Steps:
    1. If value is an Element:
    2.     return SerializeElement(value)  // Ne bytes
    3. If value is a Scalar:
    4.     return SerializeScalar(value)   // Ns bytes
~~~

In expressions such as `session_id = domain_separator + "spend" + Encode(k)`,
string literals are ASCII byte strings and `+` denotes raw byte concatenation.

### Ternary Decomposition {#ternary-decomposition}

To decompose a value into its base-3 representation, the following
algorithm performs D rounds of short division by 3 over the 32-byte
little-endian scalar encoding. The quotient in each step is computed
with a multiply-and-shift instead of a division instruction, so the
algorithm contains no data-dependent branches, divisions, or table
lookups and runs in constant time for a fixed D:

~~~
TritDecompose(v):
  Input:
    - v: Scalar value (an integer in [0, 3^D))
  Output:
    - digits: Array of D scalars (each 0, 1, or 2)

  Steps:
    1. bytes = v.to_bytes_le()  // 32 bytes, little-endian
    2. For j = 0 to D-1:
    3.     r = 0
    4.     For i = 31 down to 0:
    5.         acc = r * 256 + bytes[i]  // 0 <= acc < 768
    6.         q = (acc * 683) >> 11     // floor(acc / 3)
    7.         bytes[i] = q
    8.         r = acc - 3 * q           // acc mod 3
    9.     digits[j] = Scalar(r)
   10. return digits
~~~

Note: This algorithm produces digits in least-significant-first
order (i.e., `digits[0]` is the least significant base-3 digit).
Each round divides the running value by 3 and outputs the remainder.
The identity `(acc * 683) >> 11` computes `floor(acc / 3)` exactly
for all `0 <= acc < 2048`, which covers the maximum intermediate
value `2 * 256 + 255 = 767`. The algorithm works for any
D <= MAX_DIGITS, as the scalar is represented in 32 bytes
(256 bits), which accommodates the full range of the Ristretto
group order.

### Scalar Conversion

Converting between credit amounts and scalars:

~~~
CreditToScalar(amount):
  Input:
    - amount: Integer credit amount (0 <= amount < 3^D)
  Output:
    - s: Scalar representation
  Exceptions:
    - AmountTooBigError: raised when the amount is not below 3^D

  Steps:
    1. if amount >= 3^D:
    2.     raise AmountTooBigError
    3. return Scalar(amount)

ScalarToCredit(s):
  Input:
    - s: Scalar value
  Output:
    - amount: Integer credit amount
  Exceptions:
    - ScalarOutOfRangeError: raised when the bytes 16..32 of the scalar value are nonzero

  Steps:
    1. bytes = s.to_bytes_le()
    2. // Check high bytes are zero
    3. For i = 16 to 31:
    4.     if bytes[i] != 0:
    5.         raise ScalarOutOfRangeError
    6. amount = bytes[0..15] as u128
    7. return amount
~~~

Note that ScalarToCredit raises ScalarOutOfRangeError rather than
returning it as a value; callers such as VerifyAndRefund rely on this
control flow to reject out-of-range public amounts, which is required
for soundness (see {{wraparound}}).

All valid credit amounts satisfy `amount < 3^D <= 3^MAX_DIGITS < 2^127`,
so they are representable in the 128-bit integer returned by
ScalarToCredit.

# Protocol Messages and Wire Format

## Message Encoding

All protocol messages are encoded using the TLS presentation language
from {{Section 3 of !TLS13=RFC8446}}. The following sections define the
structure of each message type.

### Issuance Request Message

~~~
struct {
    opaque K[Ne];         /* Compressed Ristretto point, Ne bytes */
    opaque pok<1..2^16-1>; /* NISigmaProtocol proof */
} IssuanceRequestMsg;
~~~

### Issuance Response Message

~~~
struct {
    opaque A[Ne];         /* Compressed Ristretto point, Ne bytes */
    opaque e[Ns];         /* Scalar, Ns bytes */
    opaque c[Ns];         /* Scalar, Ns bytes */
    opaque pok<1..2^16-1>; /* NISigmaProtocol proof */
} IssuanceResponseMsg;
~~~

### Spend Proof Message

~~~
struct {
    opaque k[Ns];           /* Nullifier scalar, Ns bytes */
    opaque s[Ns];           /* Spend amount scalar, Ns bytes */
    opaque a[Ns];           /* Top-up amount scalar, Ns bytes */
    opaque ctx[Ns];         /* Request context scalar, Ns bytes */
    opaque A_prime[Ne];     /* Compressed Ristretto point, Ne bytes */
    opaque B_bar[Ne];       /* Compressed Ristretto point, Ne bytes */
    opaque Com1[D][Ne];     /* D compressed Ristretto points, D*Ne bytes */
    opaque T1[D][Ne];       /* D compressed Ristretto points, D*Ne bytes */
    opaque Com2[D][Ne];     /* D compressed Ristretto points, D*Ne bytes */
    opaque T2[D][Ne];       /* D compressed Ristretto points, D*Ne bytes */
    opaque K_n[Ne];         /* Compressed Ristretto point, Ne bytes */
    opaque pok<1..2^16-1>; /* NISigmaProtocol proof */
} SpendProofMsg;
~~~

### Refund Message

~~~
struct {
    opaque A_star[Ne];    /* Compressed Ristretto point, Ne bytes */
    opaque e_star[Ns];    /* Scalar, Ns bytes */
    opaque t[Ns];         /* Return amount scalar, Ns bytes */
    opaque pok<1..2^16-1>; /* NISigmaProtocol proof */
} RefundMsg;
~~~

### Error Response

~~~
struct {
    uint16 error_code;
    opaque error_message<0..2^16-1>;
} ErrorMsg;
~~~

Error codes are defined in {{error-codes}}.

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
   - Service creates a BBS signature on the blinded commitment K (which
     binds the credit amount, nullifier, and blinding factor) and returns it
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

4. **Top-Up**: Alice's balance is down to 60, so she buys 500 more
   credits
   - Alice pays out-of-band; the purchase is bound to the request
     context ctx
   - Her next spend proof declares a top-up amount a = 500 alongside
     the spend amount s = 50 (which her balance of 60 covers)
   - The service authorizes the top-up by verifying the proof with
     a = 500 and setting the return amount t = 500
   - The refund token contains her previous balance plus 450 credits
     (500 purchased minus 50 spent); the service does not learn the
     resulting balance. Had the out-of-band payment failed, the
     service could instead have set any t down to 0, clawing back
     the top-up while keeping the charge

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
   with a small false-positive rate.

## Constant-Time Operations

To prevent timing attacks, implementations MUST use constant-time
scalar arithmetic and point operations. See the timing attack
mitigations in the Security Considerations for detailed requirements.

## Randomness Generation

All randomness is provided through the PRNG interface
(see {{prng-appendix}}). The PRNG is used for private key generation,
blinding factors, and proof randomness. See {{prng-appendix}} for
the interface definition and requirements.

## Point Validation

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

All implementations MUST validate points at these locations:

- When receiving `K` in issuance request
- When receiving `A` in issuance response
- When receiving `A'` and `B_bar` in spend proof
- When receiving `Com1[j]`, `T1[j]`, `Com2[j]`, `T2[j]`, and `K_n`
  commitments in spend proof
- When receiving `A*` in refund response

## Error Handling

Implementations SHOULD NOT provide detailed error messages that could leak
information about the verification process. A single INVALID response should be
returned for all verification failures.

### Error Codes {#error-codes}

While detailed error messages should not be exposed to untrusted parties,
implementations MAY use the following internal error codes:

- `INVALID_PROOF`: Proof verification failed
- `NULLIFIER_REUSE`: Double-spend attempt detected
- `MALFORMED_REQUEST`: Request format is invalid
- `INVALID_AMOUNT`: Credit amount exceeds maximum (3^D - 1)

## Parameter Selection

The digit count D determines the range of credit values
(0 to 3^D - 1). Implementations MUST enforce D <= MAX_DIGITS to
ensure amounts fit the credit encoding and to preserve the soundness
margin described in {{wraparound}}. Larger D supports higher credit
values but increases proof size and verification time linearly.

### Performance Characteristics

The spending proof uses a single `LinearRelation` with `6D + 5` equations
and a witness of `8D + 7` scalars. The `NISigmaProtocol` interface
handles all proof generation and verification.

- **Sizes**:

| Component | Size | ristretto255 (Ne=Ns=32) |
|-----------|------|-------------------------|
| Issuance request | Ne + 3\*Ns + 2 | 130 bytes |
| Issuance response | Ne + 4\*Ns + 2 | 162 bytes |
| Spend proof | (4D+3)\*Ne + (8D+12)\*Ns + 2 | 384D + 482 bytes |
| Refund | Ne + 4\*Ns + 2 | 162 bytes |
| Token (client storage) | Ne + 5\*Ns | 192 bytes |
| Nullifier (server storage) | Ns | 32 bytes |

Each `pok` field encodes a challenge scalar and the response scalars
from `NISigmaProtocol`, prefixed by a 2-byte length field.
The issuance request proof has 2 witness scalars (3\*Ns),
the issuance response and refund proofs have 1 witness scalar (2\*Ns),
and the spend proof has `8D + 7` witness scalars ((8D+8)\*Ns).

### Choice of Radix {#radix}

In this proof framework, a base-B digit costs `B - 1` group elements
(the digit commitment plus `B - 2` auxiliary commitments) and
`B + 1` witness scalars per digit, while covering `log2(B)` bits of
range. With Ne = Ns = 32 the marginal proof size is therefore
`64*B / log2(B)` bytes per bit of range: 128 for base 2, 121.1 for
base 3, 128 for base 4 (an exact tie with base 2), and increasing
for every larger base. Base 3 minimizes this cost; a ternary spend
proof is approximately 5% smaller than the equivalent binary one.
This specification therefore uses base-3 digits. See
{{ternary-decomposition}} for a constant-time decomposition
algorithm.

A compact B-way OR proof of the digit relation has the same
marginal cost: one instance element plus `2*B - 1` proof scalars
per digit, or `32 + 32*(2*B - 1) = 64*B` bytes. The choice between
the linear encoding used here and a disjunctive presentation
therefore does not affect proof size, and base 3 remains optimal
under either.

# Suites for ACT {#suites}

A suite for ACT specifies the parameters used to implement the
functionality required for the protocol to take place.
The suite should be available to both the client and server,
and agreement on the specific instantiation is assumed throughout.

A suite contains instantiations of the following functionalities:

- Group: A prime-order group exposing the interface detailed
in {{Section 2.1 of !RFC9497}}.
For the HashToGroup function, the domain separation tag (DST) is
constructed in accordance with the recommendations
in {{Section 3.1 of !RFC9380}}.
- NISigmaProtocol: These are parameters used to implement the
Fiat-Shamir transform in accordance with the recommendations
in {{FIAT-SHAMIR}}.
- PRNG: A cryptographically secure pseudorandom number generator
providing the `random_scalar()` method, backed by a CSPRNG in
accordance with {{FIPS186}}.
- MAX_DIGITS: Specifies the maximum number of base-3 digits allowed
to represent credits. Suites MUST choose MAX_DIGITS such that
`3^MAX_DIGITS + 2^128 <= Order()` (see {{wraparound}}) and
`3^MAX_DIGITS <= 2^127` so that credit amounts fit the integer
encoding of ScalarToCredit.

## ACT(ristretto255, SHAKE128)

The group is ristretto255 as specified in {{!RFC9496}}.
It also specifies the `Order()`, `Identity()`, and `Generator()` functions.

The HashToGroup(msg) function uses hash_to_ristretto255(msg, DST) {{!RFC9380}}
with DST = "HashToGroup-" || domain_separator, and
expand_message = expand_message_xmd using SHA-512.

SerializeElement(A) is the 'Encode' function
from {{Section 4.3.2 of !RFC9496}} producing an array of `Ne=32` bytes.

DeserializeElement(bytes) is the 'Decode' function
from {{Section 4.3.1 of !RFC9496}}.
This function must validate that the input is the valid canonical
byte representation of an element of the group.
This function must raise an error if deserialization fails,
or if the resulting element is the group identity element.

SerializeScalar(s) outputs a `Ns=32` byte array representing the
little-endian encoding of the scalar value with the top three bits
set to zero.

DeserializeScalar(bytes) attempts to deserialize a scalar from a
little-endian 32-byte string.
This function must fail if the input does not represent an integer
between zero and `Order()-1` inclusive.
Note that this means the top three bits of the input MUST be zero.

The NISigmaProtocol interface is implemented by NISchnorrProofShake128Ris255 as follows:

~~~ pseudocode
class Ristretto255Codec(ByteSchnorrCodec):
    GG = ristretto255

class NISchnorrProofShake128Ris255(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = Ristretto255Codec
    DuplexSponge = SHAKE128

    def get_protocol_id():
        return b"ACT-v1_SchnorrProof_Shake128_Ristretto255"
                 .ljust(64, b"\x00")
~~~

where SchnorrProof is defined in {{Section 2.2.7 of SIGMA}},
ByteSchnorrCodec in {{Section 7 of FIAT-SHAMIR}}, and SHAKE128 is the
duplex sponge specified in {{Section 8.1 of FIAT-SHAMIR}}, based on
the extendable-output function defined in {{FIPS202}}. The protocol
identifier (see {{Section 5 of SIGMA}}) is the ASCII string
"ACT-v1_SchnorrProof_Shake128_Ristretto255" padded to 64 bytes with
zero bytes. The session identifiers constructed throughout this
document are passed as the `session` input of NISigmaProtocol.

The PRNG is instantiated as defined in {{prng-appendix}}.

Set `MAX_DIGITS=80`. This is the largest D for which `3^D < 2^127`,
so every valid credit amount is representable in the 128-bit integer
encoding used by ScalarToCredit, and it keeps `3^D + 2^128` far
below the group order, as required by {{wraparound}}.

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

## Cryptographic Assumptions

Security relies on:

1. **The q-SDH Assumption** in the Ristretto255 group. We refer to {{TZ23}} for the formal definition.

2. **Random Oracle Model**: The hash function used by the NISigmaProtocol (SHAKE128 in the ristretto255 suite) is modeled as a random oracle.

## Amount Validation and Modular Wraparound {#wraparound}

The spend proof constrains the proven values `v1 = c - s` and
`v2 = c + a` only modulo the group order q: the range proofs show
that each value, interpreted as an integer, lies in `[0, 3^D)`, but
the relations among c, s, a, v1, and v2 hold in the scalar field.
If the issuer accepted arbitrary scalars as the public amounts s or
a, a malicious client could exploit wraparound to inflate its
balance. For example, with `s = q - 1` (that is, `s = -1 mod q`), a
token holding c credits yields a "post-spend balance" of `c + 1`
that passes the first range proof.

Issuers MUST therefore validate the public amounts before verifying
a spend proof: s and a MUST decode successfully via ScalarToCredit
and MUST be less than `3^D`, and the return amount MUST satisfy
`t <= s + a`, as specified in VerifyAndRefund. In addition, suites
MUST choose MAX_DIGITS such that:

~~~
3^MAX_DIGITS + 2^128 <= Order()
~~~

where `2^128` is the upper bound enforced by ScalarToCredit. Under
these checks, wraparound is impossible. Token balances satisfy
`c < 3^D` by induction: issuance amounts are validated against
`3^D`, and each refund produces a balance
`v1 + t <= v1 + s + a = c + a`, which the second range proof shows
is below `3^D`. Given `c < 3^D` and a validated `s < 3^D`, the
field value `c - s` either equals the integer `c - s` or, when
`s > c`, wraps to `c - s + q >= q - 3^D > 3^D`, which the first
range proof rejects; the proof therefore enforces `s <= c` over
the integers. The field value `c + a` is at most `2*3^D - 2 < q`
and cannot wrap, so the second range proof enforces `c + a < 3^D`
over the integers.

Parameterizations whose range bound approaches the group order
violate this condition. For example, a 252-bit range with amounts
validated only against `2^128` admits a balance-inflation attack
using spend amounts near `q - 2^252`: such amounts pass validation,
and the wrapped remainder falls inside the proven range. The
`MAX_DIGITS = 80` limit of the suite in {{suites}} satisfies the
condition with a margin of more than 120 bits.

## Privacy Limitations

The protocol does NOT provide:

1. **Network-Level Privacy**: IP addresses and network metadata can still link transactions.
2. **Amount Privacy**: The spent amount s and top-up amount a are revealed to the issuer.
3. **Timing Privacy**: Transaction timing patterns could potentially be used for correlation.

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
   - MUST avoid early-exit conditions based on secret values
   - The algebraic range proof eliminates conditional branches on secret
     digit values, reducing the timing attack surface compared to CDS
     OR-proof approaches
   - Critical constant-time operations include:
     * Scalar multiplication and addition
     * Ternary decomposition in range proofs (see
       {{ternary-decomposition}}, which uses fixed iteration counts
       and no division instructions)
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

**Prevention**: Atomic nullifier checking and recording as described in the nullifier database and concurrency mitigations above.

### 2. Balance Inflation Attack
**Scenario**: An attacker attempts to create a proof claiming to have more credits than actually issued by manipulating the range proofs, or by submitting spend or top-up amounts that wrap around the group order.

**Prevention**: The cryptographic soundness of the range proofs, combined with the mandatory amount validation described in {{wraparound}}, prevents this attack.

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
rest of their credits in time. Issuers MAY implement functionality for clients to acknowledge
receipt of the refund, allowing the issuer to delete the refund
record. Alternatively, issuers MAY clean up refund records in bulk
at a specified expiration date.

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

TODO

# PRNG Interface {#prng-appendix}

This appendix defines the abstract PRNG interface used throughout the protocol
and a deterministic `SeededPRNG` construction for test vector generation.

## Abstract Interface

~~~ pseudocode
interface PRNG:
  random_scalar() -> Scalar
    // Returns a uniformly distributed random scalar in [0, q).
    // The implementation MUST draw sufficient entropy (at least 64 bytes)
    // and reduce modulo the group order q.
~~~

In production, the PRNG MUST be backed by a CSPRNG in accordance with
{{FIPS186}}. The `random_scalar()` method draws 64 bytes from the
underlying CSPRNG and reduces modulo the group order to produce a
uniformly distributed scalar.

## SeededPRNG for Test Vectors

For deterministic test vector generation, the following `SeededPRNG`
construction uses SHAKE128 as the underlying stream:

~~~ pseudocode
class SeededPRNG(PRNG):
  state: SHAKE128 instance

  SeededPRNG(seed):
    Input:
      - seed: Byte Array.
    Steps:
      1. self.state = SHAKE128.init()
      2. self.state.absorb(seed)

  random_scalar() -> Scalar:
    Output:
      - s: Scalar.
    Steps:
      1. bytes = self.state.squeeze(64)  // 64 bytes of output
      2. s = from_little_endian_bytes(bytes) mod q
      3. return s
~~~

where SHAKE128 is defined in {{FIPS202}}.

WARNING: `SeededPRNG` MUST NOT be used in production. It is provided solely
for generating reproducible test vectors. Production implementations MUST
use OS-provided entropy sources.

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

**Refund**: The response issued for the remaining balance after a spend, including the issuer-chosen return amount added to the post-spend balance.

**Credit**: A numerical unit of authorization that can be spent by clients.

**Domain Separator**: A unique string used to ensure cryptographic isolation between different deployments.

**Element**: A point in the Ristretto255 elliptic curve group.

**Issuer**: The entity that creates and signs credit tokens.

**Nullifier**: A unique value revealed during spending that prevents double-spending of the same token.

**Partial Spending**: The ability to spend less than the full value of a token and receive change.

**Top-Up**: An issuer-authorized amount added to a token's balance during a spend, bound as a public value in the spend proof.

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
