# Security Model — PU-CP-ABE

## 1. Overview

The scheme is proved secure under **Indistinguishability under Selective Chosen Plaintext Attack (IND-sCPA)**. This document covers:
1. The formal security game (as in the paper)
2. How hybrid encryption preserves the security guarantee
3. Practical security properties of the AWS deployment

---

## 2. Security of the Hybrid Construction

The paper's scheme proves security for `ABE.Enc(M, mpk, T)` with M ∈ G_T. In this implementation, ABE encrypts a random K ∈ G_T and the data key is derived from it:

```
CT_ABE = ABE.Enc(K, mpk, T)          K ←$ G_T
DEK    = SHA-256(K)
C_AES  = AES-GCM.Enc(M, DEK, AAD = object_id)
```

**Claim:** If ABE is IND-sCPA secure and AES-256-GCM is IND-CPA secure, then the hybrid construction is IND-sCPA secure.

**Intuition:** An adversary who can distinguish encryptions of `M_0` vs `M_1` under the hybrid scheme must either:
- Distinguish `C_AES = AES-GCM.Enc(M_b, DEK)` without knowing DEK (breaks AES-GCM IND-CPA), **or**
- Recover DEK from `CT_ABE = ABE.Enc(DEK, mpk, T)` (breaks ABE IND-sCPA)

Both are assumed computationally infeasible. Therefore breaking the hybrid scheme is at least as hard as breaking either component.

---

## 3. Participants and Trust Assumptions

| Party | Role | Trust Level |
|---|---|---|
| **Trusted Authority (TA)** | Runs `Setup()` and `KeyGen()` locally | Fully trusted; never colludes |
| **Data Owner** | Chooses policy T; runs `Enc()` and `UPKeyGen()` locally; keeps `E_T`; uploads ciphertexts and `tk` | Honest |
| **Cloud Server (Lambda)** | Runs `CTUpdate()` only; stores ciphertexts | **Honest-but-curious** |
| **Data User** | Holds `sk_A`; runs `Dec()` locally | Potentially adversarial |

**Critical isolation — enforced by code, not just policy:**
- Lambda never has access to `msk` (not stored in S3 or anywhere in AWS)
- Lambda never has access to `E_T` or the plaintext (the owner encrypts locally; `E_T` is written to the owner's `owner_secrets/` and never uploaded)
- Lambda receives `tk` only for the specific update, and `tk` reveals nothing about DEK or M
- `sk_A` is delivered to users out-of-band, never via S3

---

## 4. Formal Security Game (IND-sCPA)

The game is played between **challenger C** and a **PPT adversary A**.

### 4.1 Game Phases

```
Phase 0 — Initialization
  A commits to a challenge access tree T* before any public parameters are revealed.
  This is the "selective" part of IND-sCPA.

Phase 1 — Setup
  C runs Setup(λ, U) → (mpk, msk).
  C sends mpk to A; keeps msk secret.

Phase 2 — Query Phase 1  (adaptive queries)
  A may request private keys sk_{A_i} for any A_i that does NOT satisfy T*.
  C returns KeyGen(mpk, msk, A_i).

Phase 3 — Challenge
  A outputs two equal-length plaintexts M_0, M_1.
  In this implementation ABE encapsulates a G_T element: A outputs K_0, K_1 ∈ G_T
  (the DEK is derived as SHA-256(K)).
  C samples b ←$ {0,1}, returns CT_ABE* = ABE.Enc(K_b, mpk, T*).

Phase 4 — Query Phase 2  (continued)
  A continues querying:
    - Private keys sk_A  (same restriction: A ⊭ T*)
    - Update keys tk_{T_j → T'_j}  where T_j ≠ T*
    - CTUpdate queries for any ct ≠ CT_ABE*

Phase 5 — Guess
  A outputs b' ∈ {0,1}.
  A wins if b' = b.
```

### 4.2 Advantage

```
Adv^{IND-sCPA}_{PU-CP-ABE}(A) = |Pr[b' = b] - 1/2|
```

The scheme is IND-sCPA secure if this advantage is negligible in λ for all PPT adversaries A.

---

## 5. Hardness Assumption — Decisional q-BDHE

Security reduces to the **decisional q-Bilinear Diffie-Hellman Exponent** problem (Boneh, Boyen, Goh 2005).

**Problem:** Given `(g, h, g^α, g^{α²}, …, g^{α^q}, g^{α^{q+2}}, …, g^{α^{2q}})` in G, and a challenge `Z ∈ GT`, decide whether `Z = e(g^{α^{q+1}}, h)` or `Z` is uniform in `GT`.

The reduction embeds the BDHE challenge into `mpk` and simulates all key/update queries for A without knowing α, by choosing polynomials and random values that cancel the unknown term in unsatisfied subtrees.

In **charm-crypto with SS512 pairing**, the BDHE assumption holds at approximately 80-bit security. For stronger guarantees, switch to `MNT224` (Type D) or `BN256` curves.

---

## 6. Policy Update Security

### 6.1 Ciphertext Indistinguishability After Update

```
Dec(sk_A, CTUpdate(CT_ABE, tk_{T→T'})) = Dec(sk_A, ABE.Enc(DEK, mpk, T'))
```

for all A satisfying T'. The updated ciphertext `CT_ABE'` is computationally indistinguishable from a fresh encryption under T'.

### 6.2 What the Cloud Learns from tk

The update token `tk` consists of group elements derived from `s_j` (from `E_T`) and the new/old attribute sets. The cloud computes `CTUpdate` using only `tk` and `mpk`. It gains:
- No information about `msk` or `α`
- No information about `s_j` (the random scalar from `E_T`) — only a masked version
- No information about DEK or M

### 6.3 Query Restrictions

| Query | Restriction |
|---|---|
| `KeyGen(A)` | A must not satisfy T* |
| `UPKeyGen(T_j, T'_j)` | T_j ≠ T* |
| `CTUpdate(ct, tk)` | ct ≠ CT_ABE* |

---

## 7. Collusion Resistance

Multiple users with attribute sets `A_1, A_2, …` cannot combine their keys to decrypt a ciphertext whose policy is not satisfied by any individual `A_i`.

**Mechanism:** Each `sk_A` is bound to a fresh random `r ←$ Z_p` during `KeyGen`. The Lagrange interpolation inside `Dec()` depends on `r` being consistent across all key components. Mixing components from two keys (with different `r_1`, `r_2`) causes the interpolation to produce a wrong result in GT, yielding a random element rather than `e(g1,g2)^{s_r}`.

```python
# Collusion attempt: attacker mixes sk_{A1}['attrs'] and sk_{A2}['attrs']
# Both contribute to Lagrange sum P_j1:
P_j1 = prod(sk_A1['attrs'][i]['sk0']**delta_i for i in some_attrs)
      * prod(sk_A2['attrs'][k]['sk0']**delta_k for k in other_attrs)
# = (g2 h0 h_i)^{r1·q(i)·delta_i} · (g2 h0 h_k)^{r2·q(k)·delta_k}
# ≠ (g2 h0 …)^{rα}  since r1 ≠ r2
# Decryption fails — random GT element obtained
```

---

## 8. AWS Deployment Security Properties

### 8.1 What Lambda Can and Cannot Do

```
Lambda CAN:                          Lambda CANNOT:
──────────────────────────────────   ──────────────────────────────────
Read mpk from S3 config/             Read msk (not in AWS at all)
Run CTUpdate(CT_ABE, tk)             Run Enc() — sees no plaintext or DEK
Read/write S3 objects/               Run KeyGen() (no msk)
Read/delete tk in S3 updates/        Decrypt CT_ABE (no sk_A)
                                     Read E_T (never uploaded)
```

`msk.json`, user key files and `E_T_v*.json` are never in S3 and therefore unreachable by any AWS service.

### 8.2 Threat Model Summary

```
Threat                              Mitigation
──────────────────────────────────────────────────────────────────────
Cloud reads CT_ABE                  IND-sCPA secure; requires sk_A satisfying T
Cloud executes CTUpdate             tk reveals no DEK/msk; correctness by structure
Cloud reads C_AES                   AES-256-GCM; requires DEK from CT_ABE first
User colludes with other users      Fresh r per key; Lagrange interpolation fails
Adversary queries update tokens     Restricted to T_j ≠ T* in security game
Lambda role escalation              IAM denies all non-listed S3 paths; no EC2/IAM APIs
Docker image tampered               Use ECR image signing + Lambda code signing
Cold-start timing side-channel      Provisioned Concurrency eliminates variable latency
```

### 8.4 Data in Transit and at Rest

- All S3 transfers: HTTPS (TLS 1.2+); S3 SSE-S3 or SSE-KMS for at-rest encryption
- Lambda ↔ S3: VPC endpoint recommended (no public internet path)
- `sk_A` delivery: must use an out-of-band secure channel (e.g., SFTP, encrypted email) — **never S3**
- CloudTrail enabled for full audit of all S3 and Lambda API calls

---

## 9. Implementation-Level Guarantees (checked by `tests/test_security.py`)

The previous PoC broke several of the assumptions above in code. Each is now a regression test:

| Requirement | Previous PoC | Now | Test |
|---|---|---|---|
| `E_T` stays with the owner | `CT["_debug"]["s_map"]` uploaded with the ciphertext — anyone could compute `K = C0 / Z^{s_r}` | `Enc` returns `(CT, E_T)`; CT contains no Z_p element | `test_cloud_store_contains_no_E_T`, `test_plaintext_not_recoverable_from_public_data` |
| `sk_A` reveals nothing about `msk` | `SK["_meta"] = {r, alpha}` | removed | `test_user_key_has_no_master_secret` |
| `sk_A` covers only `A ∪ U'` | components for every index 1..4ℓ; access enforced only by a CLI flag | components for `ρ(A) ∪ U'` only; `A` read from the key | `test_user_key_covers_only_A_and_defaults`, `test_cannot_claim_attributes_not_in_key` |
| ρ is a system-wide mapping | derived per policy (same name → different index) | fixed at Setup, in mpk | `test_rho_is_global` |
| Cloud holds mpk only | cloud scripts loaded `ta_setup.json` (mpk + msk) | separate `mpk.json` / `msk.json`; loaders reject msk | `test_non_authority_roles_refuse_msk` |
| Policy update replaces the ciphertext | old versions kept and readable | vN deleted after CTUpdate (opt-in history) | `test_old_version_replaced_by_default` |
| Integrity of C_AES | — | AES-GCM tag, AAD = object_id | `test_tampered_c_aes_detected` |
