# Algorithm Overview — PU-CP-ABE Hybrid Implementation

All scheme algorithms live in `crypto/abe_core.py`; every role imports the same module.
This document maps each algorithm in the paper (Sec. III–IV) to the code, the role that runs it,
and the data it is allowed to see.

| Paper algorithm | Code | Run by | Inputs it sees |
|---|---|---|---|
| Setup(λ, U) → (mpk, msk) | `PUCPABE.setup(universe)` via `ta_local.py setup` | Authority | — |
| KeyGen(mpk, msk, A) → sk_A | `PUCPABE.keygen(msk, mpk, attrs)` via `ta_local.py keygen` | Authority | msk |
| Enc(M, mpk, T) → (ct_T, E_T) | `PUCPABE.encrypt(K, mpk, policy)` via `owner_encrypt.py` | Data owner | plaintext, E_T |
| Dec(mpk, sk_A, ct_T) → M | `PUCPABE.decrypt(mpk, sk, CT)` via `client_decrypt.py` | Data user | own sk_A |
| UPKeyGen(mpk, E_T, T, T′) → tk | `UPKeyGen(abe, mpk, E_T, tree, new_policy)` via `owner_upkeygen.py` | Data owner | E_T |
| CTUpdate(mpk, ct_T, tk) → ct_T′ | `CTUpdate(CT, tk)` via `cloud_update.py` / `app.py` (Lambda) | Cloud | ct_T, tk |

---

## 0. Hybrid encryption (KEM/DEM)

The scheme encrypts a message in G_T. Files are bytes, so the owner encrypts a random G_T
element K with ABE and the file with AES-256-GCM:

```
K      ←$ G_T
DEK    = SHA-256(serialize(K))
C_AES  = AES-256-GCM(M, DEK, AAD = object_id)        # crypto/hybrid.py
(CT, E_T) = Enc(K, mpk, T)
```

A policy update changes only CT; `C_AES` is copied unchanged into the new version.

---

## 1. Policy language and access tree

```
policy ::= expr
expr   ::= term ("OR" term)*        a chain of n ORs  -> 1-of-n gate
term   ::= atom ("AND" atom)*       a chain of n ANDs -> n-of-n gate
atom   ::= NAME | "(" expr ")" | "(" k "," expr ("," expr)* ")"     k-of-n threshold gate
```

* A bare attribute `attA` becomes the gate `(1, attA)`.
* The same attribute may not appear twice under one gate.
* Unknown characters raise an error (the old tokenizer looped forever on e.g. `-`).

`tree_from_policy()` splits the tree into K subtrees T_j, one per gate (paper Sec. IV-B), and the
**ciphertext stores this structure explicitly**:

```json
"tree": {"root": "Tr",
         "nodes": {"Tr": {"t": 1, "leaves": ["attA"],         "children": ["T1"]},
                   "T1": {"t": 2, "leaves": ["attB", "attC"], "children": []}}}
```

| Field | Paper notation |
|---|---|
| node label (`Tr`, `T1`, …) | subtree T_j, root node s_j |
| `t` | threshold t_j |
| `leaves` | leaf-node set L_j |
| `children` (ordered) | non-leaf node set N_j; the position i gives index 2ℓ − t_j + i |

Decryption and updating read this structure; they never re-derive labels by re-parsing the policy
string, so labels stay stable across updates.

---

## 2. Index layout

```
real attributes   ρ(att) ∈ {1 .. ℓ}         fixed at Setup, published in mpk["rho"]
default attrs U'  {ℓ+1 .. 4ℓ}               given to every user
Ω_j               {ℓ+1 .. 2ℓ − t_j}         (ℓ − t_j default indices)
gate-child i      2ℓ − t_j + i              (1-based position in "children")
h_0 .. h_{4ℓ}     in mpk
```

The paper uses U' = {ℓ+1 .. 2ℓ}; the range is widened to 4ℓ so a gate may have more gate-children
than its threshold. Those indices only ever serve as Ω_j or gate-child indices.

---

## 3. Setup(λ, U) → (mpk, msk)

```
g ∈ G1, g2 ∈ G2, h_0..h_{4ℓ} ∈ G2, α, β, θ ∈ Z_p
g1 = g^α,  v = g^θ,  w = g2^{α/θ}          so that e(g1, g2) = e(v, w)
mpk = (g, g2, v^β, {h_i}, Z = e(g1, g2), ρ)
msk = (α, w^{1/β})
```

`ta_local.py setup` writes **two** files: `mpk.json` (public; optionally published to the cloud store
at `config/mpk.json`) and `msk.json` (Authority only). Every non-Authority loader refuses a file that
contains `msk`.

---

## 4. KeyGen(mpk, msk, A) → sk_A

```
r ←$ Z_p,  q(·) random of degree ℓ−1 with q(0) = α
for t ∈ ρ(A) ∪ U':
    a_t = (g2 h_0 h_t)^{r q(t)}
    b_t = g^{r q(t)}
    c_t = { h_j^{r q(t)} : j ∈ 1..4ℓ, j ≠ t }
d = (w^{1/β})^{r−1} = w^{(r−1)/β}
sk_A = { attrs: A, d, k: {t: (a_t, b_t, c_t)} }
```

The key holds components **only** for the user's own attributes plus U'. It contains neither α nor
h_t^{r q(t)} for its own index t. The attribute set A is part of the key, so the client cannot claim
extra attributes on the command line.

---

## 5. Enc(K, mpk, T) → (ct_T, E_T)

```
E_T = { s_j ←$ Z_p  for each subtree T_j }           (s_r for the root)
for each T_j:
    ct_{j,1} = (h_0 · Π_{i ∈ ρ(L_j) ∪ Ω_j} h_i)^{s_j}
    ct_{j,2} = g^{s_j}
    ct_{j,child k} = h_{2ℓ − t_j + pos(k)}^{s_j} · g2^{s_k}     for each gate-child T_k
ct_{Tr,v} = (v^β)^{s_r}
C0 = K · Z^{s_r}
CT = {scheme, ell, policy, tree, C0, ct_T}
```

`E_T` is returned **separately**. `owner_encrypt.py` writes it to
`owner_secrets/<object_id>/E_T_v1.json` and uploads only `{policy, c_aes, ct_abe}`.

---

## 6. Dec(mpk, sk_A, ct_T) → K

Recursive over the stored tree, bottom-up (paper Sec. IV-B, Dec):

```
for subtree T_j:
    A'_j  = first t_j satisfied leaves (ρ(L_j ∩ A))
    S_j   = satisfied gate-children, enough to reach t_j
    X     = A'_j ∪ {2ℓ − t_j + pos(k) : k ∈ S_j} ∪ Ω_j          |X| = ℓ
    Tset  = ρ(L_j) ∪ {2ℓ − t_j + pos(k)} ∪ Ω_j
    P_{j,1} = Π_{i∈X} (a_i · Π_{t∈Tset, t≠i} c_i[t])^{Δ_{i,X}(0)} = (g2 h_0 Π_{Tset} h)^{rα}
    P_{j,2} = Π_{i∈X} b_i^{Δ_{i,X}(0)}                               = g^{rα}
    D_{j,3,k} = e(P_{k,2}, ct_{j,child k}) / D_{k,1}
    D_{j,1} = e(ct_{j,2}, P_{j,1}) / ( e(P_{j,2}, ct_{j,1}) · Π_k D_{j,3,k} ) = e(g2^{rα}, g^{s_j})
root:  D_{r,2} = e(ct_{Tr,v}, d);   K = C0 · D_{r,2} / D_{r,1}
```

If the root is not satisfied, `PermissionError` is raised (`client_decrypt.py` exits with code 3).

---

## 7. Policy update (paper Sec. IV-C)

### 7.1 Detecting the update — `plan_update(tree, new_policy)`

The owner only supplies the new policy. The code compares it with the stored tree (canonical forms,
child order ignored) and finds the single gate T_j that changes:

| Result | Meaning |
|---|---|
| `Attributes2Existing` | T_j keeps its gate-children; its leaf set and/or threshold change |
| `Attributes2New` | T_j gains exactly one new gate T_t (attributes only); T_j's own leaves/threshold may change too |
| error | no change; more than one gate changed; a gate removed; nested new gate; root-gate update (RootEtOR / RootEtAND / RootEtThreshold — not implemented) |

`--mode` and `--target-subtree` on `owner_upkeygen.py` are optional assertions against the detected values.

### 7.2 UPKeyGen(mpk, E_T, T, T′) → tk   (owner)

```
t'_j ←$ Z_p
tk_{j,1} = (h_0 Π_{ρ(L'_j) ∪ Ω'_j} h)^{s_j} · (h_0 Π_{ρ(L_j) ∪ Ω_j} h)^{−s_j t'_j}

if t'_j ≠ t_j and T_j already has gate-children:            (engineering addition, see below)
    tk_children[k] = h_{2ℓ − t'_j + pos(k)}^{s_j} · g2^{s_k}

Attributes2New additionally:
    s_t ←$ Z_p                                               (fresh, added to E_T')
    ct_{T_t} = ((h_0 Π_{ρ(L_t) ∪ Ω_t} h)^{s_t}, g^{s_t})
    tk_leaf  = h_{2ℓ − t'_j + (|N_j|+1)}^{s_j} · g2^{s_t}
tk = {type, target_subtree, new_policy, new_node, t'_j, tk_{j,1}, tk_children [, new_subtree, ct_{T_t}, tk_leaf]}
```

`owner_upkeygen.py` uploads tk to `updates/<object_id>/tk_v<N>.json` and stores
`E_T_v<N+1>.json` locally. tk contains no element of Z_p other than the blinding exponent t'_j.

*Why `tk_children`:* the paper keeps ct_{j,i+2} unchanged, but its index 2ℓ − t_j + i depends on t_j.
When the threshold of a gate that has gate-children changes, the old components would no longer
match (and Ω'_j could collide with them), so the owner re-issues just those components. The update
key stays constant-size whenever t_j is unchanged or T_j has no gate-children (the common case,
including both examples in the paper).

### 7.3 CTUpdate(mpk, ct_T, tk) → ct_T′   (cloud)

```
ct'_{j,1} = ct_{j,1}^{t'_j} · tk_{j,1}  = (h_0 Π_{ρ(L'_j) ∪ Ω'_j} h)^{s_j}
ct'_{j,2} = ct_{j,2}
ct'_{j,child k} = tk_children[k] if present, else unchanged
Attributes2New: ct'_{j,child T_t} = tk_leaf;  add ct_{T_t};  add T_t to the tree
tree.nodes[T_j] = new_node;  policy = new_policy
```

`cloud_update.apply_update()` checks that tk targets the latest version, writes v<N+1> with the same
`c_aes`, then deletes vN and the consumed tk (the paper replaces ct_T by ct_T′; use
`--keep-history` / `KEEP_HISTORY=1` only for demos). A replayed S3 event for an already applied tk
is a no-op.

---

## 8. Serialization

`serialize_any` turns every Charm element into `{"__charm__": base64}` and recurses through
dicts/lists; `deserialize_any` reverses it. Integer dict keys (e.g. `h`) become strings in JSON;
`h_get()` accepts both.

---

## 9. File formats

| File | Location | Content |
|---|---|---|
| `mpk.json` | public; `config/mpk.json` in the store | `{curve, ell, mpk}` (mpk includes `rho`) |
| `msk.json` | Authority machine only | `{curve, ell, msk}` |
| `<user>.json` | the user only | `{curve, ell, attrs, sk}` |
| `objects/<id>/v<N>.json` | cloud | `{scheme, object_id, version, policy, c_aes, ct_abe, ts}` |
| `objects/<id>/latest.json` | cloud | `{object_id, latest_version}` |
| `updates/<id>/tk_v<N>.json` | cloud (transient) | `{object_id, base_version, tk}` |
| `E_T_v<N>.json` | owner machine only | `{object_id, version, E_T}` |
