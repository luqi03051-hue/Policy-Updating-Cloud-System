# -*- coding: utf-8 -*-
"""
abe_core.py — PU-CP-ABE core (shared by every role)

Implements the scheme of
  "IoT-Cloud Data Sharing and Access Control System With Efficient Policy Updating"

    Setup(λ, U)                 -> (mpk, msk)          [Authority]
    KeyGen(mpk, msk, A)         -> sk_A                [Authority]
    Enc(M, mpk, T)              -> (ct_T, E_T)         [Data owner]   E_T stays with the owner
    Dec(mpk, sk_A, ct_T)        -> M                   [Data user]
    UPKeyGen(mpk, E_T, T, T')   -> tk_{T->T'}          [Data owner]   needs E_T
    CTUpdate(mpk, ct_T, tk)     -> ct_{T'}             [Cloud]        never sees E_T / msk / sk

Differences from the previous PoC (see docs/CHANGES.md for the full list):
  * Enc returns (CT, E_T); the ciphertext no longer carries the random numbers s_j.
  * sk_A contains only {w^{(r-1)/β}, sk_t : t ∈ A ∪ U'} — no α, no keys for attributes outside A,
    and no h_t^{r q(t)} for its own index t (exactly as in the paper).
  * ρ (attribute name -> index) is fixed once at Setup and published in mpk.
  * The ciphertext stores the access-tree structure explicitly (labels, thresholds, leaves,
    ordered gate-children), so decryption never depends on re-parsing a policy string.
  * In Attributes2New the new subtree secret s_t is freshly sampled by the owner.

Engineering notes (deviations kept from the original implementation, documented):
  * The default-attribute range U' is extended to {ℓ+1 .. 4ℓ} (paper: {ℓ+1 .. 2ℓ}) so that a gate
    may have more gate-children than its threshold; these indices are only ever used as
    Ω_j / gate-child indices, never as real attributes.
  * If an update changes t_j of a gate that already has gate-children, the child components
    ct_{j,i+2} = h_{2ℓ-t_j+i}^{s_j} g2^{s_k} are re-issued in tk (the paper keeps them unchanged,
    which is only correct when t_j does not change).
"""

from __future__ import annotations

import base64
import copy
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from charm.toolbox.pairinggroup import G1, G2, GT, ZR, PairingGroup, pair

SCHEME_ID = "pu-cp-abe/2"
H_FACTOR = 4  # h_0 .. h_{H_FACTOR*ell}; default attributes U' = {ell+1 .. H_FACTOR*ell}

MODE_EXISTING = "Attributes2Existing"
MODE_NEW = "Attributes2New"


# ============================================================
# 1) JSON + serialization helpers
# ============================================================
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def save_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


_PRIMITIVES = (str, int, float, bool, type(None))


def serialize_any(group: PairingGroup, obj: Any) -> Any:
    """Charm elements -> {"__charm__": base64}; containers recursively; primitives as-is."""
    if isinstance(obj, dict):
        return {str(k): serialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [serialize_any(group, v) for v in obj]
    if isinstance(obj, _PRIMITIVES):
        return obj
    return {"__charm__": b64e(group.serialize(obj))}


def deserialize_any(group: PairingGroup, obj: Any) -> Any:
    if isinstance(obj, dict) and "__charm__" in obj:
        return group.deserialize(b64d(obj["__charm__"]))
    if isinstance(obj, dict):
        return {k: deserialize_any(group, v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deserialize_any(group, v) for v in obj]
    return obj


def h_get(mpk: Dict[str, Any], idx: int):
    """mpk['h'][idx] — works for in-memory (int keys) and JSON-loaded (str keys) dicts."""
    h = mpk["h"]
    if idx in h:
        return h[idx]
    if str(idx) in h:
        return h[str(idx)]
    raise KeyError(f"mpk['h'] has no index {idx}")


# ============================================================
# 2) Policy language
#    policy ::= expr
#    expr   ::= term ("OR" term)*          (a chain of n ORs  -> 1-of-n gate)
#    term   ::= atom ("AND" atom)*         (a chain of n ANDs -> n-of-n gate)
#    atom   ::= NAME | "(" expr ")" | "(" k "," expr ("," expr)* ")"
# ============================================================
@dataclass(frozen=True)
class Leaf:
    name: str


@dataclass(frozen=True)
class Gate:
    kind: str  # "AND" / "OR" / "THRESH"
    k: int
    children: Tuple["Node", ...]


Node = Union[Leaf, Gate]


def tokenize(s: str) -> List[str]:
    tokens: List[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c in "(),":
            tokens.append(c)
            i += 1
            continue
        j = i
        while j < len(s) and (s[j].isalnum() or s[j] == "_"):
            j += 1
        if j == i:
            raise ValueError(f"Unexpected character {c!r} at position {i} in policy {s!r}")
        tok = s[i:j]
        if tok.lower() in ("and", "or"):
            tok = tok.upper()
        tokens.append(tok)
        i = j
    return tokens


class _Parser:
    def __init__(self, tokens: List[str]):
        self.toks = tokens
        self.pos = 0

    def peek(self) -> Optional[str]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def consume(self, expected: Optional[str] = None) -> str:
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of policy.")
        if expected is not None and tok != expected:
            raise ValueError(f"Expected '{expected}', got '{tok}'.")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        node = self.parse_or()
        if self.peek() is not None:
            raise ValueError(f"Extra tokens in policy: {self.toks[self.pos:]}")
        return node

    def parse_or(self) -> Node:
        items = [self.parse_and()]
        while self.peek() == "OR":
            self.consume("OR")
            items.append(self.parse_and())
        return items[0] if len(items) == 1 else Gate("OR", 1, tuple(items))

    def parse_and(self) -> Node:
        items = [self.parse_atom()]
        while self.peek() == "AND":
            self.consume("AND")
            items.append(self.parse_atom())
        return items[0] if len(items) == 1 else Gate("AND", len(items), tuple(items))

    def parse_atom(self) -> Node:
        tok = self.peek()
        if tok == "(":
            if (self.pos + 2 < len(self.toks) and self.toks[self.pos + 1].isdigit()
                    and self.toks[self.pos + 2] == ","):
                return self.parse_threshold()
            self.consume("(")
            node = self.parse_or()
            self.consume(")")
            return node
        if tok is None or tok in {"AND", "OR", ",", ")"}:
            raise ValueError(f"Expected attribute or '(' but got {tok!r}.")
        self.consume()
        return Leaf(tok)

    def parse_threshold(self) -> Node:
        self.consume("(")
        k = int(self.consume())
        self.consume(",")
        children = [self.parse_or()]
        while self.peek() == ",":
            self.consume(",")
            children.append(self.parse_or())
        self.consume(")")
        if not (1 <= k <= len(children)):
            raise ValueError(f"Invalid threshold gate: k={k}, n={len(children)}")
        return Gate("THRESH", k, tuple(children))


def parse_policy(policy: str) -> Gate:
    """Parse a policy string. A bare attribute 'attA' becomes the 1-of-1 gate (1, attA)."""
    if not policy or not policy.strip():
        raise ValueError("Policy is empty.")
    node = _Parser(tokenize(policy)).parse()
    if isinstance(node, Leaf):
        node = Gate("THRESH", 1, (node,))
    return node


# ============================================================
# 3) Access-tree structure stored inside the ciphertext
#    tree = {"root": "Tr",
#            "nodes": {"Tr": {"t": 1, "leaves": ["attA"], "children": ["T1"]},
#                      "T1": {"t": 2, "leaves": ["attB","attC"], "children": []}}}
#    "children" order defines the position i used in ct_{j,i+2} / h_{2ℓ-t_j+i}.
# ============================================================
def _gate_leaves(g: Gate) -> List[str]:
    names = [c.name for c in g.children if isinstance(c, Leaf)]
    if len(set(names)) != len(names):
        raise ValueError(f"An attribute appears twice under the same gate: {names}")
    return sorted(names)


def tree_from_policy(root: Gate) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    counter = [0]

    def visit(g: Gate, label: str) -> None:
        leaves = _gate_leaves(g)
        children: List[str] = []
        for c in g.children:
            if isinstance(c, Gate):
                counter[0] += 1
                lab = f"T{counter[0]}"
                children.append(lab)
                visit(c, lab)
        nodes[label] = {"t": g.k, "leaves": leaves, "children": children}

    visit(root, "Tr")
    return {"root": "Tr", "nodes": nodes}


def canon_ast(g: Gate) -> str:
    parts = [f"a:{n}" for n in _gate_leaves(g)] + [canon_ast(c) for c in g.children if isinstance(c, Gate)]
    return f"G{g.k}(" + ",".join(sorted(parts)) + ")"


def canon_tree(tree: Dict[str, Any], label: str) -> str:
    node = tree["nodes"][label]
    parts = [f"a:{n}" for n in node["leaves"]] + [canon_tree(tree, c) for c in node["children"]]
    return f"G{node['t']}(" + ",".join(sorted(parts)) + ")"


def policy_from_tree(tree: Dict[str, Any], label: Optional[str] = None) -> str:
    """Render the stored tree back to a policy string (threshold notation)."""
    label = label or tree["root"]
    node = tree["nodes"][label]
    items = list(node["leaves"]) + [policy_from_tree(tree, c) for c in node["children"]]
    return f"({node['t']}, " + ", ".join(items) + ")"


def tree_attributes(tree: Dict[str, Any]) -> Set[str]:
    return {a for n in tree["nodes"].values() for a in n["leaves"]}


def _next_label(tree: Dict[str, Any]) -> str:
    nums = [int(k[1:]) for k in tree["nodes"] if k.startswith("T") and k[1:].isdigit()]
    return f"T{max(nums, default=0) + 1}"


# ============================================================
# 4) The scheme
# ============================================================
class PUCPABE:
    def __init__(self, group: PairingGroup, ell: int):
        if ell < 1:
            raise ValueError("ell must be >= 1")
        self.group = group
        self.ell = ell
        self.max_h = H_FACTOR * ell
        self.U_prime = list(range(ell + 1, self.max_h + 1))

    # ---------- index helpers ----------
    def omega(self, t: int) -> List[int]:
        """Ω_j = {ℓ+1, ..., 2ℓ - t_j}"""
        return list(range(self.ell + 1, 2 * self.ell - t + 1))

    def child_index(self, t: int, pos: int) -> int:
        """Index of the pos-th (1-based) gate-child of a gate with threshold t: 2ℓ - t + pos."""
        idx = 2 * self.ell - t + pos
        if idx > self.max_h:
            raise ValueError(f"Gate has too many gate-children for ell={self.ell} (index {idx} > {self.max_h}).")
        return idx

    def _check_node(self, mpk: Dict[str, Any], node: Dict[str, Any]) -> None:
        rho = mpk["rho"]
        unknown = [a for a in node["leaves"] if a not in rho]
        if unknown:
            raise ValueError(f"Attributes not in the system universe (mpk.rho): {unknown}")
        if not (1 <= node["t"] <= self.ell):
            raise ValueError(f"Threshold t={node['t']} must be in [1, ell={self.ell}].")
        if node["t"] > len(node["leaves"]) + len(node["children"]):
            raise ValueError(f"Threshold t={node['t']} exceeds the number of children.")

    def _subtree_base(self, mpk: Dict[str, Any], leaves: List[str], t: int):
        """h_0 · Π_{i ∈ ρ(L_j) ∪ Ω_j} h_i"""
        prod = h_get(mpk, 0)
        for idx in [mpk["rho"][a] for a in leaves] + self.omega(t):
            prod *= h_get(mpk, idx)
        return prod

    def _subtree_ct(self, mpk, node: Dict[str, Any], s_j, child_s: Dict[str, Any]) -> Dict[str, Any]:
        ct = {
            "ct1": self._subtree_base(mpk, node["leaves"], node["t"]) ** s_j,  # (h0 Π h_i)^{s_j}
            "ct2": mpk["g"] ** s_j,                                              # g^{s_j}
            "ct_child": {},
        }
        for pos, lab in enumerate(node["children"], start=1):
            # ct_{j,i+2} = h_{2ℓ - t_j + i}^{s_j} · g2^{s_k}
            ct["ct_child"][lab] = (h_get(mpk, self.child_index(node["t"], pos)) ** s_j) * (mpk["g2"] ** child_s[lab])
        return ct

    # ---------- Setup ----------
    def setup(self, universe: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        names = [a.strip() for a in universe if a.strip()]
        if len(set(names)) != len(names):
            raise ValueError("Duplicate attribute names in universe.")
        if len(names) > self.ell:
            raise ValueError(f"Universe has {len(names)} attributes but ell={self.ell}.")
        for n in names:
            tokenize(n)  # validates the name

        g = self.group.random(G1)
        g2 = self.group.random(G2)
        alpha, beta, theta = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        g1 = g ** alpha
        v = g ** theta
        w = g2 ** (alpha / theta)  # e(g1, g2) = e(v, w)

        mpk = {
            "g": g,
            "g2": g2,
            "v_beta": v ** beta,
            "h": {i: self.group.random(G2) for i in range(0, self.max_h + 1)},
            "Z": pair(g1, g2),
            "rho": {name: i + 1 for i, name in enumerate(names)},  # ρ(att_i) = i, public
        }
        msk = {"alpha": alpha, "w_1_over_beta": w ** (1 / beta)}
        return mpk, msk

    # ---------- KeyGen ----------
    def keygen(self, msk: Dict[str, Any], mpk: Dict[str, Any], attrs: List[str]) -> Dict[str, Any]:
        rho = mpk["rho"]
        attrs = sorted(set(a.strip() for a in attrs if a.strip()))
        unknown = [a for a in attrs if a not in rho]
        if unknown:
            raise ValueError(f"Attributes not in the system universe: {unknown}")

        coeffs = [msk["alpha"]] + [self.group.random(ZR) for _ in range(self.ell - 1)]  # q(0) = α

        def q(i: int):
            x = self.group.init(ZR, i)
            acc = self.group.init(ZR, 0)
            for j, cj in enumerate(coeffs):
                acc += cj * (x ** j)
            return acc

        r = self.group.random(ZR)
        comps: Dict[str, Any] = {}
        for i in [rho[a] for a in attrs] + self.U_prime:  # t ∈ A ∪ U'
            e = r * q(i)
            comps[str(i)] = {
                "a": (mpk["g2"] * h_get(mpk, 0) * h_get(mpk, i)) ** e,  # (g2 h0 h_t)^{r q(t)}
                "b": mpk["g"] ** e,                                       # g^{r q(t)}
                "c": {str(j): h_get(mpk, j) ** e                          # h_j^{r q(t)}, j ≠ t
                      for j in range(1, self.max_h + 1) if j != i},
            }
        return {"attrs": attrs, "d": msk["w_1_over_beta"] ** (r - 1), "k": comps}  # d = w^{(r-1)/β}

    # ---------- Enc ----------
    def encrypt(self, M, mpk: Dict[str, Any], policy: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        tree = tree_from_policy(parse_policy(policy))
        for node in tree["nodes"].values():
            self._check_node(mpk, node)
            for pos in range(1, len(node["children"]) + 1):
                self.child_index(node["t"], pos)

        E_T = {label: self.group.random(ZR) for label in tree["nodes"]}  # s_j per subtree
        ct_T = {label: self._subtree_ct(mpk, node, E_T[label], E_T) for label, node in tree["nodes"].items()}
        s_r = E_T["Tr"]
        ct_T["Tr"]["ct_v"] = mpk["v_beta"] ** s_r  # ct_{Tr,3} = (v^β)^{s_r}

        CT = {
            "scheme": SCHEME_ID,
            "ell": self.ell,
            "policy": policy,
            "tree": tree,
            "C0": M * (mpk["Z"] ** s_r),  # M · e(g1, g2)^{s_r}
            "ct_T": ct_T,
        }
        return CT, E_T

    # ---------- Dec ----------
    def decrypt(self, mpk: Dict[str, Any], sk: Dict[str, Any], CT: Dict[str, Any]):
        if CT.get("scheme") != SCHEME_ID:
            raise ValueError(f"Unsupported ciphertext format {CT.get('scheme')!r}; expected {SCHEME_ID}.")
        rho = mpk["rho"]
        A = set(sk["attrs"])
        K = sk["k"]
        tree = CT["tree"]
        group = self.group

        def lagrange(i: int, S: List[int]):
            x0 = group.init(ZR, 0)
            num, den = group.init(ZR, 1), group.init(ZR, 1)
            iz = group.init(ZR, i)
            for j in S:
                if j != i:
                    jz = group.init(ZR, j)
                    num *= (x0 - jz)
                    den *= (iz - jz)
            return num / den

        def base_i(i: int, Tset: List[int]):
            # (g2 h0 Π_{t∈Tset} h_t)^{r q(i)} = a_i · Π_{t∈Tset, t≠i} c_i[t]   (requires i ∈ Tset)
            comp = K[str(i)]
            acc = comp["a"]
            for t in Tset:
                if t != i:
                    acc *= comp["c"][str(t)]
            return acc

        memo: Dict[str, Tuple[Any, Any]] = {}

        def dec(label: str):
            if label in memo:
                return memo[label]
            node = tree["nodes"][label]
            t = node["t"]
            ctj = CT["ct_T"][label]
            Lj = [rho[a] for a in node["leaves"]]
            sat_leaf = [rho[a] for a in node["leaves"] if a in A]

            sat_children = []  # (pos, label, D_k1, P_k2)
            for pos, child in enumerate(node["children"], start=1):
                Dk1, Pk2 = dec(child)
                if Dk1 is not None:
                    sat_children.append((pos, child, Dk1, Pk2))

            if len(sat_leaf) + len(sat_children) < t:
                memo[label] = (None, None)
                return memo[label]

            A_prime = sat_leaf[:t]
            S_j = sat_children[: t - len(A_prime)]
            S_idx = [self.child_index(t, pos) for (pos, _c, _d, _p) in S_j]
            Omega = self.omega(t)
            X = A_prime + S_idx + Omega            # |X| = ℓ
            Tset = Lj + S_idx + Omega

            missing = [i for i in X if str(i) not in K]
            if missing:
                raise ValueError(f"Private key lacks components {missing}.")

            Pj1 = group.init(G2, 1)
            Pj2 = group.init(G1, 1)
            for i in X:
                delta = lagrange(i, X)
                Pj1 *= base_i(i, Tset) ** delta   # (g2 h0 Π h_t)^{rα}
                Pj2 *= K[str(i)]["b"] ** delta    # g^{rα}

            denom = pair(Pj2, ctj["ct1"])
            for (_pos, child, Dk1, Pk2) in S_j:
                denom *= pair(Pk2, ctj["ct_child"][child]) / Dk1   # D_{j,3,i}

            Dj1 = pair(ctj["ct2"], Pj1) / denom        # e(g2^{rα}, g^{s_j})
            memo[label] = (Dj1, Pj2)
            return memo[label]

        Dr1, _ = dec(tree["root"])
        if Dr1 is None:
            raise PermissionError("Access policy not satisfied by the private key's attributes.")
        Dr2 = pair(CT["ct_T"][tree["root"]]["ct_v"], sk["d"])
        return CT["C0"] * (Dr2 / Dr1)


# ============================================================
# 5) Policy updating (single gate): plan -> UPKeyGen (owner) -> CTUpdate (cloud)
# ============================================================
@dataclass
class UpdatePlan:
    mode: str                  # MODE_EXISTING / MODE_NEW
    target: str                # label of T_j in the current tree
    new_t: int                 # t'_j
    new_leaves: List[str]      # L'_j (direct leaves of T_j after the update)
    new_gate: Optional[Gate]   # Attributes2New only: the new leaf-only gate T_t


def plan_update(tree: Dict[str, Any], new_policy: str) -> UpdatePlan:
    """
    Compare the stored tree with the new policy and locate the single gate that changes.
    Supported (paper Sec. IV-C): Attributes2Existing and Attributes2New.
    Not supported: root-gate updates (RootEtOR / RootEtAND / RootEtThreshold) and multi-gate edits.
    """
    new_root = parse_policy(new_policy)
    if canon_tree(tree, tree["root"]) == canon_ast(new_root):
        raise ValueError("The new policy is equivalent to the current one; nothing to update.")
    old_root_canon = canon_tree(tree, tree["root"])
    if any(isinstance(c, Gate) and canon_ast(c) == old_root_canon for c in new_root.children):
        raise ValueError("Root-gate updates (RootEtOR/RootEtAND/RootEtThreshold) are not implemented.")
    return _diff(tree, tree["root"], new_root)


def _diff(tree: Dict[str, Any], label: str, g: Gate) -> UpdatePlan:
    node = tree["nodes"][label]
    new_leaves = _gate_leaves(g)
    remaining = [c for c in g.children if isinstance(c, Gate)]
    unmatched_old: List[str] = []
    for child in node["children"]:
        cn = canon_tree(tree, child)
        hit = next((k for k, c in enumerate(remaining) if canon_ast(c) == cn), None)
        if hit is None:
            unmatched_old.append(child)
        else:
            remaining.pop(hit)
    self_changed = g.k != node["t"] or new_leaves != node["leaves"]

    if not unmatched_old and not remaining:
        return UpdatePlan(MODE_EXISTING, label, g.k, new_leaves, None)
    if not unmatched_old and len(remaining) == 1:
        new_gate = remaining[0]
        if any(isinstance(c, Gate) for c in new_gate.children):
            raise ValueError("Attributes2New: the new gate may only contain attributes (no nested gates).")
        return UpdatePlan(MODE_NEW, label, g.k, new_leaves, new_gate)
    if len(unmatched_old) == 1 and len(remaining) == 1 and not self_changed:
        return _diff(tree, unmatched_old[0], remaining[0])
    raise ValueError(
        f"The new policy changes more than one gate (around subtree {label}). "
        "PU-CP-ABE updates one gate per update key; apply the changes one at a time."
    )


def UPKeyGen(abe: PUCPABE, mpk: Dict[str, Any], E_T: Dict[str, Any], tree: Dict[str, Any],
             new_policy: str, expect_mode: Optional[str] = None,
             expect_target: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Data owner side. Returns (tk_{T->T'}, E_T') where E_T' is the owner's updated random-number set.
    tk contains no s_j in the clear: only group elements and the blinding exponent t'_j.
    """
    group = abe.group
    plan = plan_update(tree, new_policy)
    if expect_mode and expect_mode != plan.mode:
        raise ValueError(f"Detected update mode {plan.mode}, but --mode {expect_mode} was given.")
    if expect_target and expect_target != plan.target:
        raise ValueError(f"Detected target subtree {plan.target}, but {expect_target} was given.")

    old = tree["nodes"][plan.target]
    s_j = E_T[plan.target]
    new_label = _next_label(tree) if plan.mode == MODE_NEW else None
    new_children = list(old["children"]) + ([new_label] if new_label else [])
    new_node = {"t": plan.new_t, "leaves": plan.new_leaves, "children": new_children}
    abe._check_node(mpk, new_node)

    # tk_{T'_j,1} = (h0 Π_{T'_j ∪ Ω'_j} h)^{s_j} · (h0 Π_{L_j ∪ Ω_j} h)^{-s_j t'_j}
    tprime = group.random(ZR)
    base_old = abe._subtree_base(mpk, old["leaves"], old["t"])
    base_new = abe._subtree_base(mpk, plan.new_leaves, plan.new_t)
    tk_j1 = (base_new ** s_j) * (base_old ** (-s_j * tprime))

    # Re-issue existing gate-child components if t_j changed (index 2ℓ - t_j + i moves).
    tk_children: Dict[str, Any] = {}
    for pos, child in enumerate(old["children"], start=1):
        new_idx = abe.child_index(plan.new_t, pos)
        if new_idx != abe.child_index(old["t"], pos):
            tk_children[child] = (h_get(mpk, new_idx) ** s_j) * (mpk["g2"] ** E_T[child])

    tk: Dict[str, Any] = {
        "type": plan.mode,
        "target_subtree": plan.target,
        "new_policy": new_policy,
        "new_node": new_node,
        "tprime": tprime,
        "tk_j1": tk_j1,
        "tk_children": tk_children,
    }
    E_T_new = dict(E_T)

    if plan.mode == MODE_NEW:
        gate_node = {"t": plan.new_gate.k, "leaves": _gate_leaves(plan.new_gate), "children": []}
        abe._check_node(mpk, gate_node)
        s_t = group.random(ZR)                                   # fresh s_t ∈ Z_p
        ct_Tt = abe._subtree_ct(mpk, gate_node, s_t, {})
        pos = len(new_children)                                  # |N_j| + 1
        tk_leaf = (h_get(mpk, abe.child_index(plan.new_t, pos)) ** s_j) * (mpk["g2"] ** s_t)
        tk.update({"new_subtree": new_label, "new_gate_node": gate_node, "ct_Tt": ct_Tt, "tk_leaf": tk_leaf})
        E_T_new[new_label] = s_t

    return tk, E_T_new


def CTUpdate(CT: Dict[str, Any], tk: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cloud side: ct_{T'_j} = (ct_{j,1}^{t'_j} · tk_{j,1}, ct_{j,2}, {ct_{j,i+2}} [, tk_leaf]) and,
    for Attributes2New, add ct_{T_t}. Does not need (and must not receive) E_T, msk or sk.
    """
    if tk.get("type") not in (MODE_EXISTING, MODE_NEW):
        raise ValueError(f"Unknown update key type {tk.get('type')!r}.")
    if CT.get("scheme") != SCHEME_ID:
        raise ValueError("Unsupported ciphertext format.")

    Tj = tk["target_subtree"]
    tree = copy.deepcopy(CT["tree"])
    if Tj not in tree["nodes"]:
        raise ValueError(f"Target subtree {Tj!r} not in ciphertext.")
    old_children = tree["nodes"][Tj]["children"]
    new_node = tk["new_node"]
    if new_node["children"][: len(old_children)] != old_children:
        raise ValueError("Update key does not match the ciphertext's tree structure.")

    ct_T = dict(CT["ct_T"])
    ctj = dict(ct_T[Tj])
    ctj["ct1"] = (ctj["ct1"] ** tk["tprime"]) * tk["tk_j1"]
    ctj["ct_child"] = dict(ctj.get("ct_child", {}))
    ctj["ct_child"].update(tk.get("tk_children", {}))

    tree["nodes"][Tj] = copy.deepcopy(new_node)
    if tk["type"] == MODE_NEW:
        Tt = tk["new_subtree"]
        if Tt in tree["nodes"]:
            raise ValueError(f"Subtree label {Tt!r} already exists.")
        ctj["ct_child"][Tt] = tk["tk_leaf"]
        ct_T[Tt] = tk["ct_Tt"]
        tree["nodes"][Tt] = copy.deepcopy(tk["new_gate_node"])
    ct_T[Tj] = ctj

    CTp = dict(CT)
    CTp.update({"tree": tree, "ct_T": ct_T, "policy": tk["new_policy"]})
    return CTp


# ============================================================
# 6) Factory + key-file helpers
#    mpk.json : {"curve","ell","mpk"}          public  (cloud, owner, users)
#    msk.json : {"curve","ell","msk"}          Authority only
#    sk.json  : {"curve","ell","attrs","sk"}   one data user
# ============================================================
def build_abe(curve: str = "SS512", ell: int = 10) -> Tuple[PairingGroup, PUCPABE]:
    group = PairingGroup(curve)
    return group, PUCPABE(group, ell)


def load_public(mpk_path_or_blob: Union[str, Dict[str, Any]]):
    blob = load_json(mpk_path_or_blob) if isinstance(mpk_path_or_blob, str) else mpk_path_or_blob
    if "msk" in blob:
        raise ValueError("This file contains msk. Give non-Authority roles mpk.json only.")
    group, abe = build_abe(blob["curve"], int(blob["ell"]))
    return group, abe, deserialize_any(group, blob["mpk"])


def load_user_key(sk_path: str, group: PairingGroup) -> Dict[str, Any]:
    blob = load_json(sk_path)
    return deserialize_any(group, blob["sk"])
