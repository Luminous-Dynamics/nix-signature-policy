#!/usr/bin/env python3
"""Small independent executable model for semantic core-v1 policy vectors.

The model intentionally does not import or invoke the Rust implementation. It
exists to detect shared-assumption bugs in decision ordering, duplicate
handling, typed group membership, lifecycle eligibility, and relations.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations
from typing import Any


@dataclass(frozen=True, order=True)
class Member:
    identity: str
    family: str
    authority: str
    custody_domain: str


def normalize_semantic(case: dict[str, Any]) -> list[dict[str, str]]:
    keys = {key["key_id"]: key for key in case["trusted_keys"]}
    out = []
    for signature in case["input"]["signatures"]:
        key = keys.get(signature["key_id"])
        if key is None:
            key_name, algorithm = signature["key_id"], "unknown"
        else:
            key_name, algorithm = key["key_name"], key["algorithm"]
        out.append(
            {
                "key_name": key_name,
                "algorithm": algorithm,
                "signature_id": signature["signature_id"],
                "verification": signature["verification"],
            }
        )
    return sorted(
        out,
        key=lambda item: (
            item["key_name"],
            item["algorithm"],
            item["signature_id"],
            item["verification"],
        ),
    )


def predicate_matches(predicate: dict[str, Any], key: dict[str, Any], algorithm: dict[str, Any]) -> bool:
    dimensions = (
        "allowed_algorithms",
        "allowed_families",
        "allowed_assurance_classes",
        "required_roles",
        "allowed_authorities",
        "allowed_custody_domains",
    )
    constrained = any(predicate.get(name) for name in dimensions)
    if predicate.get("match_all", False):
        return not constrained
    if not constrained:
        return False
    return (
        (not predicate.get("allowed_algorithms") or algorithm["algorithm"] in predicate["allowed_algorithms"])
        and (not predicate.get("allowed_families") or algorithm["family"] in predicate["allowed_families"])
        and (
            not predicate.get("allowed_assurance_classes")
            or algorithm["assurance_class"] in predicate["allowed_assurance_classes"]
        )
        and set(predicate.get("required_roles", [])).issubset(set(key.get("roles", [])))
        and (not predicate.get("allowed_authorities") or key["authority"] in predicate["allowed_authorities"])
        and (
            not predicate.get("allowed_custody_domains")
            or key["custody_domain"] in predicate["allowed_custody_domains"]
        )
    )


def attr(member: Member, name: str) -> str:
    return {
        "identity": member.identity,
        "family": member.family,
        "authority": member.authority,
        "custody_domain": member.custody_domain,
    }[name]


def relation_satisfied(relation: dict[str, Any], members: dict[str, set[Member]]) -> bool:
    values = [sorted({attr(member, relation["attribute"]) for member in members.get(group, set())}) for group in relation["groups"]]
    if not values:
        return False
    if relation["mode"] == "same":
        return bool(set(values[0]).intersection(*map(set, values[1:])))
    # Small exhaustive injective assignment; core-v1 relations are bounded.
    for choices in permutations(sorted(set().union(*map(set, values))), len(values)):
        if all(choice in group_values for choice, group_values in zip(choices, values, strict=True)):
            return True
    return False


def evaluate(case: dict[str, Any]) -> dict[str, Any]:
    policy = case["policy"]
    now = case.get("evaluation_time", 0)
    candidates = normalize_semantic(case)
    reasons: set[str] = set()

    def early(code: str) -> dict[str, Any]:
        return {"decision": "refuse", "satisfied_clause": None, "reason_codes": {code}, "clauses": []}

    if policy.get("epoch", 1) < case.get("minimum_policy_epoch", 0):
        return early("policy_rollback")
    if policy.get("active_from") is not None and now < policy["active_from"]:
        return early("policy_not_active")
    if policy.get("expires_at") is not None and now >= policy["expires_at"]:
        return early("policy_expired")
    if len(candidates) > policy.get("max_signature_observations", 128):
        return early("too_many_observations")

    unique: dict[tuple[str, str, str], str] = {}
    conflict = False
    for candidate in candidates:
        identity = (candidate["key_name"], candidate["algorithm"], candidate["signature_id"])
        previous = unique.get(identity)
        if previous is None:
            unique[identity] = candidate["verification"]
        elif previous == candidate["verification"]:
            reasons.add("duplicate_candidate")
        else:
            conflict = True
            reasons.add("conflicting_candidate")
    if conflict:
        return {"decision": "refuse", "satisfied_clause": None, "reason_codes": reasons, "clauses": []}
    if len(unique) > policy.get("max_signature_candidates", 32):
        reasons.add("too_many_candidates")
        return {"decision": "refuse", "satisfied_clause": None, "reason_codes": reasons, "clauses": []}

    algorithms = {item["algorithm"]: item for item in policy["algorithm_registry"]}
    families = {item["family"]: item for item in policy.get("family_registry", [])}
    keys_by_name: dict[str, list[dict[str, Any]]] = {}
    for key in case["trusted_keys"]:
        keys_by_name.setdefault(key["key_name"], []).append(key)
    group_members = {definition["group"]: set() for definition in policy["group_definitions"]}

    for (key_name, candidate_algorithm, _signature_id), verification in sorted(unique.items()):
        if verification == "invalid":
            reasons.add("invalid_signature")
            continue
        if verification == "malformed":
            reasons.add("malformed_signature")
            continue
        named = keys_by_name.get(key_name)
        if not named:
            reasons.add("unknown_key")
            continue
        key = next((item for item in named if item["algorithm"] == candidate_algorithm), None)
        if key is None:
            reasons.add("algorithm_mismatch")
            continue
        if key.get("revoked", False):
            reasons.add("revoked_key")
            continue
        if key.get("valid_from") is not None and now < key["valid_from"]:
            reasons.add("not_yet_valid_key")
            continue
        if key.get("valid_until") is not None and now >= key["valid_until"]:
            reasons.add("expired_key")
            continue
        algorithm = algorithms.get(key["algorithm"])
        if algorithm is None or algorithm["family"] not in families:
            reasons.add("invalid_policy")
            continue
        status = families[algorithm["family"]].get("status", "enabled")
        if status == "observe_only":
            reasons.add("observe_only_family")
            continue
        if status == "deprecated":
            reasons.add("deprecated_family")
        if status == "forbidden":
            reasons.add("forbidden_family")
            continue
        member = Member(key["signer_identity"], algorithm["family"], key["authority"], key["custody_domain"])
        for definition in policy["group_definitions"]:
            if predicate_matches(definition["predicate"], key, algorithm):
                group_members[definition["group"]].add(member)

    clauses = []
    satisfied_clause = None
    for clause in policy["accept_if_any"]:
        active = (clause.get("active_from") is None or now >= clause["active_from"]) and (
            clause.get("active_until") is None or now < clause["active_until"]
        )
        groups = []
        satisfied = active
        for requirement in clause["required_groups"]:
            members = group_members.get(requirement["group"], set())
            counts = {
                "identity": len({member.identity for member in members}),
                "family": len({member.family for member in members}),
                "authority": len({member.authority for member in members}),
                "custody_domain": len({member.custody_domain for member in members}),
            }
            ok = (
                counts["identity"] >= requirement.get("min_distinct_identities", 0)
                and counts["family"] >= requirement.get("min_distinct_families", 0)
                and counts["authority"] >= requirement.get("min_distinct_authorities", 0)
                and counts["custody_domain"] >= requirement.get("min_distinct_custody_domains", 0)
            )
            satisfied = satisfied and ok
            groups.append({"group": requirement["group"], "observed_identities": counts["identity"], "required_identities": requirement.get("min_distinct_identities", 0)})
        relations = [relation_satisfied(relation, group_members) for relation in clause.get("relations", [])]
        satisfied = satisfied and all(relations)
        if satisfied and satisfied_clause is None:
            satisfied_clause = clause["clause_id"]
        clauses.append({"clause_id": clause["clause_id"], "active": active, "satisfied": satisfied, "groups": groups, "relations": relations})

    if satisfied_clause is not None:
        decision = "accept"
    elif not any(clause["active"] for clause in clauses):
        decision = "refuse"
        reasons.add("no_active_clause")
    else:
        decision = "refuse"
        if any(not relation for clause in clauses if clause["active"] for relation in clause["relations"]):
            reasons.add("missing_required_relation")
        reasons.add("missing_required_group")
    return {"decision": decision, "satisfied_clause": satisfied_clause, "reason_codes": reasons, "clauses": clauses}


def best_group_counts(result: dict[str, Any]) -> dict[str, int]:
    clauses = result["clauses"]
    if result["satisfied_clause"] is not None:
        selected = next(clause for clause in clauses if clause["clause_id"] == result["satisfied_clause"])
    else:
        active = [clause for clause in clauses if clause["active"]]
        if not active:
            return {}
        selected = min(active, key=lambda clause: sum(max(0, group["required_identities"] - group["observed_identities"]) for group in clause["groups"]))
    return {group["group"]: group["observed_identities"] for group in selected["groups"]}
