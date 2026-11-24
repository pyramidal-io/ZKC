"""Exact frozen statements eligible for historical containment dispositions.

These source pins scope the verifier's historical proof-type exceptions. They
are neither registry rankings nor a grant to new circuits reusing the labels.
Published packages and entries remain protected by the separate history gate.
"""

from __future__ import annotations

import hashlib
import pathlib

# circuit -> (frozen main source SHA-256, proof types)
CONTAINMENT_IDENTITIES = {
    "zkc_credential_rebind": (
        "4e0413e7b5683a14865d0d567e166f7ad0d2918e54fae709b49617079e91f9d4",
        (
            "zkc:proof:credential_rebind:v1",
        ),
    ),
    "zkc_credential_rebind_binding_v2": (
        "736195b059e200467e668a88c74d64e89afabadd637813d24af47a795f841162",
        (
            "zkc:proof:credential_rebind:v2",
        ),
    ),
    "zkc_credential_rebind_v2": (
        "45602e646d93bafdc4d2f0dc16159e87ffc5c62477cc741a122d7700e6734800",
        (
            "zkc:proof:rebind:v2",
        ),
    ),
    "zkc_credential_rebind_v2_binding_v2": (
        "3deeaa9738793773bc341ce36b698c1a1d767635468735df1e7530fef85bce64",
        (
            "zkc:proof:rebind:v3",
        ),
    ),
    "zkc_jurisdiction": (
        "79bb4fbc5972defc80c78b681949ffe462bb378f75eaa7a2a950e9339ff66202",
        (
            "zkc:proof:jurisdiction:v1",
        ),
    ),
    "zkc_jurisdiction_v2": (
        "513b48e7e02ec06367fe760dc16701947090d9c48809cdd99e6ac146124142be",
        (
            "zkc:proof:jurisdiction:v2",
        ),
    ),
    "zkc_remaining_predicates": (
        "4647e9ec0f689ec139af9d64f280d25551ce246a384406ece13a847ab71fb809",
        (
            "zkc:proof:accreditation:v1",
            "zkc:proof:sanctions:v1",
            "zkc:proof:source:v1",
            "zkc:proof:tax:v1",
        ),
    ),
    "zkc_remaining_predicates_v2": (
        "331604f7d28cd62d309384e66f0545e8e8e331ec2da483ae4192406cd197fa50",
        (
            "zkc:proof:accreditation:v2",
            "zkc:proof:sanctions:v2",
            "zkc:proof:source:v2",
            "zkc:proof:tax:v2",
        ),
    ),
    "zkc_remaining_predicates_v3": (
        "7a4dbb197b4e7c32be4fe0b7e96eb54a127eb761743c0b43d68f2a0bb474544d",
        (
            "zkc:proof:accreditation:v3",
            "zkc:proof:sanctions:v3",
            "zkc:proof:source:v3",
            "zkc:proof:tax:v3",
        ),
    ),
    "zkc_remaining_predicates_v4": (
        "702bdbc98de8559503ebb91112bb8573d135eea3bfacf16b890f7d716e8bb948",
        (
            "zkc:proof:accreditation:v4",
            "zkc:proof:sanctions:v4",
            "zkc:proof:source:v4",
            "zkc:proof:tax:v4",
        ),
    ),
    "zkc_remaining_predicates_v5": (
        "372e2703eee2111dfa55cbe5e976f00679dbefa4cd495a17801391bf4c940a7a",
        (
            "zkc:proof:accreditation:v5",
            "zkc:proof:sanctions:v5",
            "zkc:proof:source:v5",
            "zkc:proof:tax:v5",
        ),
    ),
    "zkc_remaining_predicates_v6": (
        "356723e3e2ebf47af3a1a2120821dc775906024b7ea161fb0f8626935b3a35cc",
        (
            "zkc:proof:accreditation:v6",
            "zkc:proof:sanctions:v6",
            "zkc:proof:source:v6",
            "zkc:proof:tax:v6",
        ),
    ),
}


def matches_containment_identity(repo_root, circuit: str, proof_type: str) -> bool:
    pin = CONTAINMENT_IDENTITIES.get(circuit)
    if pin is None or proof_type not in pin[1]:
        return False
    source = pathlib.Path(repo_root) / "noir" / circuit / "src/main.nr"
    try:
        return (
            not source.is_symlink()
            and hashlib.sha256(source.read_bytes()).hexdigest() == pin[0]
        )
    except OSError:
        return False
