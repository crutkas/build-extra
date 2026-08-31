#!/usr/bin/env python3

"""Portable A6 provenance criterion for the frozen archive-auditor prefix.

Git object evidence is authoritative for commit identity, trees, parents,
messages, and trailers. A Copilot-Session value is immutable message text, but
its resolution is only a machine-local attestation. Absence on another machine
is therefore reported as unverifiable-foreign unless a claim explicitly
requires local evidence, in which case validation fails closed.
"""

from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
FROZEN_BASE = "79f3c5fa9111e438b923222dd27392843a995995"
FROZEN_TIP = "ce12c499d3c2a3531091f749c0490ce5e6cbc5c7"
SESSION_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class FrozenCommitClaim:
    oid: str
    tree: str
    parents: tuple[str, ...]
    message_sha256: str
    trailers: tuple[tuple[str, str], ...]


FROZEN_CLAIMS = (
    FrozenCommitClaim(
        oid="a94e4d6681292a130a8672b0973b0dcd01ce080e",
        tree="9ce5e98ecc1c1bd9ea1073eaf29c012b94f0e0d2",
        parents=("79f3c5fa9111e438b923222dd27392843a995995",),
        message_sha256="b9b7e38c5704510866f200fca6089ac1f045fcf19f7ea7cd11b03de2bef89ecf",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "f8baccc1-50a2-41ac-ac82-88acacd633a3"),
        ),
    ),
    FrozenCommitClaim(
        oid="da6edf863fca143ecabf20d589728e59ba2d59f5",
        tree="100049211d67461b274ec13a0a4c8f9ab65003f1",
        parents=("a94e4d6681292a130a8672b0973b0dcd01ce080e",),
        message_sha256="9f7c6a9c625002f96def0426ceeeb8eca319eca05ffbf668cd21c01acf5a75ac",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "4b1bd29a-e703-4a21-b158-20472240da6e"),
        ),
    ),
    FrozenCommitClaim(
        oid="df089ce357a2ceb89760d710e28aa458cc3dc3ca",
        tree="a21ffb83db6706d3c71614bd7c6591fd876830a4",
        parents=("da6edf863fca143ecabf20d589728e59ba2d59f5",),
        message_sha256="78af63de22c3cae59754ad0b12b2386f0c59de55238f94055dbe92f1b800f40b",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "4b1bd29a-e703-4a21-b158-20472240da6e"),
        ),
    ),
    FrozenCommitClaim(
        oid="c38102d47f6b962bf859a214e98e733aba47a5ba",
        tree="f7cbc48424f18a4a15c1857f029b10ff19ed5689",
        parents=("df089ce357a2ceb89760d710e28aa458cc3dc3ca",),
        message_sha256="a6190ae47d670308fe8345fac1adbef794076bc287f51e846b5e296a3f5d3764",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "4b1bd29a-e703-4a21-b158-20472240da6e"),
        ),
    ),
    FrozenCommitClaim(
        oid="5c70a3aa45fdbae5381e5b0e7fe2d3ba9d5b8b91",
        tree="4d4a91cbabb2c994852f0a46801e292afe3f1d92",
        parents=("c38102d47f6b962bf859a214e98e733aba47a5ba",),
        message_sha256="79ae6bd89b15e28ee391c25b47b3c0cca11a4cd96be92e834d847e914c848889",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "4b1bd29a-e703-4a21-b158-20472240da6e"),
        ),
    ),
    FrozenCommitClaim(
        oid="d5dfc9780b2144e90988ab353390286b87b32c9c",
        tree="a59ed4d526c87c4cdeb54123a06aa770b27d6ee8",
        parents=("5c70a3aa45fdbae5381e5b0e7fe2d3ba9d5b8b91",),
        message_sha256="e0e3f85f8e3c00f71980b49710f84c662712d5156956b61fe0d246e92a41dc23",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "4b1bd29a-e703-4a21-b158-20472240da6e"),
        ),
    ),
    FrozenCommitClaim(
        oid="42f230e14f7a38443307ea94b7eca869865894fd",
        tree="1f71025725f91ec0d94b825cadc7cd5960260954",
        parents=("d5dfc9780b2144e90988ab353390286b87b32c9c",),
        message_sha256="f52ae9d9c0d0662e2ef950d4e332183210f8ca794767ab75310a209dfc347ab5",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "34d8ff79-70c3-4bca-a6cd-d089947777cb"),
        ),
    ),
    FrozenCommitClaim(
        oid="fa6cec21bb1c18172c527d3ad42828499324d456",
        tree="ae6fd86222ccb55d96293027a03f856036799cad",
        parents=("42f230e14f7a38443307ea94b7eca869865894fd",),
        message_sha256="3762e33906bc33d4ab9239e4aa3df2721e7bb81f7530a32d4d5650b7260a44cd",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "82d70ea3-43a6-4b3d-ae41-574f99f116c4"),
        ),
    ),
    FrozenCommitClaim(
        oid="60874bade26d2bfa433177a2728d1b8f5ad80bdd",
        tree="12a8d80e72f49a7e096bf64e302ffa1d66cdb7d5",
        parents=("fa6cec21bb1c18172c527d3ad42828499324d456",),
        message_sha256="19bf15cb735b5d1735457a24a47c37e3b05cdf2a064369b5c7b7fecf17e589f0",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "82d70ea3-43a6-4b3d-ae41-574f99f116c4"),
        ),
    ),
    FrozenCommitClaim(
        oid="f61e52857a28688ce810b9406959a56a45915b5a",
        tree="0ad106cf6ceff526469217fba7715e3583d80e24",
        parents=("60874bade26d2bfa433177a2728d1b8f5ad80bdd",),
        message_sha256="f2f1870bdc0a4962fce1431950320b981538834693076649374732942722cbd9",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "82d70ea3-43a6-4b3d-ae41-574f99f116c4"),
        ),
    ),
    FrozenCommitClaim(
        oid="ce12c499d3c2a3531091f749c0490ce5e6cbc5c7",
        tree="0ad106cf6ceff526469217fba7715e3583d80e24",
        parents=("f61e52857a28688ce810b9406959a56a45915b5a",),
        message_sha256="332f980d4ad80da7c315ce9f8ac8c4752de1266dfe0a484028ac1caad03e839e",
        trailers=(
            ("Signed-off-by", "Clint Rutkas <clint@rutkas.com>"),
            ("Co-authored-by", "Copilot App <223556219+Copilot@users.noreply.github.com>"),
            ("Copilot-Session", "82d70ea3-43a6-4b3d-ae41-574f99f116c4"),
        ),
    ),
)


def git(repository, *args, input_bytes=None):
    try:
        return subprocess.run(
            ["git", "-C", str(repository), *args],
            input=input_bytes,
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        diagnostic = error.stderr.decode("utf-8", "replace").strip()
        raise AssertionError(f"git {' '.join(args)} failed: {diagnostic}") from error


def split_commit(raw):
    try:
        raw_headers, message = raw.split(b"\n\n", 1)
    except ValueError as error:
        raise AssertionError("commit object lacks a header/message boundary") from error

    headers = {}
    for line in raw_headers.splitlines():
        if line.startswith(b" "):
            continue
        try:
            key, value = line.split(b" ", 1)
        except ValueError as error:
            raise AssertionError(f"malformed commit header: {line!r}") from error
        headers.setdefault(key.decode("ascii"), []).append(value.decode("ascii"))
    return headers, message


def terminal_trailers(message):
    trailers = []
    for line in reversed(message.rstrip(b"\n").splitlines()):
        if b": " not in line:
            break
        key, value = line.split(b": ", 1)
        if not re.fullmatch(rb"[A-Za-z0-9-]+", key):
            break
        trailers.append((key.decode("ascii"), value.decode("utf-8")))
    trailers.reverse()
    return tuple(trailers)


def hash_commit(repository, raw):
    return git(repository, "hash-object", "-t", "commit", "--stdin", input_bytes=raw).decode(
        "ascii"
    ).strip()


def single_session(claim):
    sessions = [value for key, value in claim.trailers if key == "Copilot-Session"]
    if len(sessions) != 1 or not SESSION_ID.fullmatch(sessions[0]):
        raise AssertionError(f"invalid Copilot-Session trailer claim for {claim.oid}")
    return sessions[0]


def validate_frozen_prefix(repository=ROOT, claims=FROZEN_CLAIMS):
    for oid in (FROZEN_BASE, FROZEN_TIP):
        try:
            git(repository, "cat-file", "-e", f"{oid}^{{commit}}")
        except AssertionError as error:
            raise AssertionError(
                f"incomplete object database lacks required A6 commit {oid}"
            ) from error

    expected_oids = tuple(claim.oid for claim in claims)
    actual_oids = tuple(
        git(repository, "rev-list", "--reverse", f"{FROZEN_BASE}..{FROZEN_TIP}")
        .decode("ascii")
        .split()
    )
    if actual_oids != expected_oids:
        raise AssertionError("frozen ordered commit prefix differs from the A6 claims")

    evidence = []
    for claim in claims:
        raw = git(repository, "cat-file", "commit", claim.oid)
        if hash_commit(repository, raw) != claim.oid:
            raise AssertionError(f"commit object identity differs for {claim.oid}")
        headers, message = split_commit(raw)
        if headers.get("tree") != [claim.tree]:
            raise AssertionError(f"tree claim differs for {claim.oid}")
        if tuple(headers.get("parent", ())) != claim.parents:
            raise AssertionError(f"parent claim differs for {claim.oid}")
        if hashlib.sha256(message).hexdigest() != claim.message_sha256:
            raise AssertionError(f"message claim differs for {claim.oid}")
        if terminal_trailers(message) != claim.trailers:
            raise AssertionError(f"trailer claim differs for {claim.oid}")
        evidence.append(
            {
                "commit": claim.oid,
                "authority": "git-object-database",
                "session": single_session(claim),
            }
        )
    return tuple(evidence)


def classify_session_attestations(
    claims,
    locally_resolvable,
    require_local_for=frozenset(),
):
    claimed_oids = {claim.oid for claim in claims}
    unknown_requirements = set(require_local_for) - claimed_oids
    if unknown_requirements:
        raise AssertionError(
            f"local evidence required for unknown commit(s): {sorted(unknown_requirements)}"
        )

    attestations = []
    for claim in claims:
        session = single_session(claim)
        status = (
            "locally-resolvable"
            if session in locally_resolvable
            else "unverifiable-foreign"
        )
        if claim.oid in require_local_for and status != "locally-resolvable":
            raise AssertionError(f"required local session evidence is unavailable for {claim.oid}")
        attestations.append(
            {
                "commit": claim.oid,
                "session": session,
                "status": status,
                "authority": "machine-local-session-state",
            }
        )
    return tuple(attestations)


class A6ProvenanceTests(unittest.TestCase):
    def test_frozen_prefix_matches_immutable_git_evidence(self):
        evidence = validate_frozen_prefix()
        self.assertEqual(len(FROZEN_CLAIMS), len(evidence))
        self.assertEqual({FROZEN_TIP}, {evidence[-1]["commit"]})
        self.assertEqual({"git-object-database"}, {item["authority"] for item in evidence})

    def test_foreign_sessions_are_explicitly_unverifiable(self):
        local = {"82d70ea3-43a6-4b3d-ae41-574f99f116c4"}
        attestations = classify_session_attestations(FROZEN_CLAIMS, local)
        self.assertEqual(len(FROZEN_CLAIMS), len(attestations))
        self.assertEqual(
            {"locally-resolvable", "unverifiable-foreign"},
            {item["status"] for item in attestations},
        )
        self.assertEqual(
            {"machine-local-session-state"},
            {item["authority"] for item in attestations},
        )
        unavailable = {item["session"] for item in attestations if item["status"] != "locally-resolvable"}
        self.assertIn("f8baccc1-50a2-41ac-ac82-88acacd633a3", unavailable)
        self.assertIn("34d8ff79-70c3-4bca-a6cd-d089947777cb", unavailable)

    def test_local_evidence_requirement_fails_closed(self):
        with self.assertRaisesRegex(AssertionError, "required local session evidence is unavailable"):
            classify_session_attestations(
                FROZEN_CLAIMS,
                locally_resolvable=frozenset(),
                require_local_for={FROZEN_CLAIMS[0].oid},
            )

    def test_unknown_local_evidence_requirement_fails_closed(self):
        with self.assertRaisesRegex(AssertionError, "local evidence required for unknown commit"):
            classify_session_attestations(
                FROZEN_CLAIMS,
                locally_resolvable=frozenset(),
                require_local_for={"0" * 40},
            )

    def test_malformed_session_claim_fails_closed(self):
        claim = FROZEN_CLAIMS[0]
        trailers = claim.trailers[:-1] + (("Copilot-Session", "not-a-session-id"),)
        with self.assertRaisesRegex(AssertionError, "invalid Copilot-Session trailer claim"):
            classify_session_attestations((replace(claim, trailers=trailers),), frozenset())

    def test_immutable_claim_mutations_are_rejected(self):
        first = FROZEN_CLAIMS[0]
        mutations = {
            "commit": replace(first, oid="0" * 40),
            "tree": replace(first, tree="0" * 40),
            "parent": replace(first, parents=("0" * 40,)),
            "message": replace(first, message_sha256="0" * 64),
            "trailer": replace(
                first,
                trailers=first.trailers[:-1]
                + (("Copilot-Session", "00000000-0000-0000-0000-000000000000"),),
            ),
        }
        expected = {
            "commit": "frozen ordered commit prefix differs",
            "tree": "tree claim differs",
            "parent": "parent claim differs",
            "message": "message claim differs",
            "trailer": "trailer claim differs",
        }
        for label, mutated in mutations.items():
            with self.subTest(mutation=label):
                claims = (mutated,) + FROZEN_CLAIMS[1:]
                with self.assertRaisesRegex(AssertionError, expected[label]):
                    validate_frozen_prefix(claims=claims)

    def test_changing_a_trailer_changes_commit_identity(self):
        claim = FROZEN_CLAIMS[0]
        raw = git(ROOT, "cat-file", "commit", claim.oid)
        old = b"Copilot-Session: f8baccc1-50a2-41ac-ac82-88acacd633a3"
        new = b"Copilot-Session: 00000000-0000-0000-0000-000000000000"
        self.assertEqual(1, raw.count(old))
        self.assertEqual(claim.oid, hash_commit(ROOT, raw))
        self.assertNotEqual(claim.oid, hash_commit(ROOT, raw.replace(old, new)))

    def test_changing_a_tree_changes_commit_identity(self):
        claim = FROZEN_CLAIMS[0]
        raw = git(ROOT, "cat-file", "commit", claim.oid)
        old = f"tree {claim.tree}".encode("ascii")
        new = b"tree " + (b"0" * 40)
        self.assertEqual(1, raw.count(old))
        self.assertEqual(claim.oid, hash_commit(ROOT, raw))
        self.assertNotEqual(claim.oid, hash_commit(ROOT, raw.replace(old, new)))

    def test_changing_a_parent_changes_commit_identity(self):
        claim = FROZEN_CLAIMS[0]
        raw = git(ROOT, "cat-file", "commit", claim.oid)
        old = f"parent {claim.parents[0]}".encode("ascii")
        new = b"parent " + (b"0" * 40)
        self.assertEqual(1, raw.count(old))
        self.assertEqual(claim.oid, hash_commit(ROOT, raw))
        self.assertNotEqual(claim.oid, hash_commit(ROOT, raw.replace(old, new)))


if __name__ == "__main__":
    unittest.main()
