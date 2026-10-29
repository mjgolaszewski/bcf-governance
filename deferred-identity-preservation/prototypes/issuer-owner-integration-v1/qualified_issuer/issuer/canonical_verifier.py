"""Private canonical verifier composition, UNRUN; no issuer or key-custody I/O.

The source-owning canonical decoder verifies JWT signature/issuer/audience/time/
typ/key shape and returns VerifiedAccessTokenClaims. Its own protocol projection
owns list/optional-field semantics. This adapter never decodes unverified JWTs,
imports runtime signing settings, obtains keys over HTTP or asserts revocation.
Dependencies/source/crypto runtime must be pinned by a separate admitted envelope.
Constructor only bounds/freezes public configuration; malformed JWK shape and
ambiguous kid refusal are delegated to the canonical decoder at verification,
not a constructor readiness verdict. No transport/owner readiness is established.
"""
import json

from chrysalis_identity.jwt_payloads import DEFAULT_MAX_JWT_CHARS
from chrysalis_identity.tokens import decode_access_token
from chrysalis_identity.verified_token_claims import VerifiedAccessTokenClaims
from .issuer_provider_v4 import ISSUER, private, require


class PinnedAccessTokenVerifier:
    @private
    def __init__(self, *, public_jwks, algorithms, audiences):
        require(type(public_jwks) is list and 0 < len(public_jwks) <= 10)
        private_members = {'d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'}
        require(all(type(key) is dict and not private_members.intersection(key)
                    for key in public_jwks))
        require(type(algorithms) is tuple and algorithms
                and all(type(value) is str and value in {'RS256', 'EdDSA'} for value in algorithms)
                and len(set(algorithms)) == len(algorithms))
        require(type(audiences) is tuple and audiences
                and all(type(value) is str and value in {'racecar', 'chrysalis-identity'}
                        for value in audiences) and len(set(audiences)) == len(audiences))
        snapshot = json.dumps(public_jwks, sort_keys=True, separators=(',', ':'), allow_nan=False)
        require(len(snapshot.encode()) <= 65536)
        self._jwks = snapshot
        self._algorithms = algorithms
        self._audiences = audiences

    @private
    def __call__(self, *, token, issuer, audience):
        require(issuer == ISSUER and audience in self._audiences)
        require(type(token) is str and 0 < len(token) <= DEFAULT_MAX_JWT_CHARS)
        verified = decode_access_token(token=token, public_jwks=json.loads(self._jwks),
                                       issuer=ISSUER, audience=audience,
                                       algorithms=list(self._algorithms))
        require(type(verified) is VerifiedAccessTokenClaims)
        # Delegate canonical serialization; do not recreate/normalize its fields.
        return verified.to_protocol_mapping()
