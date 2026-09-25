"""
Transcript-bound negotiation over the XXhfs (post-quantum) handshake.

The mechanism itself is covered in
``tests/core/security/noise/test_transcript_binding.py``. What is specific
here is that ``PatternXXhfs`` reads ``h`` off its own SymmetricState at the
right instant, so these tests exercise the full three-message handshake rather
than the encoding and the check in isolation.
"""

import pytest
import trio

from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.crypto.x25519 import X25519PrivateKey
from libp2p.peer.id import ID
from libp2p.security.noise.exceptions import SecurityProtocolDowngrade
from libp2p.security.noise.pq.patterns_pq import PatternXXhfs
from libp2p.security.noise.pq.transport_pq import (
    IDENTITY_BOUND_PROTOCOL_ID,
    PROTOCOL_ID,
    TransportPQ,
    protocol_id_for,
)
from libp2p.security.noise.transcript_binding import (
    TranscriptBindingConfig,
    TranscriptBindingVariant,
)
from tests.security.noise.pq.helpers import make_conn_pair

HFS = "/noise-mlkem768-hfs/0.2.0"
NOISE = "/noise"

VARIANTS: list[TranscriptBindingVariant] = ["extension", "identity"]


def make_config(
    actual_protocol: str = HFS,
    protocols: tuple[str, ...] = (HFS, NOISE),
    mode: str = "enforce",
    variant: str = "extension",
) -> TranscriptBindingConfig:
    return TranscriptBindingConfig(
        security_protocols=protocols,
        actual_protocol=actual_protocol,
        mode=mode,  # type: ignore[arg-type]
        variant=variant,  # type: ignore[arg-type]
    )


def make_pattern(
    config: TranscriptBindingConfig | None,
) -> tuple[PatternXXhfs, ID]:
    keypair = create_new_key_pair()
    peer = ID.from_pubkey(keypair.public_key)
    pattern = PatternXXhfs(
        local_peer=peer,
        libp2p_privkey=keypair.private_key,
        noise_static_key=X25519PrivateKey.new(),
        transcript_binding=config,
    )
    return pattern, peer


async def run_handshake(
    initiator: PatternXXhfs, responder: PatternXXhfs, responder_peer: ID
) -> list[BaseException]:
    """
    Run one XXhfs handshake over an in-memory connection pair.

    Each side's exception is collected rather than allowed to propagate, so a
    test can assert on both peers independently.

    Args:
        initiator: The dialling pattern.
        responder: The listening pattern.
        responder_peer: The peer ID the initiator expects.

    Returns:
        list: What each side raised, empty when the handshake succeeded.

    """
    init_conn, resp_conn = make_conn_pair()
    errors: list[BaseException] = []

    async def dial() -> None:
        try:
            await initiator.handshake_outbound(init_conn, responder_peer)
        except Exception as exc:
            errors.append(exc)

    async def listen() -> None:
        try:
            await responder.handshake_inbound(resp_conn)
        except Exception as exc:
            errors.append(exc)

    with trio.fail_after(60):
        async with trio.open_nursery() as nursery:
            nursery.start_soon(dial)
            nursery.start_soon(listen)

    return errors


@pytest.mark.trio
@pytest.mark.parametrize("variant", VARIANTS)
async def test_honest_session_completes(variant: str) -> None:
    """The post-quantum suite is what both peers prefer, and what they got."""
    config = make_config(variant=variant)
    initiator, _ = make_pattern(config)
    responder, responder_peer = make_pattern(config)

    assert await run_handshake(initiator, responder, responder_peer) == []


@pytest.mark.trio
@pytest.mark.parametrize("variant", VARIANTS)
async def test_simulated_downgrade_is_refused(variant: str) -> None:
    """
    Running XXhfs while both peers' offers imply plain /noise is as much a
    mismatch as the other way round, and is refused just the same.
    """
    config = make_config(actual_protocol=HFS, protocols=(NOISE, HFS), variant=variant)
    initiator, _ = make_pattern(config)
    responder, responder_peer = make_pattern(config)

    errors = await run_handshake(initiator, responder, responder_peer)

    assert len(errors) == 2
    assert all(isinstance(exc, SecurityProtocolDowngrade) for exc in errors)


@pytest.mark.trio
@pytest.mark.parametrize("initiator_binds", [True, False], ids=["dialer", "listener"])
async def test_a_peer_that_sends_no_binding_is_accepted(initiator_binds: bool) -> None:
    """A peer without the extension is an older peer, not an attacker."""
    config = make_config()
    bound, bound_peer = make_pattern(config)
    unbound, unbound_peer = make_pattern(None)

    if initiator_binds:
        errors = await run_handshake(bound, unbound, unbound_peer)
    else:
        errors = await run_handshake(unbound, bound, bound_peer)

    assert errors == []


@pytest.mark.trio
async def test_warn_mode_completes_the_handshake() -> None:
    """Warn mode reports a mismatch without refusing the connection."""
    config = make_config(protocols=(NOISE, HFS), mode="warn")
    initiator, _ = make_pattern(config)
    responder, responder_peer = make_pattern(config)

    assert await run_handshake(initiator, responder, responder_peer) == []


class TestIdentifierMovesWithTheVariant:
    """
    The identity variant carries its own protocol identifier.

    A peer binding that way verifies a different message, so it must not answer
    to the identifier used by peers that do not. Letting multistream-select
    separate them is the difference between "no protocol in common" and a
    handshake that negotiates and then fails on a signature.
    """

    def _transport(self, config: TranscriptBindingConfig | None) -> TransportPQ:
        return TransportPQ(
            libp2p_keypair=create_new_key_pair(),
            noise_privkey=X25519PrivateKey.new(),
            transcript_binding=config,
        )

    def test_identity_variant_advertises_the_bound_identifier(self) -> None:
        config = make_config(
            actual_protocol=IDENTITY_BOUND_PROTOCOL_ID,
            protocols=(IDENTITY_BOUND_PROTOCOL_ID, NOISE),
            variant="identity",
        )

        assert self._transport(config).protocol_id == IDENTITY_BOUND_PROTOCOL_ID

    def test_extension_variant_keeps_the_ordinary_identifier(self) -> None:
        config = make_config(actual_protocol=HFS, variant="extension")

        assert self._transport(config).protocol_id == PROTOCOL_ID

    def test_off_and_unconfigured_keep_the_ordinary_identifier(self) -> None:
        off = make_config(actual_protocol=HFS, variant="identity", mode="off")

        assert self._transport(off).protocol_id == PROTOCOL_ID
        assert self._transport(None).protocol_id == PROTOCOL_ID

    def test_protocol_id_for_matches_the_transport(self) -> None:
        for config in (
            None,
            make_config(actual_protocol=HFS, variant="extension"),
            make_config(
                actual_protocol=IDENTITY_BOUND_PROTOCOL_ID,
                protocols=(IDENTITY_BOUND_PROTOCOL_ID, NOISE),
                variant="identity",
            ),
        ):
            assert protocol_id_for(config) == self._transport(config).protocol_id

    def test_a_config_naming_the_wrong_identifier_is_refused(self) -> None:
        """
        The downgrade check compares against ``actual_protocol``, so a config
        naming an identifier this transport does not advertise would compare
        against the wrong thing and either miss a downgrade or invent one.
        """
        config = make_config(actual_protocol=HFS, variant="identity")

        with pytest.raises(ValueError, match="advertises"):
            self._transport(config)
