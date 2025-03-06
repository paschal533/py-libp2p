import logging

from libp2p.abc import (
    IRawConnection,
    ISecureConn,
    ISecureTransport,
)
from libp2p.crypto.keys import (
    KeyPair,
    PrivateKey,
)
from libp2p.custom_types import (
    TProtocol,
)
from libp2p.peer.id import (
    ID,
)

from .patterns import (
    IPattern,
    PatternXX,
)

PROTOCOL_ID = TProtocol("/noise")


class Transport(ISecureTransport):
    libp2p_privkey: PrivateKey
    noise_privkey: PrivateKey
    local_peer: ID
    early_data: bytes
    with_noise_pipes: bool

    def __init__(
        self,
        libp2p_keypair: KeyPair,
        noise_privkey: PrivateKey = None,
        early_data: bytes = None,
        with_noise_pipes: bool = False,
    ) -> None:
        self.libp2p_privkey = libp2p_keypair.private_key
        self.noise_privkey = noise_privkey
        self.local_peer = ID.from_pubkey(libp2p_keypair.public_key)
        self.early_data = early_data
        self.with_noise_pipes = with_noise_pipes
        if self.with_noise_pipes:
            raise NotImplementedError

    def get_pattern(self) -> IPattern:
        if self.with_noise_pipes:
            raise NotImplementedError
        else:
            logging.debug(
                f"libp2p key: {self.libp2p_privkey}, "
                f"noise key: {self.noise_privkey}"
            )
            noise_key = (
                self.noise_privkey or self.libp2p_privkey
            )  # Fallback to libp2p key
            return PatternXX(
                self.local_peer,
                self.libp2p_privkey,
                noise_key,
                self.early_data,
            )

    async def secure_inbound(self, conn: IRawConnection) -> ISecureConn:
        logging.debug("Starting inbound handshake")
        pattern = self.get_pattern()
        secure_conn = await pattern.handshake_inbound(conn)
        logging.debug("Handshake completed successfully")
        return secure_conn

    async def secure_outbound(self, conn: IRawConnection, peer_id: ID) -> ISecureConn:
        pattern = self.get_pattern()
        return await pattern.handshake_outbound(conn, peer_id)
