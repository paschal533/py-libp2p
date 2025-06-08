#!/usr/bin/env python3

import argparse
import multiaddr
import trio
import logging
from libp2p import generate_new_rsa_identity, new_host
from libp2p.custom_types import TProtocol
from libp2p.network.stream.net_stream import INetStream
from libp2p.security.noise.transport import Transport as NoiseTransport
from libp2p.stream_muxer.yamux.yamux import Yamux
from libp2p.stream_muxer.yamux.yamux import PROTOCOL_ID as YAMUX_PROTOCOL_ID
from cryptography.hazmat.primitives.asymmetric import x25519

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("../logs/py_ping_server.log", mode="w", encoding="utf-8"),
    ],
)

logger = logging.getLogger(__name__)

# Ping protocol constants
PING_PROTOCOL_ID = TProtocol("/ipfs/ping/1.0.0")
PING_LENGTH = 32

class PingHandler:
    def __init__(self):
        self.active_streams = {}
        self.ping_count = 0
    
    async def handle_ping(self, stream: INetStream) -> None:
        """Handle incoming ping requests according to libp2p ping spec."""
        peer_id = stream.muxed_conn.peer_id
        stream_id = id(stream)
        
        print(f"🔗 [PING] New ping stream opened by {peer_id}")
        logger.info(f"Ping handler called for peer {peer_id}, stream {stream_id}")
        
        self.active_streams[stream_id] = {
            'peer_id': peer_id,
            'stream': stream,
            'ping_count': 0
        }
        
        try:
            while True:
                try:
                    print(f"🔍 [PING] Waiting for ping data from {peer_id}...")
                    logger.debug(f"Reading {PING_LENGTH} bytes from stream {stream_id}")
                    
                    # Read exactly 32 bytes as per libp2p ping spec
                    data = await stream.read(PING_LENGTH)
                    
                    if not data or len(data) == 0:
                        print(f"📡 [PING] Connection closed by {peer_id}")
                        logger.info(f"Stream {stream_id} closed by peer")
                        break
                    
                    if len(data) != PING_LENGTH:
                        print(f"⚠️  [PING] Received {len(data)} bytes, expected {PING_LENGTH}")
                        logger.warning(f"Partial ping data: got {len(data)}, expected {PING_LENGTH}")
                        # Try to read remaining bytes
                        remaining = PING_LENGTH - len(data)
                        additional_data = await stream.read(remaining)
                        if additional_data:
                            data += additional_data
                            logger.debug(f"Read additional {len(additional_data)} bytes")
                    
                    self.active_streams[stream_id]['ping_count'] += 1
                    ping_num = self.active_streams[stream_id]['ping_count']
                    
                    print(f"🏓 [PING] [{ping_num}] Received ping from {peer_id}: {len(data)} bytes")
                    logger.debug(f"Ping {ping_num} data: {data.hex()}")
                    
                    # Echo the exact same data back (libp2p ping protocol)
                    await stream.write(data)
                    print(f"↩️  [PING] [{ping_num}] Echoed ping back to {peer_id}")
                    logger.debug(f"Ping {ping_num} response sent")
                    
                except Exception as e:
                    print(f"❌ [PING] Error in ping loop with {peer_id}: {e}")
                    logger.exception(f"Ping loop error for stream {stream_id}")
                    break
                    
        except Exception as e:
            print(f"❌ [PING] Error handling ping from {peer_id}: {e}")
            logger.exception(f"Ping handler error for stream {stream_id}")
        finally:
            try:
                print(f"🔒 [PING] Closing ping stream with {peer_id}")
                await stream.close()
                logger.info(f"Stream {stream_id} closed cleanly")
            except Exception as e:
                logger.debug(f"Error closing stream {stream_id}: {e}")
            
            if stream_id in self.active_streams:
                ping_count = self.active_streams[stream_id]['ping_count']
                del self.active_streams[stream_id]
                print(f"✅ [PING] Session completed with {peer_id} ({ping_count} pings)")

def create_noise_keypair():
    """Create Noise protocol keypair for encryption."""
    try:
        x25519_private_key = x25519.X25519PrivateKey.generate()

        class NoisePrivateKey:
            def __init__(self, key):
                self._key = key

            def to_bytes(self):
                return self._key.private_bytes_raw()

            def public_key(self):
                return NoisePublicKey(self._key.public_key())

            def get_public_key(self):
                return NoisePublicKey(self._key.public_key())

        class NoisePublicKey:
            def __init__(self, key):
                self._key = key

            def to_bytes(self):
                return self._key.public_bytes_raw()

        return NoisePrivateKey(x25519_private_key)
    except Exception as e:
        logger.error(f"Failed to create Noise keypair: {e}")
        return None

async def run_server(port: int) -> None:
    """Run ping server that accepts connections from js-libp2p clients."""
    listen_addr = multiaddr.Multiaddr(f"/ip4/0.0.0.0/tcp/{port}")
    
    # Generate identity and encryption keys
    key_pair = generate_new_rsa_identity()
    logger.debug("Generated RSA keypair for host identity")

    noise_privkey = create_noise_keypair()
    if not noise_privkey:
        print("❌ Failed to create Noise keypair")
        return
    logger.debug("Generated Noise keypair for encryption")

    # Configure security and multiplexing
    noise_transport = NoiseTransport(key_pair, noise_privkey=noise_privkey)
    sec_opt = {TProtocol("/noise"): noise_transport}
    muxer_opt = {TProtocol(YAMUX_PROTOCOL_ID): Yamux}

    logger.info(f"Security options: {list(sec_opt.keys())}")
    logger.info(f"Muxer options: {list(muxer_opt.keys())}")

    # Create libp2p host
    host = new_host(key_pair=key_pair, sec_opt=sec_opt, muxer_opt=muxer_opt)
    ping_handler = PingHandler()
    
    print("🚀 Starting py-libp2p ping server...")
    
    async with host.run(listen_addrs=[listen_addr]):
        # Register ping protocol handlers
        print(f"📝 Registering ping handler for protocol: {PING_PROTOCOL_ID}")
        host.set_stream_handler(PING_PROTOCOL_ID, ping_handler.handle_ping)
        
        # Register alternative protocol IDs for compatibility
        alt_protocols = [
            TProtocol("/ping/1.0.0"),
            TProtocol("/libp2p/ping/1.0.0"),
        ]
        
        for alt_proto in alt_protocols:
            print(f"📝 Also registering handler for: {alt_proto}")
            host.set_stream_handler(alt_proto, ping_handler.handle_ping)
        
        # Display server information
        peer_id = host.get_id()
        print("✅ Server started!")
        print(f"📋 Peer ID: {peer_id}")
        print(f"🌐 Listening: {listen_addr}")
        print(f"🏓 Primary Protocol: {PING_PROTOCOL_ID}")
        print(f"🔐 Security: Noise encryption")
        print(f"🚇 Muxer: Yamux stream multiplexing")
        
        print("\n📋 Registered protocols:")
        print(f"   - {PING_PROTOCOL_ID}")
        for proto in alt_protocols:
            print(f"   - {proto}")
        
        print(f"\n🧪 Test with js-libp2p:")
        print(f"   node ping-client.js /ip4/127.0.0.1/tcp/{port}/p2p/{peer_id}")
        
        print(f"\n🧪 Test with py-libp2p:")
        print(f"   python ping_client.py /ip4/127.0.0.1/tcp/{port}/p2p/{peer_id}")
        
        print(f"\n⏳ Waiting for connections...")
        print("Press Ctrl+C to exit")
        
        # Connection event logging
        host._network.swarm.add_conn_handler(
            lambda conn: logger.info(f"New connection from {conn.peer_id}")
        )
        
        await trio.sleep_forever()

def main():
    parser = argparse.ArgumentParser(description="py-libp2p ping server for interop testing")
    parser.add_argument('--port', '-p', type=int, default=8000,
                       help='Port to listen on (default: 8000)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    if not args.debug:
        logging.getLogger().setLevel(logging.INFO)
    
    try:
        trio.run(run_server, args.port)
    except KeyboardInterrupt:
        print("\n👋 Server stopped!")
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        logger.exception("Fatal server error")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())