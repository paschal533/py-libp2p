#!/usr/bin/env python3

import argparse
import multiaddr
import trio
import logging
import time
from libp2p import generate_new_rsa_identity, new_host
from libp2p.custom_types import TProtocol
from libp2p.network.stream.net_stream import INetStream
from libp2p.security.noise.transport import Transport as NoiseTransport
from libp2p.stream_muxer.yamux.yamux import Yamux
from libp2p.stream_muxer.yamux.yamux import PROTOCOL_ID as YAMUX_PROTOCOL_ID
from cryptography.hazmat.primitives.asymmetric import x25519
import secrets

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("../logs/py_ping_client.log", mode="w", encoding="utf-8"),
    ],
)

logger = logging.getLogger(__name__)

# Ping protocol constants
PING_PROTOCOL_ID = TProtocol("/ipfs/ping/1.0.0")
PING_LENGTH = 32

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

async def ping_peer(host, target_addr: str, count: int = 5) -> None:
    """Send ping requests to target peer."""
    print(f"🎯 Target: {target_addr}")
    
    try:
        # Parse target multiaddr
        target_ma = multiaddr.Multiaddr(target_addr)
        target_peer_id = target_ma.getPeerId()
        
        if not target_peer_id:
            raise ValueError("Could not extract peer ID from multiaddr")
        
        print(f"🎯 Target Peer ID: {target_peer_id}")
        logger.info(f"Attempting to connect to {target_peer_id}")
        
        # Connect to peer
        print("🔗 Connecting to peer...")
        await host.connect(target_ma)
        print("✅ Connection established!")
        logger.info(f"Connected to {target_peer_id}")
        
        # Open ping stream
        print(f"🔄 Opening ping stream with protocol: {PING_PROTOCOL_ID}")
        stream = await host.new_stream(target_peer_id, [PING_PROTOCOL_ID])
        logger.info(f"Ping stream opened: {stream}")
        
        print(f"\n🏓 Starting ping sequence ({count} pings)...")
        rtts = []
        
        for i in range(1, count + 1):
            try:
                print(f"\n🏓 Sending ping {i}/{count}...")
                
                # Generate random 32-byte payload
                ping_data = secrets.token_bytes(PING_LENGTH)
                logger.debug(f"Ping {i} payload: {ping_data.hex()}")
                
                start_time = time.time()
                
                # Send ping
                await stream.write(ping_data)
                logger.debug(f"Ping {i} data sent")
                
                # Read response
                response = await stream.read(PING_LENGTH)
                end_time = time.time()
                
                if len(response) != PING_LENGTH:
                    raise ValueError(f"Expected {PING_LENGTH} bytes, got {len(response)}")
                
                if response != ping_data:
                    raise ValueError("Response data doesn't match sent data")
                
                rtt = (end_time - start_time) * 1000  # Convert to milliseconds
                rtts.append(rtt)
                
                print(f"✅ Ping {i} successful!")
                print(f"   RTT: {rtt:.2f}ms")
                logger.info(f"Ping {i}: RTT={rtt:.2f}ms")
                
                # Wait between pings
                if i < count:
                    await trio.sleep(1)
                    
            except Exception as e:
                print(f"❌ Ping {i} failed: {e}")
                logger.error(f"Ping {i} failed: {e}")
        
        # Close stream
        print("\n🔒 Closing ping stream...")
        await stream.close()
        logger.info("Ping stream closed")
        
        # Print statistics
        if rtts:
            avg_rtt = sum(rtts) / len(rtts)
            min_rtt = min(rtts)
            max_rtt = max(rtts)
            loss_rate = ((count - len(rtts)) / count) * 100
            
            print(f"\n📊 Ping Statistics:")
            print(f"   Packets: Sent={count}, Received={len(rtts)}, Lost={count - len(rtts)}")
            print(f"   Loss rate: {loss_rate:.1f}%")
            print(f"   RTT: min={min_rtt:.2f}ms, avg={avg_rtt:.2f}ms, max={max_rtt:.2f}ms")
        else:
            print(f"\n📊 All pings failed ({count} attempts)")
            
    except Exception as e:
        print(f"❌ Client error: {e}")
        logger.exception("Client error")
        raise

async def run_client(target_addr: str, count: int) -> None:
    """Run ping client that connects to js-libp2p or py-libp2p servers."""
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
    
    print("🚀 Starting py-libp2p ping client...")
    
    async with host.run():
        peer_id = host.get_id()
        print(f"📋 Our Peer ID: {peer_id}")
        logger.info(f"Client started with peer ID: {peer_id}")
        
        await ping_peer(host, target_addr, count)

def main():
    parser = argparse.ArgumentParser(description="py-libp2p ping client for interop testing")
    parser.add_argument('target', help='Target multiaddr (e.g., /ip4/127.0.0.1/tcp/8000/p2p/...)')
    parser.add_argument('--count', '-c', type=int, default=5,
                       help='Number of ping packets to send (default: 5)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    if not args.debug:
        logging.getLogger().setLevel(logging.INFO)
    
    if args.count <= 0 or args.count > 100:
        print("❌ Count must be between 1 and 100")
        return 1
    
    try:
        trio.run(run_client, args.target, args.count)
        print("⏹️  Client stopped")
    except KeyboardInterrupt:
        print("\n👋 Client stopped!")
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        logger.exception("Fatal client error")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())