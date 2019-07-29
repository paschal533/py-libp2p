import asyncio
import io
from typing import NamedTuple

import pytest

from libp2p.peer.id import ID
from libp2p.pubsub.pb import rpc_pb2

from tests.utils import (
    connect,
)

from .utils import (
    make_pubsub_msg,
)


TESTING_TOPIC = "TEST_SUBSCRIBE"
TESTING_DATA = b"data"


@pytest.mark.parametrize(
    "num_hosts",
    (1,),
)
@pytest.mark.asyncio
async def test_subscribe_and_unsubscribe(pubsubs_fsub):
    await pubsubs_fsub[0].subscribe(TESTING_TOPIC)
    assert TESTING_TOPIC in pubsubs_fsub[0].my_topics

    await pubsubs_fsub[0].unsubscribe(TESTING_TOPIC)
    assert TESTING_TOPIC not in pubsubs_fsub[0].my_topics


@pytest.mark.parametrize(
    "num_hosts",
    (1,),
)
@pytest.mark.asyncio
async def test_re_subscribe(pubsubs_fsub):
    await pubsubs_fsub[0].subscribe(TESTING_TOPIC)
    assert TESTING_TOPIC in pubsubs_fsub[0].my_topics

    await pubsubs_fsub[0].subscribe(TESTING_TOPIC)
    assert TESTING_TOPIC in pubsubs_fsub[0].my_topics


@pytest.mark.parametrize(
    "num_hosts",
    (1,),
)
@pytest.mark.asyncio
async def test_re_unsubscribe(pubsubs_fsub):
    # Unsubscribe from topic we didn't even subscribe to
    assert "NOT_MY_TOPIC" not in pubsubs_fsub[0].my_topics
    await pubsubs_fsub[0].unsubscribe("NOT_MY_TOPIC")
    assert "NOT_MY_TOPIC" not in pubsubs_fsub[0].my_topics

    await pubsubs_fsub[0].subscribe(TESTING_TOPIC)
    assert TESTING_TOPIC in pubsubs_fsub[0].my_topics

    await pubsubs_fsub[0].unsubscribe(TESTING_TOPIC)
    assert TESTING_TOPIC not in pubsubs_fsub[0].my_topics

    await pubsubs_fsub[0].unsubscribe(TESTING_TOPIC)
    assert TESTING_TOPIC not in pubsubs_fsub[0].my_topics


@pytest.mark.asyncio
async def test_peers_subscribe(pubsubs_fsub):
    await connect(pubsubs_fsub[0].host, pubsubs_fsub[1].host)
    await pubsubs_fsub[0].subscribe(TESTING_TOPIC)
    # Yield to let 0 notify 1
    await asyncio.sleep(0.1)
    assert str(pubsubs_fsub[0].my_id) in pubsubs_fsub[1].peer_topics[TESTING_TOPIC]
    await pubsubs_fsub[0].unsubscribe(TESTING_TOPIC)
    # Yield to let 0 notify 1
    await asyncio.sleep(0.1)
    assert str(pubsubs_fsub[0].my_id) not in pubsubs_fsub[1].peer_topics[TESTING_TOPIC]


@pytest.mark.parametrize(
    "num_hosts",
    (1,),
)
@pytest.mark.asyncio
async def test_get_hello_packet(pubsubs_fsub):
    def _get_hello_packet_topic_ids():
        packet = rpc_pb2.RPC()
        packet.ParseFromString(pubsubs_fsub[0].get_hello_packet())
        return tuple(
            sub.topicid
            for sub in packet.subscriptions
        )

    # pylint: disable=len-as-condition
    # Test: No subscription, so there should not be any topic ids in the hello packet.
    assert len(_get_hello_packet_topic_ids()) == 0

    # Test: After subscriptions, topic ids should be in the hello packet.
    topic_ids = ["t", "o", "p", "i", "c"]
    await asyncio.gather(*[
        pubsubs_fsub[0].subscribe(topic)
        for topic in topic_ids
    ])
    topic_ids_in_hello = _get_hello_packet_topic_ids()
    for topic in topic_ids:
        assert topic in topic_ids_in_hello


class FakeNetStream:
    _queue: asyncio.Queue

    class FakeMplexConn(NamedTuple):
        peer_id: ID = ID(b"\x12\x20" + b"\x00" * 32)

    mplex_conn = FakeMplexConn()

    def __init__(self) -> None:
        self._queue = asyncio.Queue()

    async def read(self) -> bytes:
        buf = io.BytesIO()
        while not self._queue.empty():
            buf.write(await self._queue.get())
        return buf.getvalue()

    async def write(self, data: bytes) -> int:
        for i in data:
            await self._queue.put(i.to_bytes(1, 'big'))
        return len(data)


@pytest.mark.parametrize(
    "num_hosts",
    (1,),
)
@pytest.mark.asyncio
async def test_continuously_read_stream(pubsubs_fsub, monkeypatch):
    s = FakeNetStream()

    await pubsubs_fsub[0].subscribe(TESTING_TOPIC)

    event_push_msg = asyncio.Event()
    event_handle_subscription = asyncio.Event()
    event_handle_rpc = asyncio.Event()

    async def mock_push_msg(msg_forwarder, msg):
        event_push_msg.set()

    def mock_handle_subscription(origin_id, sub_message):
        event_handle_subscription.set()

    async def mock_handle_rpc(rpc, sender_peer_id):
        event_handle_rpc.set()

    monkeypatch.setattr(pubsubs_fsub[0], "push_msg", mock_push_msg)
    monkeypatch.setattr(pubsubs_fsub[0], "handle_subscription", mock_handle_subscription)
    monkeypatch.setattr(pubsubs_fsub[0].router, "handle_rpc", mock_handle_rpc)

    async def wait_for_event_occurring(event):
        try:
            await asyncio.wait_for(event.wait(), timeout=0.01)
        except asyncio.TimeoutError as error:
            event.clear()
            raise asyncio.TimeoutError(
                f"Event {event} is not set before the timeout. "
                "This indicates the mocked functions are not called properly."
            ) from error
        else:
            event.clear()

    # Kick off the task `continuously_read_stream`
    task = asyncio.ensure_future(pubsubs_fsub[0].continuously_read_stream(s))

    # Test: `push_msg` is called when publishing to a subscribed topic.
    publish_subscribed_topic = rpc_pb2.RPC(
        publish=[rpc_pb2.Message(
            topicIDs=[TESTING_TOPIC]
        )],
    )
    await s.write(publish_subscribed_topic.SerializeToString())
    await wait_for_event_occurring(event_push_msg)
    # Make sure the other events are not emitted.
    with pytest.raises(asyncio.TimeoutError):
        await wait_for_event_occurring(event_handle_subscription)
    with pytest.raises(asyncio.TimeoutError):
        await wait_for_event_occurring(event_handle_rpc)

    # Test: `push_msg` is not called when publishing to a topic-not-subscribed.
    publish_not_subscribed_topic = rpc_pb2.RPC(
        publish=[rpc_pb2.Message(
            topicIDs=["NOT_SUBSCRIBED"]
        )],
    )
    await s.write(publish_not_subscribed_topic.SerializeToString())
    with pytest.raises(asyncio.TimeoutError):
        await wait_for_event_occurring(event_push_msg)

    # Test: `handle_subscription` is called when a subscription message is received.
    subscription_msg = rpc_pb2.RPC(
        subscriptions=[rpc_pb2.RPC.SubOpts()],
    )
    await s.write(subscription_msg.SerializeToString())
    await wait_for_event_occurring(event_handle_subscription)
    # Make sure the other events are not emitted.
    with pytest.raises(asyncio.TimeoutError):
        await wait_for_event_occurring(event_push_msg)
    with pytest.raises(asyncio.TimeoutError):
        await wait_for_event_occurring(event_handle_rpc)

    # Test: `handle_rpc` is called when a control message is received.
    control_msg = rpc_pb2.RPC(control=rpc_pb2.ControlMessage())
    await s.write(control_msg.SerializeToString())
    await wait_for_event_occurring(event_handle_rpc)
    # Make sure the other events are not emitted.
    with pytest.raises(asyncio.TimeoutError):
        await wait_for_event_occurring(event_push_msg)
    with pytest.raises(asyncio.TimeoutError):
        await wait_for_event_occurring(event_handle_subscription)

    task.cancel()


@pytest.mark.parametrize(
    "num_hosts",
    (2,),
)
@pytest.mark.asyncio
async def test_publish(pubsubs_fsub, monkeypatch):
    msg_forwarders = []
    msgs = []

    async def push_msg(msg_forwarder, msg):
        msg_forwarders.append(msg_forwarder)
        msgs.append(msg)
    monkeypatch.setattr(pubsubs_fsub[0], "push_msg", push_msg)

    await pubsubs_fsub[0].publish(TESTING_TOPIC, TESTING_DATA)
    await pubsubs_fsub[0].publish(TESTING_TOPIC, TESTING_DATA)

    assert len(msgs) == 2, "`push_msg` should be called every time `publish` is called"
    assert (msg_forwarders[0] == msg_forwarders[1]) and (msg_forwarders[1] == pubsubs_fsub[0].my_id)
    assert msgs[0].seqno != msgs[1].seqno, "`seqno` should be different every time"


@pytest.mark.parametrize(
    "num_hosts",
    (1,),
)
@pytest.mark.asyncio
async def test_push_msg(pubsubs_fsub, monkeypatch):
    # pylint: disable=protected-access
    msg_0 = make_pubsub_msg(
        origin_id=pubsubs_fsub[0].my_id,
        topic_ids=[TESTING_TOPIC],
        data=TESTING_DATA,
        seqno=b"\x00" * 8,
    )

    event = asyncio.Event()

    async def router_publish(*args, **kwargs):
        event.set()
    monkeypatch.setattr(pubsubs_fsub[0].router, "publish", router_publish)

    # Test: `msg` is not seen before `push_msg`, and is seen after `push_msg`.
    assert not pubsubs_fsub[0]._is_msg_seen(msg_0)
    await pubsubs_fsub[0].push_msg(pubsubs_fsub[0].my_id, msg_0)
    assert pubsubs_fsub[0]._is_msg_seen(msg_0)
    # Test: Ensure `router.publish` is called in `push_msg`
    await asyncio.wait_for(event.wait(), timeout=0.1)

    # Test: `push_msg` the message again and it will be reject.
    #   `router_publish` is not called then.
    event.clear()
    await pubsubs_fsub[0].push_msg(pubsubs_fsub[0].my_id, msg_0)
    await asyncio.sleep(0.01)
    assert not event.is_set()

    sub = await pubsubs_fsub[0].subscribe(TESTING_TOPIC)
    # Test: `push_msg` succeeds with another unseen msg.
    msg_1 = make_pubsub_msg(
        origin_id=pubsubs_fsub[0].my_id,
        topic_ids=[TESTING_TOPIC],
        data=TESTING_DATA,
        seqno=b"\x11" * 8,
    )
    assert not pubsubs_fsub[0]._is_msg_seen(msg_1)
    await pubsubs_fsub[0].push_msg(pubsubs_fsub[0].my_id, msg_1)
    assert pubsubs_fsub[0]._is_msg_seen(msg_1)
    await asyncio.wait_for(event.wait(), timeout=0.1)
    # Test: Subscribers are notified when `push_msg` new messages.
    assert (await sub.get()) == msg_1
