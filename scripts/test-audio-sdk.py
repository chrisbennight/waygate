"""Ordinary SDK requests and an application WebRTC peer against the Rust fixture."""

import asyncio
import base64
import io
import json
import statistics
import sys
import time
import wave
from urllib.parse import urlsplit

from aiortc import RTCConfiguration, RTCPeerConnection, RTCSessionDescription
from openai import AsyncOpenAI, OpenAI, NotFoundError


def loopback(value):
    url = urlsplit(value)
    if url.scheme != "http" or url.hostname != "127.0.0.1" or url.username or url.password:
        raise ValueError("audio qualification requires a loopback fixture")
    return value


gateway = loopback(sys.argv[1])
provider = loopback(sys.argv[2])


def speech_and_resources():
    with OpenAI(base_url=gateway, api_key="fixture-gateway", max_retries=0, timeout=10) as client:
        audio = client.audio.speech.create(model="speech", input="Fixture narration", voice="narrator", instructions="Quiet fixture direction", response_format="wav", speed=1)
        with wave.open(io.BytesIO(audio.content), "rb") as wav:
            assert wav.getnframes() == 480
        with client.audio.speech.with_streaming_response.create(model="speech", input="Fixture narration", voice="narrator", response_format="pcm") as stream:
            chunks = stream.iter_bytes(chunk_size=100)
            first = next(chunks)
            assert first == b"\x01\x00" * 50
            assert len(first + b"".join(chunks)) == 960
        with client.audio.speech.with_streaming_response.create(model="speech", input="Fixture narration", voice="narrator", response_format="pcm", stream_format="sse") as events:
            observed = [json.loads(line[6:]) for line in events.iter_lines() if line.startswith("data: ")]
        assert [event["type"] for event in observed] == ["speech.audio.delta", "speech.audio.done"]
        assert base64.b64decode(observed[0]["audio"])
        recording = audio.content
        consent = client.audio.voice_consents.create(name="Fixture consent", language="en-US", recording=("consent.wav", recording, "audio/wav"))
        assert client.audio.voice_consents.retrieve(consent.id).id == consent.id
        assert client.audio.voice_consents.update(consent.id, name="Renamed fixture").name == "Renamed fixture"
        assert next(iter(client.audio.voice_consents.list(limit=10))).id == consent.id
        voice = client.audio.voices.create(name="Fixture voice", consent=consent.id, audio_sample=("voice.wav", recording, "audio/wav"))
        assert client.audio.speech.create(model="speech", input="Fixture narration", voice={"id": voice.id}, response_format="pcm").content
        assert client.audio.voices.delete(voice.id).deleted
        try:
            client.audio.speech.create(model="speech", input="Fixture narration", voice={"id": voice.id}, response_format="pcm")
        except NotFoundError:
            pass
        else:
            raise AssertionError("deleted voice remained selectable")
        assert client.audio.voice_consents.retrieve(consent.id).id == consent.id
        assert client.audio.voice_consents.delete(consent.id).deleted


async def websocket(base_url, key, model):
    started = time.perf_counter()
    first_audio = None
    async with AsyncOpenAI(base_url=base_url, api_key=key, max_retries=0, timeout=10) as client:
        async with client.realtime.connect(model=model) as connection:
            await connection.session.update(session={"type": "realtime", "output_modalities": ["audio"], "audio": {"output": {"voice": "narrator"}}})
            await connection.conversation.item.create(item={"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Fixture narration"}]})
            await connection.response.create()
            transcript = False
            async for event in connection:
                if event.type == "response.output_audio.delta":
                    assert base64.b64decode(event.delta)
                    first_audio = (time.perf_counter() - started) * 1000
                if event.type == "response.output_audio_transcript.delta":
                    transcript = True
                if event.type == "response.done":
                    assert event.response.status == "completed" and transcript
                    break
            await connection.response.create()
            async for event in connection:
                if event.type == "response.output_audio.delta":
                    await connection.response.cancel()
                if event.type == "response.done":
                    assert event.response.status == "cancelled"
                    break
            await connection.conversation.item.truncate(item_id="item_audio", content_index=0, audio_end_ms=10)
            async for event in connection:
                if event.type == "conversation.item.truncated":
                    assert event.item_id == "item_audio"
                    break
    assert first_audio is not None
    return round(first_audio, 2)


async def webrtc():
    pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
    pc.addTransceiver("audio", direction="recvonly")
    channel = pc.createDataChannel("oai-events")
    opened = asyncio.Event()
    completed = asyncio.Event()
    cancelled = asyncio.Event()
    media = asyncio.Event()
    transcript = asyncio.Event()
    unsupported = asyncio.Event()

    @channel.on("open")
    def ready():
        opened.set()

    @channel.on("message")
    def event(data):
        value = json.loads(data)
        if value["type"] == "error" and value["error"]["code"] == "unsupported_option":
            unsupported.set()
        if value["type"] == "response.output_audio_transcript.delta":
            transcript.set()
        if value["type"] == "response.done":
            (completed if value["response"]["status"] == "completed" else cancelled).set()
        if value["type"] == "response.output_audio.delta" and completed.is_set():
            channel.send(json.dumps({"type": "response.cancel"}))

    @pc.on("track")
    def track(track):
        async def consume():
            while True:
                frame = await track.recv()
                if any(bytes(frame.planes[0])):
                    media.set()
        asyncio.create_task(consume())

    async with AsyncOpenAI(base_url=gateway, api_key="fixture-gateway", max_retries=0, timeout=15) as client:
        await pc.setLocalDescription(await pc.createOffer())
        answer = await client.realtime.calls.with_raw_response.create(sdp=pc.localDescription.sdp, session={"type": "realtime", "model": "live", "output_modalities": ["audio"], "audio": {"output": {"voice": "narrator"}}})
        location = answer.headers["location"]
        assert location.startswith("/v1/realtime/calls/call_")
        assert answer.headers["content-type"].startswith("application/sdp")
        sdp = answer.parse().content.decode()
        try:
            await pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="answer"))
            await asyncio.wait_for(opened.wait(), 15)
            channel.send(json.dumps({"type": "response.create", "response": {"instructions": "unsupported fixture direction"}}))
            await asyncio.wait_for(unsupported.wait(), 5)
            channel.send(json.dumps({"type": "conversation.item.create", "item": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Fixture narration"}]}}))
            channel.send(json.dumps({"type": "response.create"}))
            await asyncio.wait_for(asyncio.gather(completed.wait(), transcript.wait(), media.wait()), 15)
            channel.send(json.dumps({"type": "response.create"}))
            await asyncio.wait_for(cancelled.wait(), 10)
        finally:
            await client.realtime.calls.hangup(location.rsplit("/", 1)[-1])
            await pc.close()


async def main():
    speech_and_resources()
    targets = {"direct": (provider, "fixture-provider", "fixture-live"), "gateway": (gateway, "fixture-gateway", "live")}
    for target in targets.values():
        await asyncio.wait_for(websocket(*target), 15)
    samples = {name: [] for name in targets}
    for index in range(3):
        for name in (["direct", "gateway"] if index % 2 == 0 else ["gateway", "direct"]):
            samples[name].append(await asyncio.wait_for(websocket(*targets[name]), 15))
    medians = {name: round(statistics.median(values), 2) for name, values in samples.items()}
    await webrtc()
    print(json.dumps({"speech": "wav/early PCM/SSE/direction", "resources": "consent and voice lifecycle", "websocket": "audio/transcript/completion/cancel/truncate", "webrtc": "Opus decoded and data channel events", "first_audio_ms": {"samples": samples, "median": medians, "added_gateway_median_ms": round(medians["gateway"] - medians["direct"], 2)}}))


if __name__ == "__main__":
    asyncio.run(main())
