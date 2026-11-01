"""Loopback-only standard audio provider for opt-in client/media qualification."""

import asyncio
import base64
import io
import json
import math
import struct
import wave

from aiohttp import web, WSMsgType
from aiortc import AudioStreamTrack, RTCConfiguration, RTCPeerConnection, RTCSessionDescription
from av import AudioFrame


class Tone(AudioStreamTrack):
    def __init__(self, enabled, first_frame):
        super().__init__()
        self.samples = 0
        self.enabled = enabled
        self.first_frame = first_frame

    async def recv(self):
        await self.enabled.wait()
        await asyncio.sleep(0.02)
        frame = AudioFrame(format="s16", layout="mono", samples=960)
        frame.sample_rate = 48000
        frame.pts = self.samples
        from fractions import Fraction
        frame.time_base = Fraction(1, 48000)
        pcm = struct.pack("<960h", *(int(6000 * math.sin(2 * math.pi * 440 * (self.samples + i) / 48000)) for i in range(960)))
        frame.planes[0].update(pcm)
        self.samples += 960
        self.first_frame.set()
        return frame


def wav_bytes():
    out = io.BytesIO()
    with wave.open(out, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(24000)
        wav.writeframes(b"\x01\x00" * 480)
    return out.getvalue()


async def serve():
    calls = {}
    consents = {}
    voices = {}
    pcm = b"\x01\x00" * 480

    @web.middleware
    async def authenticated(req, handler):
        if req.headers.get("Authorization") != "Bearer fixture-provider":
            return web.json_response({"error": {"message": "fixture authorization failed"}}, status=401)
        return await handler(req)

    async def speech(req):
        body = await req.json()
        assert body["model"] == "fixture-speech"
        if "instructions" in body:
            assert body["instructions"] == "Quiet fixture direction"
            assert body["speed"] == 1
        if isinstance(body["voice"], dict) and body["voice"]["id"] not in voices:
            return web.json_response({"error": {"message": "voice missing"}}, status=404)
        if body.get("stream_format") == "sse":
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(req)
            for event in [{"type": "speech.audio.delta", "audio": base64.b64encode(pcm).decode()}, {"type": "speech.audio.done", "usage": {"input_tokens": 0, "output_tokens": 0}}]:
                await response.write(("data: " + json.dumps(event) + "\n\n").encode())
            return response
        data = wav_bytes() if body.get("response_format") == "wav" else pcm
        response = web.StreamResponse(headers={"Content-Type": "audio/wav" if body.get("response_format") == "wav" else "audio/pcm"})
        await response.prepare(req)
        await response.write(data[:100])
        await asyncio.sleep(0.05)
        await response.write(data[100:])
        return response

    async def resources(req):
        collection = "voice_consents" if "voice_consents" in req.path else "voices"
        store = consents if collection == "voice_consents" else voices
        prefix = "cons_fixture" if collection == "voice_consents" else "voice_fixture"
        identifier = req.match_info.get("id")
        kind = "audio.voice_consent" if collection == "voice_consents" else "audio.voice"
        if req.method == "DELETE":
            if identifier not in store:
                return web.json_response({"error": {"message": "missing"}}, status=404)
            del store[identifier]
            return web.json_response({"id": identifier, "object": kind if collection == "voice_consents" else "audio.voice.deleted", "deleted": True})
        if req.method == "GET":
            return web.json_response(store[identifier] if identifier else {"object": "list", "data": list(store.values()), "has_more": False})
        if identifier:
            fields = await req.json()
            store[identifier].update(fields)
            return web.json_response(store[identifier])
        form = await req.post()
        assert "recording" in form if collection == "voice_consents" else "audio_sample" in form
        value = {"id": prefix, "object": kind, "name": form["name"], "created_at": 42}
        if collection == "voice_consents":
            value["language"] = form["language"]
        else:
            assert form["consent"] in consents
            value["type"] = "audio_sample"
        store[prefix] = value
        return web.json_response(value)

    async def handle_event(event, emit, state):
        kind = event["type"]
        if "pc" in state and kind == "response.create" and event.get("response", {}).get("instructions"):
            await emit({"type": "error", "error": {"type": "invalid_request_error", "code": "unsupported_option", "message": "Fixture provider does not support response instructions"}})
            return
        if kind == "session.update":
            await emit({"type": "session.updated", "session": event["session"]})
        elif kind == "conversation.item.create":
            await emit({"type": "conversation.item.created", "item": {"id": "item_user", **event["item"]}})
        elif kind == "response.create":
            state["ordinal"] = state.get("ordinal", 0) + 1
            response_id = "resp_" + str(state["ordinal"])
            await emit({"type": "response.created", "response": {"id": response_id, "status": "in_progress"}})
            await emit({"type": "response.output_item.added", "response_id": response_id, "output_index": 0, "item": {"id": "item_audio", "type": "message", "role": "assistant", "status": "in_progress", "content": []}})
            await emit({"type": "response.output_audio.delta", "response_id": response_id, "item_id": "item_audio", "output_index": 0, "content_index": 0, "delta": base64.b64encode(pcm).decode()})
            if "pc" in state:
                state["enabled"].set()
                await state["first_frame"].wait()
                await emit({"type": "output_audio_buffer.started", "response_id": response_id})
            await emit({"type": "response.output_audio_transcript.delta", "response_id": response_id, "item_id": "item_audio", "output_index": 0, "content_index": 0, "delta": "Fixture narration"})
            # The client cancels the second response while it is in progress.
            if state["ordinal"] == 1:
                await emit({"type": "response.done", "response": {"id": response_id, "status": "completed", "output": [], "usage": {"input_tokens": 0, "output_tokens": 0}}})
        elif kind == "response.cancel":
            if "pc" in state:
                state["enabled"].clear()
            await emit({"type": "response.done", "response": {"id": "resp_" + str(state["ordinal"]), "status": "cancelled", "output": [], "usage": {"input_tokens": 0, "output_tokens": 0}}})
        elif kind == "conversation.item.truncate":
            await emit({"type": "conversation.item.truncated", "item_id": event["item_id"], "content_index": event["content_index"], "audio_end_ms": event["audio_end_ms"]})

    async def realtime(req):
        ws = web.WebSocketResponse()
        await ws.prepare(req)
        call_id = req.query.get("call_id")
        if call_id:
            state = calls[call_id]
            state["sideband"] = ws
        else:
            assert req.query["model"] == "fixture-live"
            state = {}
        await ws.send_json({"type": "session.created", "session": {"type": "realtime", "id": "sess_fixture", "model": "fixture-live"}})
        async for message in ws:
            if message.type == WSMsgType.TEXT:
                await handle_event(json.loads(message.data), ws.send_json, state)
        return ws

    async def create_call(req):
        form = await req.post()
        session = json.loads(form["session"])
        assert session["type"] == "realtime" and session["model"] == "fixture-live"
        pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
        state = {"pc": pc, "enabled": asyncio.Event(), "first_frame": asyncio.Event()}
        call_id = "call_" + str(len(calls) + 1)
        calls[call_id] = state
        pc.addTrack(Tone(state["enabled"], state["first_frame"]))

        @pc.on("datachannel")
        def datachannel(channel):
            assert channel.label == "oai-events"

            async def emit(event):
                channel.send(json.dumps(event))
                if "sideband" in state:
                    await state["sideband"].send_json(event)

            @channel.on("message")
            def message(data):
                asyncio.create_task(handle_event(json.loads(data), emit, state))

        await pc.setRemoteDescription(RTCSessionDescription(sdp=form["sdp"], type="offer"))
        await pc.setLocalDescription(await pc.createAnswer())
        return web.Response(status=201, text=pc.localDescription.sdp, content_type="application/sdp", headers={"Location": "/v1/realtime/calls/" + call_id})

    async def hangup(req):
        state = calls.pop(req.match_info["id"], None)
        if state is None:
            return web.Response(status=404)
        if "sideband" in state:
            await state["sideband"].close()
        await state["pc"].close()
        return web.Response(status=200)

    app = web.Application(middlewares=[authenticated], client_max_size=12 * 1024 * 1024)
    app.router.add_post("/v1/audio/speech", speech)
    app.router.add_route("*", "/v1/audio/voices", resources)
    app.router.add_route("*", "/v1/audio/voices/{id}", resources)
    app.router.add_route("*", "/v1/audio/voice_consents", resources)
    app.router.add_route("*", "/v1/audio/voice_consents/{id}", resources)
    app.router.add_get("/v1/realtime", realtime)
    app.router.add_post("/v1/realtime/calls", create_call)
    app.router.add_post("/v1/realtime/calls/{id}/hangup", hangup)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    print(json.dumps({"base_url": "http://127.0.0.1:" + str(port) + "/v1"}), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        for state in calls.values():
            await state["pc"].close()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(serve())
