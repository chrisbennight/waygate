"""Ordinary SDK transcription requests against the Rust test's local gateway."""

import io
import os
import sys
import tempfile
import wave
from urllib.parse import urlsplit

from openai import AuthenticationError, BadRequestError, OpenAI

gateway = sys.argv[1]
url = urlsplit(gateway)
if url.scheme != "http" or url.hostname != "127.0.0.1" or url.username or url.password:
    raise ValueError("transcription qualification requires the local gateway fixture")

recording = io.BytesIO()
with wave.open(recording, "wb") as wav:
    wav.setnchannels(1)
    wav.setsampwidth(2)
    wav.setframerate(16000)
    wav.writeframes(b"\x00\x00" * 1600)

with tempfile.TemporaryDirectory() as directory:
    path = os.path.join(directory, "sample.wav")
    with open(path, "wb") as output:
        output.write(recording.getvalue())
    with OpenAI(base_url=gateway, api_key="fixture-gateway", max_retries=0, timeout=10) as client:
        with open(path, "rb") as audio:
            result = client.audio.transcriptions.create(model="local-asr", file=audio)
        assert result.text == "fixture transcript"
        with open(path, "rb") as audio:
            text = client.audio.transcriptions.create(
                model="local-asr", file=audio, response_format="text"
            )
        assert text.strip() == "fixture transcript"
        with open(path, "rb") as audio:
            try:
                client.audio.transcriptions.create(
                    model="local-asr", file=audio, response_format="srt"
                )
            except BadRequestError:
                pass
            else:
                raise AssertionError("an unsupported response format was accepted")
    with OpenAI(base_url=gateway, api_key="wrong-key", max_retries=0, timeout=10) as client:
        with open(path, "rb") as audio:
            try:
                client.audio.transcriptions.create(model="local-asr", file=audio)
            except AuthenticationError:
                pass
            else:
                raise AssertionError("an unauthenticated caller was accepted")

print("transcription SDK qualification passed")
