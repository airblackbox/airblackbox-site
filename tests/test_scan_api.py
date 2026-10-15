"""POST /api/scan runs the air-blackbox SDK scanner, in every language it reads.

Starts the Vercel handler on a local port (no Redis: the free-tier fallback
path) and posts code the way the console does.
"""
import importlib.util
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="module")
def server():
    os.environ.pop("REDIS_URL", None)
    spec = importlib.util.spec_from_file_location("scan_api", os.path.join(ROOT, "api", "scan.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    httpd = HTTPServer(("127.0.0.1", 0), mod.handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_port}", mod
    httpd.shutdown()


def post(url, body):
    req = urllib.request.Request(url + "/api/scan", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


PY = ('import openai\nclient = openai.OpenAI()\n\ndef ask(q):\n'
      '    return client.chat.completions.create(model="gpt-4o", messages=q)\n')
KT = ('import dev.langchain4j.model.chat.ChatModel\n\n'
      'fun ask(model: ChatModel, q: String): String = runCatching { model.chat(q) }.getOrDefault("")\n')
TS = ('import OpenAI from "openai";\nconst client = new OpenAI();\n'
      'export async function ask(q: string) {\n  return client.chat.completions.create({ model: "gpt-4o", messages: q });\n}\n')


def test_python_paste_gets_sdk_findings(server):
    url, mod = server
    status, data = post(url, {"code": PY})
    assert status == 200, data
    assert data["meta"]["engine"] == "air-blackbox"
    assert data["meta"]["scanner_version"] == mod.SDK_VERSION
    assert data["meta"]["language"] == "python" and data["meta"]["language_source"] == "detected"
    assert data["meta"]["has_llm_calls"] is True
    names = {f["name"]: f for f in data["findings"]}
    assert names["LLM call error handling"]["status"] == "fail"
    assert names["LLM call error handling"]["severity"] == "high"
    assert "GDPR consent management" in names and "CO: Consumer AI disclosure" in names
    titles = [a["title"] for a in data["articles"]]
    assert titles[0] == "Risk Management" and "GDPR Data Protection" in titles
    assert 0 <= data["score"] <= 100
    assert "openai" in data["meta"]["frameworks_detected"]


def test_kotlin_and_typescript_are_detected(server):
    url, _ = server
    status, kt = post(url, {"code": KT})
    assert status == 200 and kt["meta"]["language"] == "kotlin"
    assert "LangChain4j" in kt["meta"]["frameworks_detected"]
    assert {f["name"]: f["status"] for f in kt["findings"]}["LLM call error handling"] == "pass"
    status, ts = post(url, {"code": TS})
    assert status == 200 and ts["meta"]["language"] == "typescript"


def test_stated_language_and_filename(server):
    url, _ = server
    status, data = post(url, {"code": PY, "language": "Python"})
    assert status == 200 and data["meta"]["language_source"] == "stated"
    status, data = post(url, {"code": TS, "filename": "agent.ts"})
    assert status == 200 and data["meta"]["language_source"] == "filename"
    status, data = post(url, {"code": PY, "language": "cobol"})
    assert status == 400 and "Unknown language" in data["error"]


def test_a_chat_app_is_not_a_hiring_system(server):
    """The old copy of the scanner matched 'chats' as 'ats' and failed NYC LL144."""
    url, _ = server
    code = 'def list_chats(user):\n    stream = open_stream(resume=True)\n    return rerank(candidates=stream.read())\n'
    _, data = post(url, {"code": code})
    assert not any(f["article"] == 16 for f in data["findings"])


def test_explanations_still_attach_to_renamed_checks(server):
    url, _ = server
    _, data = post(url, {"code": PY})
    logging = next(f for f in data["findings"] if f["name"] == "Application logging")
    assert logging["meaning"] and logging["meaning"] != logging["evidence"]
