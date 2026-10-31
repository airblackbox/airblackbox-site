"""Malformed bundles the browser verifier must refuse, matching air-evidence.

Built from genuine bundles: demo/sample.air-evidence, and fixtures written by
the TypeScript package with fictional data (tests/fixtures/). Each malformed
case was accepted, or read as authentic, before the check that now catches it;
the genuine ones must still pass.
Run it with:
    pip install playwright && playwright install chromium
    python tests/test_verify_malformed.py
"""
import functools, glob, http.server, io, os, socketserver, sys, tempfile, threading, zipfile

from playwright.sync_api import sync_playwright

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
PORT = 8934


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def serve():
    h = functools.partial(_Quiet, directory=ROOT)
    socketserver.TCPServer.allow_reuse_address = True
    s = socketserver.TCPServer(("127.0.0.1", PORT), h)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def launch_chromium(p):
    """As in test_verify_edges.py: CHROMIUM_PATH, then PLAYWRIGHT_BROWSERS_PATH, then the default."""
    exe = os.environ.get("CHROMIUM_PATH")
    if not exe:
        base = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
        if base:
            hits = sorted(glob.glob(os.path.join(base, "chromium-*", "chrome-linux", "chrome")))
            exe = hits[-1] if hits else None
    return p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
SAMPLE = os.path.join(ROOT, 'demo', 'sample.air-evidence')
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')


def rewrite(src, replace):
    out = io.BytesIO()
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            zout.writestr(info, replace.get(info.filename, zin.read(info.filename)))
    return out.getvalue()


def cases(tmp):
    genuine = open(SAMPLE, "rb").read()
    with zipfile.ZipFile(SAMPLE) as z:
        manifest = z.read("manifest.json")
    decoy = io.BytesIO()
    with zipfile.ZipFile(decoy, "w") as z:
        z.writestr("readme.txt", "nothing to see")
    variants = {
        # name: (bytes, expect bad?, text the page must show)
        "genuine": (genuine, False, ""),
        "repeated manifest key": (rewrite(SAMPLE, {"manifest.json":
            b'{"bundle_id": "FORGED-BY-ATTACKER", "counts": {"actions": 999},' + manifest[1:]}),
            True, "repeats the key"),
        "bytes after the archive": (genuine + b"<script>payload()</script>", True, "bytes follow the end"),
        "document before the archive": (b"%PDF-1.4 decoy\n" + genuine, True, "does not begin with the archive"),
        # Refused either way; which check names it depends on the offsets.
        "zip before the archive": (decoy.getvalue() + genuine, True, ""),
        "chain broken at export": (open(os.path.join(FIXTURES, "broken-chain.air-evidence"), "rb").read(),
                                   True, "already broken"),
        "unanchored, reason recorded": (open(os.path.join(FIXTURES, "unanchored.air-evidence"), "rb").read(),
                                        False, "Recorded reason: anchoring disabled"),
        # Written by the streaming export: manifest.json last, sizes in data
        # descriptors after each member, members deflated in 64 KB pieces.
        "streamed export": (open(os.path.join(FIXTURES, "streamed.air-evidence"), "rb").read(),
                            False, "ed25519:4efd9b2ddbb9fe18"),
    }
    paths = {}
    for name, (data, bad, text) in variants.items():
        p = os.path.join(tmp, name.replace(" ", "_").replace(",", "") + ".air-evidence")
        open(p, "wb").write(data)
        paths[name] = (p, bad, text)
    return paths


def main():
    httpd = serve(); base = f"http://127.0.0.1:{PORT}"; failures = []
    with tempfile.TemporaryDirectory() as tmp, sync_playwright() as p:
        b = launch_chromium(p)
        for name, (path, want_bad, want_text) in cases(tmp).items():
            pg = b.new_page()
            pg.goto(f"{base}/verify.html")
            pg.set_input_files("#file", path)
            pg.wait_for_selector(".verdict h2", timeout=20000)
            pg.wait_for_function("() => !document.querySelector('.verdict h2').innerText.includes('Checking')",
                                 timeout=20000)
            verdict = pg.inner_text(".verdict h2").strip()
            page_text = pg.inner_text("body")
            bad = verdict.startswith(("Do not rely", "Could not check"))
            print(f"[{name}] -> {verdict}")
            if bad != want_bad:
                failures.append(f"[{name}] expected {'a refusal' if want_bad else 'a pass'}, got '{verdict}'")
            if want_text and want_text not in page_text:
                failures.append(f"[{name}] page does not say '{want_text}'")
            pg.close()
        b.close()
    httpd.shutdown()
    if failures:
        print("\nFAILURES:\n  " + "\n  ".join(failures)); sys.exit(1)
    print("\nall malformed-bundle cases handled")


if __name__ == "__main__":
    main()
