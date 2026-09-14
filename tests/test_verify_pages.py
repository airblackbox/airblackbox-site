"""Prove the refactor did not change any verdict, and that the hero verifies for real.

The engine was moved out of verify.html into a shared verify-engine.js. That file
is the one place canonicalJSON() lives, so a regression here would silently break
every signature check. These tests run the actual pages in Chromium against the
real signed sample bundle and against tampered copies of it.

Run it with:
    pip install playwright && playwright install chromium
    python tests/test_verify_pages.py
"""
import glob, http.server, socketserver, threading, functools, shutil, zipfile, io, os, sys, time
from playwright.sync_api import sync_playwright

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
PORT = 8931

# tampered copies, built from the genuine bundle
def make_tampered():
    src = os.path.join(ROOT, 'demo/sample.air-evidence')
    raw = open(src, 'rb').read()
    zin = zipfile.ZipFile(io.BytesIO(raw))
    names = zin.namelist()

    # 1. flip a decision inside the records, leaving the manifest signature intact
    out1 = io.BytesIO()
    with zipfile.ZipFile(out1, 'w', zipfile.ZIP_DEFLATED) as z:
        for n in names:
            data = zin.read(n)
            if n == 'records/actions.jsonl':
                data = data.replace(b'"reject"', b'"advance"', 1)
            z.writestr(n, data)
    open(os.path.join(ROOT, 'demo/_t_flip.air-evidence'), 'wb').write(out1.getvalue())

    # 2. add an unsigned file the manifest does not list
    out2 = io.BytesIO()
    with zipfile.ZipFile(out2, 'w', zipfile.ZIP_DEFLATED) as z:
        for n in names:
            z.writestr(n, zin.read(n))
        z.writestr('attachments/reviewer_signoff.txt', b'Approved by compliance.')
    open(os.path.join(ROOT, 'demo/_t_extra.air-evidence'), 'wb').write(out2.getvalue())


def serve():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=ROOT)
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd



def launch_chromium(p):
    """Resolve a Chromium that exists on THIS machine.

    A plain `playwright install chromium` needs no executable_path at all, so
    that is the default. Some CI images instead pre-provision browsers under
    PLAYWRIGHT_BROWSERS_PATH, so fall back to that, and let CHROMIUM_PATH
    override both. Hardcoding one absolute path makes a test pass in exactly
    one environment and fail everywhere else.
    """
    exe = os.environ.get("CHROMIUM_PATH")
    if not exe:
        base = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
        if base:
            hits = sorted(glob.glob(os.path.join(base, "chromium-*", "chrome-linux", "chrome")))
            exe = hits[-1] if hits else None
    return p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()


def main():
    make_tampered()
    httpd = serve()
    base = f"http://127.0.0.1:{PORT}"
    failures = []

    with sync_playwright() as p:
        browser = launch_chromium(p)
        page = browser.new_page()
        errors = []          # real JS exceptions
        bad_urls = []        # resources that failed to load, by URL
        page.on("pageerror", lambda e: errors.append("JS exception: " + str(e)))
        page.on("response", lambda r: bad_urls.append(f"{r.status} {r.url}") if r.status >= 400 else None)
        page.on("requestfailed", lambda r: bad_urls.append(f"failed {r.url}"))

        # --- 1. homepage hero auto-verifies the genuine sample ---
        page.goto(f"{base}/index.html")
        page.wait_for_selector(".hv-verdict", timeout=20000)
        verdict = page.inner_text(".hv-verdict").strip()
        rows = page.eval_on_selector_all(".hv-row", "els => els.map(e => e.innerText.trim())")
        print(f"\n[hero] verdict: {verdict}")
        for r in rows:
            print(f"       {r}")
        if "TAMPERED" in verdict:
            failures.append("hero reported TAMPERED for the genuine bundle")
        if len(rows) < 5:
            failures.append(f"hero showed only {len(rows)} checks, expected ~6")
        if "your" not in page.inner_text("#hvFoot"):
            failures.append("hero footer lost the 'your browser' claim")

        # --- 2. the standalone /verify page still works after the engine extraction ---
        page.goto(f"{base}/verify.html")
        page.set_input_files("#file", os.path.join(ROOT, 'demo/sample.air-evidence'))
        page.wait_for_selector(".verdict h2", timeout=20000)
        vh = page.inner_text(".verdict h2").strip()
        print(f"\n[verify.html] genuine bundle -> {vh}")
        if "Do not rely" in vh:
            failures.append(f"verify.html rejected the genuine bundle: {vh}")

        # --- 3. both surfaces must REFUSE tampered bundles ---
        for label, fn, expect in [
            ("flipped decision", 'demo/_t_flip.air-evidence', "Do not rely"),
            ("unsigned extra file", 'demo/_t_extra.air-evidence', "Do not rely"),
        ]:
            page.goto(f"{base}/verify.html")
            page.set_input_files("#file", os.path.join(ROOT, fn))
            page.wait_for_selector(".verdict h2", timeout=20000)
            got = page.inner_text(".verdict h2").strip()
            print(f"[verify.html] {label:22} -> {got}")
            if expect not in got:
                failures.append(f"verify.html ACCEPTED a tampered bundle ({label}): {got}")

        # hero must refuse a tampered file dropped on it, too
        page.goto(f"{base}/index.html")
        page.wait_for_selector(".hv-verdict", timeout=20000)
        page.eval_on_selector("#hv", """async (el, url) => {
            const buf = await (await fetch(url)).arrayBuffer();
            const R = await verify(buf, "");
            window.__heroTamperLevel = R.level;
        }""", "/demo/_t_flip.air-evidence")
        lvl = page.evaluate("window.__heroTamperLevel")
        print(f"[hero engine] flipped decision -> level={lvl}")
        if lvl != "bad":
            failures.append(f"hero engine did not flag a flipped decision (level={lvl})")

        # Any JS exception is a real failure. For resources, only the stdlib
        # server's missing favicon is excused - everything the pages actually
        # depend on must load.
        if errors:
            failures.append(f"JS exceptions: {errors[:3]}")
        # Only same-origin resources are in scope: this sandbox blocks outbound
        # egress, so the Google Fonts stylesheet always fails here and says
        # nothing about the deployed site. The favicon is absent from the
        # stdlib server. Everything else the pages depend on must load.
        external = [u for u in bad_urls if '127.0.0.1' not in u]
        broken = [u for u in bad_urls if '127.0.0.1' in u and 'favicon' not in u]
        if broken:
            failures.append(f"same-origin resources failed: {broken[:5]}")
        print(f"\n[resources] {len(broken)} same-origin failures, "
              f"{len(external)} external blocked by the sandbox (expected)")

        browser.close()

    httpd.shutdown()
    for f in [os.path.join(ROOT, 'demo/_t_flip.air-evidence'),
              os.path.join(ROOT, 'demo/_t_extra.air-evidence')]:
        os.remove(f)

    print("\n" + "=" * 60)
    if failures:
        print("FAILED:")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    print("PASS - genuine bundle verifies on both surfaces; both refuse tampering")


main()
