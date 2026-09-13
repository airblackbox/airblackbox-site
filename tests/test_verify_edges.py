"""Edge cases for the hero panel, hunting for false passes and broken states."""
import http.server, socketserver, threading, functools, os, sys, time
from playwright.sync_api import sync_playwright

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
PORT = 8933

def serve():
    h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=ROOT)
    socketserver.TCPServer.allow_reuse_address = True
    s = socketserver.TCPServer(("127.0.0.1", PORT), h)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s

# Kill Ed25519 support before any page script runs, the way an older
# Safari/Firefox would present.
NO_ED25519 = """
const _imp = crypto.subtle.importKey.bind(crypto.subtle);
crypto.subtle.importKey = function(fmt, key, algo, ext, usages){
  const name = (algo && (algo.name || algo)) || "";
  if (String(name).toLowerCase().indexOf("ed25519") !== -1)
    return Promise.reject(new Error("Unsupported algorithm"));
  return _imp(fmt, key, algo, ext, usages);
};
"""

def main():
    httpd = serve(); base = f"http://127.0.0.1:{PORT}"; failures = []
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path='/opt/pw-browsers/chromium-1194/chrome-linux/chrome')

        # --- A. browser that cannot do Ed25519 must NOT be told "VERIFIED" ---
        pg = b.new_page()
        pg.add_init_script(NO_ED25519)
        pg.goto(f"{base}/index.html")
        pg.wait_for_selector(".hv-verdict", timeout=20000)
        verdict = pg.inner_text(".hv-verdict").strip()
        rows = pg.eval_on_selector_all(".hv-row", "e=>e.map(x=>x.innerText.replace(/\\s+/g,' ').trim())")
        print("\n[A] no-Ed25519 browser")
        print(f"    verdict: {verdict}")
        for r in rows: print(f"    {r}")
        uncheckable = any("could not be checked" in r.lower() for r in rows)
        if not uncheckable:
            failures.append("[A] engine did not report unverifiable signatures")
        if "VERIFIED" in verdict.upper() and uncheckable:
            failures.append(f"[A] FALSE PASS: says '{verdict}' when signatures could not be checked")
        pg.close()

        # --- A2. /verify must not claim authenticity when it could not check ---
        pg = b.new_page()
        pg.add_init_script(NO_ED25519)
        pg.goto(f"{base}/verify.html")
        pg.set_input_files("#file", os.path.join(ROOT, 'demo/sample.air-evidence'))
        pg.wait_for_selector(".verdict h2", timeout=20000)
        vh = pg.inner_text(".verdict h2").strip()
        vp = pg.inner_text(".verdict p").strip()
        print(f"\n[A2] /verify on no-Ed25519 browser -> {vh}")
        if "authentic" in vh.lower() or "genuine and unaltered" in vp.lower():
            failures.append(f"[A2] /verify claims authenticity it could not check: {vh}")
        pg.close()

        # --- B. sample bundle missing -> graceful, no crash ---
        pg = b.new_page()
        pg.route("**/demo/sample.air-evidence", lambda r: r.abort())
        pg.goto(f"{base}/index.html")
        time.sleep(2.5)
        body = pg.inner_text("#hvBody").strip()
        foot_html = pg.inner_html("#hvFoot")
        print(f"\n[B] sample fetch blocked -> body: {body[:90]!r}")
        if not body:
            failures.append("[B] panel left empty when the sample could not be fetched")
        if "undefined" in body.lower() or "[object" in body.lower():
            failures.append(f"[B] leaked a raw JS value: {body[:80]}")
        if '/verify' not in foot_html:
            failures.append(f"[B] no route to the verifier after fetch failure: {foot_html[:80]}")
        pg.close()

        # --- C. garbage file dropped -> refuses, does not crash ---
        pg = b.new_page()
        pg.goto(f"{base}/index.html")
        pg.wait_for_selector(".hv-verdict", timeout=20000)
        res = pg.evaluate("""async () => {
            const buf = new TextEncoder().encode("this is definitely not a zip file").buffer;
            try { const R = await verify(buf, ""); return {level: R.level, first: R.checks[0] && R.checks[0].t}; }
            catch (e) { return {threw: String(e && e.message || e)}; }
        }""")
        print(f"\n[C] garbage input -> {res}")
        if res.get("threw"):
            failures.append(f"[C] engine threw on garbage instead of reporting: {res['threw']}")
        elif res.get("level") != "bad":
            failures.append(f"[C] garbage input not rejected (level={res.get('level')})")
        pg.close()

        # --- D. mobile layout: no horizontal overflow, panel visible ---
        pg = b.new_page(viewport={'width': 375, 'height': 812})
        pg.goto(f"{base}/index.html")
        pg.wait_for_selector(".hv-verdict", timeout=20000)
        ov = pg.evaluate("() => ({doc: document.documentElement.scrollWidth, win: window.innerWidth})")
        vis = pg.is_visible("#hv")
        h1 = pg.evaluate("() => { const e=document.querySelector('.hero-copy h1'); const r=e.getBoundingClientRect(); return {right: Math.round(r.right), w: window.innerWidth}; }")
        print(f"\n[D] mobile 375px -> scrollWidth {ov['doc']} vs viewport {ov['win']}, panel visible={vis}, h1 right={h1['right']}")
        if ov['doc'] > ov['win'] + 1:
            failures.append(f"[D] horizontal overflow on mobile: {ov['doc']}px > {ov['win']}px")
        if not vis:
            failures.append("[D] verification panel not visible on mobile")
        pg.close()

        b.close()
    httpd.shutdown()

    print("\n" + "=" * 60)
    if failures:
        print("BUGS FOUND:")
        for f in failures: print("  -", f)
        sys.exit(1)
    print("PASS - no edge-case bugs found")

main()
