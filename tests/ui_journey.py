import sys
from playwright.sync_api import sync_playwright
URL, OUT = sys.argv[1].rstrip("/"), sys.argv[2]
errors = []
with sync_playwright() as p:
    b = p.chromium.launch(channel="chrome")
    ctx = b.new_context(viewport={"width": 1360, "height": 900})   # fresh context = fresh browser profile
    pg = ctx.new_page()
    pg.on("console", lambda m: errors.append(f"console.{m.type}: {m.text}") if m.type in ("error", "warning") else None)
    pg.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    pg.on("response", lambda r: errors.append(f"HTTP {r.status} {r.url}") if r.status >= 400 else None)

    # ---------- landing ----------
    pg.goto(URL + "/", wait_until="networkidle"); pg.wait_for_timeout(2200)
    pg.screenshot(path=f"{OUT}/10-landing-hero.png")
    print("floating tiles:", pg.locator("#floatTiles .ft").count(), "| gallery cards:", pg.locator("#gal .gcard").count())
    pg.locator("#gallery").scroll_into_view_if_needed(); pg.wait_for_timeout(1000)
    pg.click('#filters .pf[data-f="network"]'); pg.wait_for_timeout(300)
    print("network filter shows:", pg.locator("#gal .gcard:not([hidden])").count())
    pg.click('#filters .pf[data-f="all"]')
    pg.click("#g-EXFIL-HTTP .go"); pg.wait_for_selector("#g-EXFIL-HTTP.contained", timeout=60000)
    pg.click("#g-EXFIL-HTTP .vf"); pg.wait_for_timeout(1200)
    print("gallery verify:", pg.inner_text("#g-EXFIL-HTTP .vr"))
    pg.click("#runAll"); pg.wait_for_function("document.querySelectorAll('#gal .gcard.contained,#gal .gcard.failed').length===6", timeout=150000)
    pg.wait_for_timeout(1500); pg.locator("#gallery").screenshot(path=f"{OUT}/11-gallery-done.png")
    print("gallery score:", pg.inner_text("#galScore"))
    for sec, name in [("#how", "12-how"), ("#receipts", "13-receipts"), ("#honest", "14-honest"), ("#faq", "15-faq")]:
        pg.locator(sec).scroll_into_view_if_needed(); pg.wait_for_timeout(1100); pg.locator(sec).screenshot(path=f"{OUT}/{name}.png")
    pg.locator("#faq details").first.click(); pg.wait_for_timeout(300)
    print("health pill:", pg.inner_text("#health"))
    pg.locator("#nav .btn.primary").click(); pg.wait_for_url("**/app/**"); pg.wait_for_timeout(1200)
    print("open app ->", pg.url)

    # ---------- app ----------
    pg.screenshot(path=f"{OUT}/20-app-empty.png")
    pg.click("#useDemo"); pg.wait_for_selector("#preview:not([hidden])"); pg.wait_for_timeout(500)
    print("preview warning:", pg.inner_text("#preview .pv-h").replace("\n", " | "))
    pg.click("#runBtn"); pg.wait_for_selector("#timeline li.start", timeout=15000); pg.wait_for_timeout(2500)
    pg.screenshot(path=f"{OUT}/22-app-running.png")
    pg.wait_for_selector("#rcDot:not([hidden])", timeout=120000); pg.wait_for_timeout(1500)
    pg.screenshot(path=f"{OUT}/23-app-answer.png")
    print("answer:", pg.inner_text("#answer")[:140].replace("\n", " "), "| guard:", pg.inner_text("#guardChip"))
    pg.click('.tab[data-tab="receipt"]'); pg.wait_for_timeout(900); pg.screenshot(path=f"{OUT}/25-app-receipt.png")
    pg.click(".verify1"); pg.wait_for_timeout(1200); print("inline verify:", pg.inner_text(".vr"))
    pg.click(".tamper1"); pg.wait_for_timeout(600)
    pg.fill("#tamperText", pg.input_value("#tamperText").replace('"canary_hits_on_listener": 0', '"canary_hits_on_listener": 7'))
    pg.click("#verifyBtn"); pg.wait_for_timeout(1200); print("tamper:", pg.inner_text("#stamp")); pg.screenshot(path=f"{OUT}/26-app-tamper.png")
    pg.keyboard.press("Escape"); pg.wait_for_timeout(500)
    pg.reload(wait_until="networkidle"); pg.wait_for_timeout(800)
    print("history survives reload:", pg.locator("#history li").count())
    pg.locator("#history li button").first.click(); pg.wait_for_timeout(1500)
    print("reopened receipt rows:", pg.locator("#receiptView table.kv tr").count())
    pg.click('.snav a[data-view="lab"]'); pg.wait_for_timeout(500); pg.click("#runAll")
    pg.wait_for_function("document.querySelectorAll('.tile.contained,.tile.failed').length===6", timeout=120000); pg.wait_for_timeout(1600)
    pg.screenshot(path=f"{OUT}/28-app-lab.png", full_page=True)
    print("app scoreboard:", pg.inner_text("#sbContained"), pg.inner_text("#sbBytes"), pg.inner_text("#sbSecrets"))
    pg.click('.snav a[data-view="ledger"]'); pg.wait_for_selector("#chain .blk"); pg.wait_for_timeout(800)
    pg.screenshot(path=f"{OUT}/29-app-ledger.png")
    pg.locator("#chain .blk").nth(3).click(); pg.wait_for_timeout(700); pg.click("#verifyBtn"); pg.wait_for_timeout(1000)
    print("ledger receipt verify:", pg.inner_text("#stamp"))

    # ---------- mobile ----------
    m = b.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2).new_page()
    for path, name in [("/", "30-m-landing"), ("/app/", "31-m-app")]:
        m.goto(URL + path, wait_until="networkidle"); m.wait_for_timeout(1400); m.screenshot(path=f"{OUT}/{name}.png")
        print(f"mobile overflow {path}:", m.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth"))
    b.close()
print("errors:", errors or "none")
