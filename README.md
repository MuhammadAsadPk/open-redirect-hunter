# 🎯 Open Redirect Hunter

A powerful, false-positive-aware **Open Redirect** detection extension for **Burp Suite**, built in **Java** on the **Montoya API**. It goes far beyond simple `?url=evil.com` checks — it understands **server-side redirects, client-side (DOM) redirects, OAuth/SSO flows, allow-list bypasses, generic path-based redirects, and multi-parameter logic flaws** — and verifies real findings with a **headless Chrome** browser so you report confirmed bugs, not noise.

> Built for real bug-bounty & VAPT workflows: **confirmed findings with real proof, minimal false positives.** 🔥

---

## 📑 Table of Contents

- [✨ Why this tool](#-why-this-tool)
- [🚀 Features at a glance](#-features-at-a-glance)
- [🧠 Detection Methodologies (the core)](#-detection-methodologies-the-core)
- [🖥️ The UI](#️-the-ui)
- [⚙️ Installation](#️-installation)
- [🧪 Usage](#-usage)
- [🔧 Settings reference](#-settings-reference)
- [🧩 Payload categories](#-payload-categories)
- [⚠️ Legal / responsible use](#️-legal--responsible-use)
- [👤 Author](#-author)

---

## ✨ Why this tool

Most open-redirect scanners only do one thing: swap a query parameter's value with `https://evil.com` and look for that string in the `Location` header. That misses the majority of **real-world** open redirects:

- 🧬 Redirects that fire **client-side via JavaScript** (SPA / React / Next.js apps) — no `Location` header at all
- 🔐 Redirects behind **login / SSO / OAuth** flows that only trigger **post-authentication**
- 🧱 **Allow-list–protected** redirects that need target-anchored bypasses (`https://trusted.com@evil.com`)
- 🌐 **Server / framework-level** path redirects that need **no query parameter** (`//evil.com`, `/\evil.com`)
- 🧩 Logic flaws that only trigger when **two parameters** are attacker-controlled at once
- 🎟️ OAuth `code` / `token` **leak chains** (account-takeover severity, not "just a redirect")

Open Redirect Hunter covers **all** of these, and confirms them with a real browser so your report holds up. ✅

---

## 🚀 Features at a glance

| | Capability |
|---|---|
| 🟢 | **Live Proxy monitoring** — passively watches in-scope traffic and tests redirect-like params automatically |
| 🧾 | **Bulk scanning** — Scan Proxy History, Scan Site Map, or Import a URL list (waybackurls/gau) |
| 🎯 | **Smart candidate detection** — 37+ redirect param-name hints + URL-shaped value detection |
| 🧮 | **Baseline-diff detection** — compares original vs attack response to kill false positives |
| 🔗 | **Multi-hop redirect chain follow** — resolves the *real* final landing host (up to 3 hops) |
| 🧬 | **DOM-based detection** — headless Chrome catches client-side JS redirects (SPA/Next.js) |
| 🔍 | **JS sink attribution** — tells you *which* script & function triggered the redirect (via CDP) |
| 💥 | **DOM XSS escalation** — auto-tries `javascript:` payload and detects a real `alert()` |
| 🧱 | **Smart allow-list bypass** — payloads anchored to the target's own domain |
| 🌐 | **Generic path-based mode** — ~90 server/framework-level payloads, no query param needed |
| 🧩 | **Multi-parameter combo testing** — catches bugs needing 2+ params at once |
| 🔐 | **Post-auth context tagging** — flags redirects on login/SSO/OAuth endpoints |
| 🎟️ | **Impact-chain detection** — flags OAuth `code`/`token` leaks as HIGH IMPACT |
| ✅ | **RFC-3986–accurate confirmation** — real URL resolution, not naive substring matching |
| 🧰 | **Rich UI** — native request/response viewers, filtering, severity colors, Copy-as-cURL |

---

## 🧠 Detection Methodologies (the core)

This is the heart of the tool. Each layer catches a different class of open redirect.

### 1️⃣ Live Proxy Monitoring (passive)
As you browse an in-scope target, the extension watches every request. For each one it extracts the **query (GET) parameters** — and **POST body params** if enabled — and decides which are worth testing. No manual setup; findings land in the Scanner table in real time. 🟢

### 2️⃣ Candidate Parameter Detection
A parameter is tested only if it *looks like* a redirect sink, to keep things fast and quiet:
- 🏷️ **Name match** — 37+ hints: `url`, `redirect`, `redirect_uri`, `next`, `return`, `return_to`, `continue`, `dest`, `callback`, `goto`, `image_url`, `target`, and more
- 🔎 **Value shape** — any value that already *looks like* a URL/path (`https://…`, `//…`, `/path`) is tested even if its name isn't obvious

### 3️⃣ Core + Categorized Payloads
A tiny **always-on core set** (`https://evil.com/`, `//evil.com/`, `///evil.com/`) runs on every candidate. Everything else lives in **toggleable categories** on the Payloads tab (off by default) so you control speed vs coverage. 🧩

### 4️⃣ Baseline Comparison (false-positive killer)
Before trusting any hit, the tool uses the **original, unmodified response** as a baseline. If the app *already* redirected to the sentinel host before your payload (app-wide behavior), it is **not** reported — only redirects your payload actually caused. 🧮

### 5️⃣ Location-Header Detection with Real URL Resolution
When the server replies with a `Location` header, the tool does **real RFC 3986 relative-URL resolution** against the request's own base URL — exactly how a browser resolves it — instead of a naive "does `evil.com` appear somewhere" substring check.
- ✅ `//evil.com/` → resolves off-site → **CONFIRMED**
- ❌ `/%0a/evil.com` → resolves **same-origin** (just a path) → correctly **ignored**
- 🪃 Backslash tricks (`/\evil.com`) are normalized the way browsers do (WHATWG), so they're still caught
- 🚦 **Status-code aware** — a real redirect needs `301/302/303/307/308`; a `Location` on a `200` is flagged separately as low-confidence "verify manually"

### 6️⃣ Multi-Step Redirect Chain Following
Apps often bounce you through intermediate hops before the final redirect. The tool **follows the chain up to 3 hops** and reports the **actual final landing host**, so `//evil.com` that ends on `evil.com` is proven, not assumed. 🔗

### 7️⃣ Static-Body JS / Meta-Refresh Detection
Even without a `Location` header, a redirect can live in the HTML body. The tool uses **regex sink extraction** (not blind string matching) to find the value assigned to real redirect sinks and confirm it points to the sentinel:
- `window.location`, `location.href`, `location.assign()`, `location.replace()`, `top.location`, `self.location`, `document.location`
- `<meta http-equiv="refresh" content="0;url=…">`
- `<a href="…evil.com…">`

### 8️⃣ DOM-Based Redirect — Headless Chrome Fallback 🧬
The big one. Modern SPA/React/**Next.js** apps ship an almost-empty HTML shell; the real redirect logic runs in **bundled JavaScript** *after* the page loads — invisible to any static check.

When enabled, for a candidate with **no** server `Location` and **no** static-body signal, the tool spins up a **real headless Chrome (Selenium)**, navigates to the attack URL, lets the page fully render and run its JS (honoring your configured timeout, with early-exit the moment it lands off-site), then reads the browser's **actual final host**. If it lands on the sentinel → **CONFIRMED (DOM)**.

> Loaded via **reflection**, so the extension still compiles and loads cleanly even without Selenium on the classpath — it just reports "Headless not available" until you add the jars.

### 9️⃣ JS Sink Attribution (which code did it?) 🔍
When a DOM redirect is confirmed, the tool reads **Chrome DevTools Protocol** performance logs and pulls the `Network.requestWillBeSent` **initiator / call stack** for the request that went to the sentinel host. The evidence then tells you *exactly* what caused it:

```
Triggered by: script -> redirectUser() at .../_app-b2ea98d1bf4b9a4d.js:142
```

So you know whether it was `window.location`, a `<meta refresh>`, etc. — perfect for a precise report.

### 🔟 DOM XSS Escalation 💥
A client-side redirect sink is often a **DOM XSS sink** too. When enabled, right after a DOM redirect is confirmed, the tool retries the same parameter with `javascript:alert(document.domain)` and uses Selenium's **Alert API** to detect a **real native `alert()`** firing (not just reflected text). If it fires → **CONFIRMED (DOM XSS)** — a big severity jump from a plain redirect.

### 1️⃣1️⃣ Smart Allow-List Bypass 🧱
When an app validates redirects against its own domain, generic payloads fail — but **target-anchored** ones succeed. The tool builds bypass payloads anchored on:
- The target's **own HTTP host**
- The redirect param's **original/baseline value** host
- A naive **parent-domain** guess

…producing the exact tricks that beat allow-lists:
```
https://target.com@evil.com/          (userinfo trick)
https://target.com.evil.com/          (subdomain confusion)
https://evil.com#target.com           (fragment trick)
https://target.com%2540evil.com/      (double-encoded @)
```
➕ **Allow-list domain sniffing** — if the app's error text leaks its allowed domain (`"Invalid redirect domain: X"`), that domain is extracted and retried as a fresh anchor.

### 1️⃣2️⃣ Dynamic Host-Encoding Bypass 🔣
Payloads that transform the sentinel host itself to beat naive string filters:
- Fully **percent-encoded** host (`%65%76%69%6c…`)
- **dot-to-`%2E`** (`evil%2Ecom`)
- **double-encoded dot** (`evil%25%32%65com`)

### 1️⃣3️⃣ Generic Path-Based Redirect (no param needed) 🌐
Inspired by the nuclei `open-redirect-generic` template and built from **real bug-bounty findings** (Boeing, Stanford, Worldpay, Linktree…). This mode targets **server / framework / reverse-proxy URL-normalization bugs** by hitting the **host root** directly with ~90 path-injection payloads — **no query parameter involved at all**:
```
//evil.com        ///evil.com        /\evil.com        //\evil.com
%5C%5Cevil.com/%252e%252e%252f        ///@evil.com      /%2f%2e%2e//evil.com
```
It is **deduped per host** (each unique host tested once per session) so it stays fast even on Live traffic.

### 1️⃣4️⃣ Multi-Parameter Combo Testing 🧩
Some redirects only break when **two parameters** are attacker-controlled at once (classic OAuth example: `redirect_uri` **+** `prompt`). Since the secondary param often doesn't look like a redirect param on its own, single-param testing misses it. When nothing is found individually, the tool tries:
- All identified candidates set to the payload **together**
- Each candidate paired with **every other** parameter (capped to stay sane)

…and reports **CONFIRMED (multi-param)**, naming exactly which params had to be combined.

### 1️⃣5️⃣ Post-Authentication Context Tagging 🔐
Open redirects on **login / SSO / OAuth / callback** endpoints are high-value and routinely missed by unauthenticated scanning. When a finding's URL matches auth keywords (`login`, `signin`, `auth`, `authorize`, `sso`, `oauth`, `saml`, `callback`, `session`…), it's tagged **`[POST-AUTH REDIRECT CONTEXT]`**. Because the tool builds its attack requests from your already-captured (authenticated) traffic, the session is carried through automatically.

### 1️⃣6️⃣ Impact-Chain Detection (OAuth token/code leak) 🎟️
Not every open redirect is equal. The tool checks whether a confirmed redirect likely **leaks a credential** to the attacker and flags it **`[HIGH IMPACT]`**:
- The request carries a sensitive flow param — `code`, `token`, `access_token`, `id_token`, `SAMLResponse`, `state`, `assertion`, `jwt`, `ticket` — that would ride along to the attacker host
- OR the endpoint is clearly an OAuth/SSO `authorize`/`callback`/`token`/`idp`/`adfs` path, where a code/token is appended to the redirect target by design

This is the difference between a *Low* "just a redirect" and a *High* **account-takeover chain**.

### 1️⃣7️⃣ POST-Body Parameter Testing 📮
Optional: also test **POST form-body** parameters (payment gateways, logout forms, webhooks), run through the exact same detection pipeline. (Headless/DOM verification is skipped for body params, since a simple headless `GET` can't replay a POST.)

### 1️⃣8️⃣ Session Dedup Cache ⚡
The same `(endpoint + param + type)` combo isn't re-tested within a session — a big speed win when the same page reloads in Live traffic or repeats across Proxy History. Cleared by **Clear Results**.

---

## 🖥️ The UI

Two tabs, built with Swing on top of Burp's native components.

### 🗂️ Scanner tab
- ⚙️ **Settings panel** — all toggles + sentinel host, threads, rate limit, headless timeout
- 🔘 **Action buttons** — Apply Settings · Clear Results · Export CSV · Scan Proxy History · Scan Site Map · Import URLs · Cancel Scan
- 📊 **Results table** with columns: Time · Method · URL · Param · Type · Payload · Evidence · Confidence · Headless · Source
- 🔎 **Filter bar** — free-text filter + "Confirmed only" + "High-impact only"
- 🎨 **Severity-tiered row colors** — DOM XSS (darkest) → High-Impact → Confirmed → Likely → Low
- 🧾 **Native Request / Response viewers** — click any finding to inspect the actual attack request & response in Burp's own editors (full syntax highlighting)
- 📜 **Live log pane** — every payload attempt, chain follow, sink-attribution debug line
- 🧮 **Status bar breakdown** — Monitored · Findings · Confirmed · DOM-XSS · High-Impact · Likely

### 🧩 Payloads tab
Every optional bypass category as its own checkbox (all **off** by default; only the 3 core payloads always run). Includes the dynamic target-aware categories (Smart Allow-list, Host-Encoding) and the Generic Path-Based mode.

### 🖱️ Right-click context menu (on any finding)
- Send to Repeater
- Copy URL · Copy Payload · **Copy as cURL** · Copy Evidence
- Deep Verify (Headless Browser)
- Try DOM XSS (`javascript:` payload)

### ➡️ "Send to Open Redirect Hunter"
A context-menu item available across Burp (Proxy History, Repeater, Site Map) to push any request into the scanner on demand.

---

## ⚙️ Installation

### Requirements
- 🧰 **Burp Suite** (Community or Professional) with the **Montoya API** (current Burp versions)
- ☕ Java is provided by Burp itself — no separate runtime needed to *load* the jar

### Load the extension
1. Download `releases/OpenRedirectHunterTab.jar`
2. Burp → **Extensions** → **Add**
3. Extension type: **Java**
4. Select the jar → **Next**
5. You should see in the **Output** tab:
   ```
   Open Redirect Hunter loaded. Sentinel host: evil.com
   ```
6. A new **Open Redirect Hunter** tab appears. ✅

### 🧬 (Optional) Enable the Headless DOM engine
The DOM-based detection, sink attribution, and DOM XSS escalation need **Selenium + Chrome**:

1. Install **Google Chrome / Chromium** on your machine
2. Download Selenium Java + its dependencies (easiest via Maven):
   ```xml
   <dependency>
     <groupId>org.seleniumhq.selenium</groupId>
     <artifactId>selenium-java</artifactId>
     <version>4.41.0</version>
   </dependency>
   ```
   ```bash
   mvn dependency:copy-dependencies
   ```
3. Burp → **Extensions** → **Extension Settings** → **Java Environment** → point the classpath folder at the downloaded jars (e.g. `target/dependency`)
4. Reload the extension — the Output tab should now show:
   ```
   Headless (Selenium) Deep Verify: available
   ```

> Without Selenium the extension still works fully for server-side, static-body, generic-path, and multi-param detection — only the headless DOM features are disabled.

### 🛠️ Build from source (optional)
```bash
# Montoya API classes on the classpath
javac -cp montoya-api.jar -d build src/OpenRedirectHunterTab.java
jar cf OpenRedirectHunterTab.jar -C build .
```

---

## 🧪 Usage

### 🟢 Live hunting (passive)
1. Set your target **in scope** (Burp → Target → Scope)
2. Make sure **Enable Extension** and **In-Scope Only** are on
3. Browse the target normally — findings appear in the Scanner table in real time

### 🧾 Bulk scanning
- **Scan Proxy History** — tests every in-scope GET (and POST, if enabled) already captured
- **Scan Site Map** — tests everything in your Target → Site map
- **Import URLs** — paste or load a URL list (e.g. `waybackurls target.com | grep "=http"`); each is fetched live and tested

### 🎯 Deep verification
- Right-click a finding → **Deep Verify (Headless Browser)** to prove it in a real browser
- Right-click → **Try DOM XSS** to attempt `javascript:alert()` escalation

### ⏹️ Control
- **Cancel Scan** stops bulk/manual scans (Live monitoring keeps running)
- **Export CSV** saves all findings

---

## 🔧 Settings reference

| Setting | What it does |
|---|---|
| 🟢 Enable Extension | Master switch for the live Proxy monitor |
| 🔵 Test GET / URL Params | Test query-string parameters |
| 📮 Test POST Body Params | Also test POST form-body parameters |
| 🎯 In-Scope Only | Restrict everything to Burp's defined scope |
| ⚡ Dedup | Skip re-testing the same endpoint+param (faster) |
| 🧬 DOM Redirect Fallback | Use headless Chrome when no static signal is found |
| 🔁 …also on Live Traffic | Allow the (slow) DOM fallback during live browsing too |
| 💥 Try DOM XSS | Escalate confirmed DOM redirects with a `javascript:` payload |
| 🛑 Stop after first finding | Stop testing a URL's other params once one is confirmed (faster) |
| 🎨 Highlight Findings | Color + annotate the evidence in Burp's HTTP history |
| 🌐 Sentinel Host | The attacker host used in payloads (default `evil.com`) |
| 🧵 Max Threads / Rate Limit | Throughput control |
| ⏱️ Headless Deep-Verify Timeout | How long to wait for a client-side redirect to fire |

---

## 🧩 Payload categories

On the **Payloads** tab (all off by default; the 3 core payloads always run):

- 🔹 **Basic Variants** — scheme/slash permutations
- 🔸 **Userinfo / @ Tricks** — `trusted@evil.com` style
- 🔣 **Encoding Tricks** — `%2f`, `%5c`, `%2e` forms
- ␣ **Whitespace / Null-byte / Case Tricks**
- 🧱 **Filter Bypass** — `/%0d/`, `/..//`, `http:///` …
- 🔐 **Encoding Bypass** — percent-encoded schemes/slashes
- 🧭 **Protocol-Relative Extras**
- 🎯 **Smart Allow-list Bypass** (target-aware, dynamic)
- 🔣 **Dynamic Host-Encoding Bypass** (target-aware, dynamic)
- 🌐 **Generic Path-Based Redirect** (host-root, ~90 payloads)

---

## ⚠️ Legal / responsible use

This tool actively sends crafted requests to targets. **Only use it against systems you are explicitly authorized to test** — your own labs, bug-bounty programs within scope, or clients with a signed engagement. Unauthorized testing is illegal. The author assumes no liability for misuse. 🛡️

---

## 👤 Author

**Muhammad Asad** — Penetration Tester & Bug Bounty Hunter
🌐 GitHub: [@MuhammadAsadPk](https://github.com/MuhammadAsadPk)

If this tool helps you land a bug, a ⭐ on the repo is appreciated!

---

<p align="center">Made with ☕ + 🔥 for the bug-bounty & AppSec community</p>
