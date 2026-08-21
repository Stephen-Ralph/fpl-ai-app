package com.example.fplaiproxy;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class LocalProxyServer {
    public interface KeyProvider {
        String getApiKey() throws Exception;
    }

    public interface StateListener {
        void onState(String state);
    }

    private static final String TAG = "FPLAIProxy";
    private static final int PORT = 8787;
    private static final int MAX_BODY = 64 * 1024;
    private static final String OPENAI_URL = "https://api.openai.com/v1/responses";

    private final KeyProvider keyProvider;
    private final StateListener listener;
    private final ExecutorService pool = Executors.newFixedThreadPool(4);
    private final RateLimiter limiter = new RateLimiter(10, 60_000L);
    private final String launchToken;

    private volatile boolean running = false;
    private ServerSocket serverSocket;

    public LocalProxyServer(KeyProvider keyProvider, StateListener listener) {
        this.keyProvider = keyProvider;
        this.listener = listener;
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        this.launchToken = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    public String getLaunchToken() {
        return launchToken;
    }

    public synchronized void start() throws Exception {
        if (running) return;
        serverSocket = new ServerSocket(PORT, 16, InetAddress.getByName("127.0.0.1"));
        running = true;
        listener.onState("Running on 127.0.0.1:" + PORT);
        pool.execute(() -> {
            while (running) {
                try {
                    Socket s = serverSocket.accept();
                    s.setSoTimeout(10_000);
                    pool.execute(() -> handle(s));
                } catch (Exception e) {
                    if (running) Log.w(TAG, "Accept failed", e);
                }
            }
        });
    }

    public synchronized void stop() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (Exception ignored) {}
        listener.onState("Stopped");
    }

    public boolean isRunning() { return running; }

    private void handle(Socket socket) {
        try (Socket s = socket;
             InputStream rawIn = new BufferedInputStream(s.getInputStream());
             OutputStream out = new BufferedOutputStream(s.getOutputStream())) {

            HttpRequest req = HttpRequest.read(rawIn, MAX_BODY);
            if (req == null) return;

            if ("GET".equals(req.method) && "/health".equals(req.path)) {
                respond(out, 200, "application/json",
                        new JSONObject().put("ok", true).put("service", "fpl-ai-local-proxy").toString());
                return;
            }

            if (!"POST".equals(req.method) || !"/api/analyse".equals(req.path)) {
                respond(out, 404, "application/json", "{\"error\":\"not_found\"}");
                return;
            }

            // Reject cross-origin browser requests. Same Android app can call directly
            // with the launch token; no permissive Access-Control-Allow-Origin exists.
            String origin = req.headers.get("origin");
            if (origin != null && !origin.equals("http://127.0.0.1:8787")) {
                respond(out, 403, "application/json", "{\"error\":\"origin_rejected\"}");
                return;
            }

            String auth = req.headers.get("x-fpl-proxy-token");
            if (auth == null || !constantTimeEquals(auth, launchToken)) {
                respond(out, 401, "application/json", "{\"error\":\"invalid_proxy_token\"}");
                return;
            }

            if (!limiter.tryAcquire()) {
                respond(out, 429, "application/json", "{\"error\":\"rate_limited\"}");
                return;
            }

            JSONObject input;
            try {
                input = new JSONObject(new String(req.body, StandardCharsets.UTF_8));
            } catch (Exception e) {
                respond(out, 400, "application/json", "{\"error\":\"invalid_json\"}");
                return;
            }

            String prompt = input.optString("prompt", "").trim();
            if (prompt.isEmpty() || prompt.length() > 40_000) {
                respond(out, 400, "application/json", "{\"error\":\"invalid_prompt\"}");
                return;
            }

            String apiKey = keyProvider.getApiKey();
            if (apiKey == null || apiKey.isEmpty()) {
                respond(out, 503, "application/json", "{\"error\":\"api_key_not_configured\"}");
                return;
            }

            JSONObject upstream = new JSONObject();
            upstream.put("model", input.optString("model", "gpt-5.6"));
            upstream.put("input", prompt);

            String result = callOpenAI(apiKey, upstream.toString());
            respond(out, 200, "application/json", result);

        } catch (PayloadTooLargeException e) {
            // Socket might still be writable.
            try {
                OutputStream out = socket.getOutputStream();
                respond(out, 413, "application/json", "{\"error\":\"payload_too_large\"}");
            } catch (Exception ignored) {}
        } catch (Exception e) {
            Log.w(TAG, "Request failed", e); // Never logs API key or body.
        }
    }

    private String callOpenAI(String apiKey, String json) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(OPENAI_URL).openConnection();
        c.setConnectTimeout(15_000);
        c.setReadTimeout(90_000);
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Authorization", "Bearer " + apiKey);
        c.setRequestProperty("Content-Type", "application/json");
        c.setRequestProperty("Accept", "application/json");

        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        c.setFixedLengthStreamingMode(body.length);
        try (OutputStream os = c.getOutputStream()) {
            os.write(body);
        }

        int status = c.getResponseCode();
        InputStream stream = status >= 200 && status < 300 ? c.getInputStream() : c.getErrorStream();
        String text = readAll(stream, 2 * 1024 * 1024);
        c.disconnect();

        if (status < 200 || status >= 300) {
            JSONObject safe = new JSONObject();
            safe.put("error", "openai_request_failed");
            safe.put("status", status);
            // Upstream message is returned because it may be useful, but headers/key are never exposed.
            safe.put("upstream", text);
            return safe.toString();
        }
        return text;
    }

    private static String readAll(InputStream in, int max) throws Exception {
        if (in == null) return "";
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int total = 0, n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > max) throw new PayloadTooLargeException();
            b.write(buf, 0, n);
        }
        return b.toString(StandardCharsets.UTF_8.name());
    }

    private static boolean constantTimeEquals(String a, String b) {
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        int diff = x.length ^ y.length;
        int len = Math.max(x.length, y.length);
        for (int i = 0; i < len; i++) {
            byte bx = i < x.length ? x[i] : 0;
            byte by = i < y.length ? y[i] : 0;
            diff |= bx ^ by;
        }
        return diff == 0;
    }

    private static void respond(OutputStream out, int status, String contentType, String body) throws Exception {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        String statusText = status == 200 ? "OK" :
                status == 400 ? "Bad Request" :
                status == 401 ? "Unauthorized" :
                status == 403 ? "Forbidden" :
                status == 404 ? "Not Found" :
                status == 413 ? "Payload Too Large" :
                status == 429 ? "Too Many Requests" : "Service Unavailable";
        String headers =
                "HTTP/1.1 " + status + " " + statusText + "\r\n" +
                "Content-Type: " + contentType + "\r\n" +
                "Content-Length: " + bytes.length + "\r\n" +
                "Cache-Control: no-store\r\n" +
                "X-Content-Type-Options: nosniff\r\n" +
                "Connection: close\r\n\r\n";
        out.write(headers.getBytes(StandardCharsets.US_ASCII));
        out.write(bytes);
        out.flush();
    }

    private static final class HttpRequest {
        final String method;
        final String path;
        final Map<String,String> headers;
        final byte[] body;

        HttpRequest(String method, String path, Map<String,String> headers, byte[] body) {
            this.method = method; this.path = path; this.headers = headers; this.body = body;
        }

        static HttpRequest read(InputStream in, int maxBody) throws Exception {
            String requestLine = readLine(in, 4096);
            if (requestLine == null || requestLine.isEmpty()) return null;
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) return null;

            Map<String,String> headers = new HashMap<>();
            while (true) {
                String line = readLine(in, 8192);
                if (line == null || line.isEmpty()) break;
                int colon = line.indexOf(':');
                if (colon > 0) {
                    headers.put(
                            line.substring(0, colon).trim().toLowerCase(Locale.US),
                            line.substring(colon + 1).trim()
                    );
                }
            }

            int length = 0;
            if (headers.containsKey("content-length")) {
                length = Integer.parseInt(headers.get("content-length"));
            }
            if (length < 0 || length > maxBody) throw new PayloadTooLargeException();

            byte[] body = new byte[length];
            int off = 0;
            while (off < length) {
                int n = in.read(body, off, length - off);
                if (n < 0) break;
                off += n;
            }
            return new HttpRequest(parts[0], parts[1].split("\\?")[0], headers, body);
        }

        static String readLine(InputStream in, int max) throws Exception {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            int prev = -1;
            while (b.size() < max) {
                int cur = in.read();
                if (cur < 0) break;
                if (prev == '\r' && cur == '\n') {
                    byte[] arr = b.toByteArray();
                    int len = Math.max(0, arr.length - 1);
                    return new String(arr, 0, len, StandardCharsets.US_ASCII);
                }
                b.write(cur);
                prev = cur;
            }
            if (b.size() >= max) throw new PayloadTooLargeException();
            return b.size() == 0 ? null : b.toString(StandardCharsets.US_ASCII.name());
        }
    }

    private static final class PayloadTooLargeException extends Exception {}
}
