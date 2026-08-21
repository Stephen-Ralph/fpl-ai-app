package com.example.fplaiproxy;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {
    private SecureKeyStore secureKeyStore;
    private LocalProxyServer proxy;
    private TextView status;
    private EditText apiKey;
    private WebView webView;

    private static final String TRUSTED_PAGE = "file:///android_asset/index.html";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        secureKeyStore = new SecureKeyStore(this);
        status = findViewById(R.id.status);
        apiKey = findViewById(R.id.apiKey);
        webView = findViewById(R.id.webView);

        configureWebView();

        findViewById(R.id.saveKey).setOnClickListener(v -> {
            try {
                secureKeyStore.save(apiKey.getText().toString());
                apiKey.setText("");
                ensureProxy();
                toast("Key encrypted with Android Keystore.");
            } catch (Exception e) {
                toast("Could not save key: " + e.getMessage());
            }
        });

        findViewById(R.id.deleteKey).setOnClickListener(v -> {
            try {
                if (proxy != null) proxy.stop();
                secureKeyStore.delete();
                apiKey.setText("");
                updateStatus("No key · proxy stopped");
                webView.loadUrl(TRUSTED_PAGE);
                toast("Saved key deleted.");
            } catch (Exception e) {
                toast("Could not delete key.");
            }
        });

        if (secureKeyStore.hasKey()) {
            ensureProxy();
        } else {
            updateStatus("No key · enter a dedicated OpenAI project key above");
        }

        webView.loadUrl(TRUSTED_PAGE);
    }

    private void configureWebView() {
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(false); // token should not persist in web storage
        webView.getSettings().setDatabaseEnabled(false);
        webView.getSettings().setAllowFileAccess(true); // required for bundled trusted asset only
        webView.getSettings().setAllowContentAccess(false);
        webView.getSettings().setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG);

        webView.setWebChromeClient(new WebChromeClient());
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                // Never navigate the privileged WebView to network content.
                if ("file".equals(uri.getScheme()) && "/android_asset/index.html".equals(uri.getPath())) {
                    return false;
                }
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, uri));
                } catch (ActivityNotFoundException ignored) {}
                return true;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                injectLaunchTokenIfTrusted(url);
            }
        });
    }

    private void ensureProxy() {
        try {
            if (proxy == null) {
                proxy = new LocalProxyServer(
                        () -> secureKeyStore.load(),
                        state -> runOnUiThread(() -> updateStatus(state))
                );
            }
            if (!proxy.isRunning()) proxy.start();
            injectLaunchTokenIfTrusted(webView.getUrl());
        } catch (Exception e) {
            updateStatus("Proxy failed: " + e.getMessage());
        }
    }

    private void injectLaunchTokenIfTrusted(String url) {
        if (proxy == null || !proxy.isRunning()) return;
        if (!TRUSTED_PAGE.equals(url)) return;
        String token = proxy.getLaunchToken().replace("\\", "\\\\").replace("'", "\\'");
        webView.evaluateJavascript(
                "Object.defineProperty(window,'__FPL_PROXY_TOKEN',{value:'" + token +
                "',writable:false,configurable:false});",
                null
        );
    }

    private void updateStatus(String text) {
        status.setText(text);
    }

    private void toast(String text) {
        Toast.makeText(this, text, Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onDestroy() {
        if (proxy != null) proxy.stop();
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
