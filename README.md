# FPL AI — integrated local-proxy Android prototype

This version combines the current FPL mobile demo with the secure localhost OpenAI proxy.

## What happens

1. Enter a dedicated OpenAI API key once.
2. The native app encrypts it using AES-256/GCM with a key held by Android Keystore.
3. The app starts a server bound only to `127.0.0.1:8787`.
4. A cryptographically random launch token is generated in memory.
5. The trusted bundled WebView receives the token via native JavaScript injection.
6. The page can call `/api/analyse` without ever receiving the OpenAI API key.
7. Network URLs are never allowed to navigate inside the privileged WebView.

## Security boundaries

- no OpenAI key in HTML/JavaScript
- no OpenAI key in source code
- no key in web storage
- Android backup disabled
- localhost binding only
- no permissive CORS
- per-launch proxy token
- fixed upstream `api.openai.com`
- request and response size limits
- rate limit
- external links open outside the privileged WebView

OpenAI recommends keeping API keys on a server rather than in mobile apps. This is a
private-device prototype that hardens local storage and access; it should not be used
as the credential architecture for a public/distributed app.

Use a dedicated OpenAI Project key with a conservative spend limit.

## Try after building

Open the app, paste the API key and press **Save**. The proxy starts automatically.
Scroll to **Local LLM Proxy** and press **Test OpenAI through local proxy**.

No Termux is involved.

## GitHub Actions APK build

This repository includes `.github/workflows/build-apk.yml`.

On every push to `main` (or a manual workflow run), GitHub Actions:
1. checks out this private repository;
2. installs Java 17 and Gradle 8.9 on the temporary GitHub runner;
3. builds `:app:assembleDebug`;
4. uploads `app-debug.apk` as the private `fpl-ai-debug-apk` workflow artifact.

No OpenAI API key is needed during the build and no API key should be committed to GitHub.
The key is entered only on the Android device and encrypted with Android Keystore.
