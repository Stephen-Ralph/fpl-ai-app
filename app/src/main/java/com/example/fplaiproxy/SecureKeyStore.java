package com.example.fplaiproxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class SecureKeyStore {
    private static final String KEY_ALIAS = "fpl_ai_proxy_aes_v1";
    private static final String PREFS = "secure_proxy_prefs";
    private static final String PREF_IV = "openai_iv";
    private static final String PREF_CT = "openai_ciphertext";

    private final Context context;

    public SecureKeyStore(Context context) {
        this.context = context.getApplicationContext();
    }

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            return ((KeyStore.SecretKeyEntry) ks.getEntry(KEY_ALIAS, null)).getSecretKey();
        }

        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return kg.generateKey();
    }

    public void save(String plaintext) throws Exception {
        if (plaintext == null || plaintext.trim().isEmpty()) {
            throw new IllegalArgumentException("API key cannot be empty.");
        }

        SecretKey key = getOrCreateKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext.trim().getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();

        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        prefs.edit()
                .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                .putString(PREF_CT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .apply();
    }

    public String load() throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String ivText = prefs.getString(PREF_IV, null);
        String ctText = prefs.getString(PREF_CT, null);
        if (ivText == null || ctText == null) return null;

        byte[] iv = Base64.decode(ivText, Base64.NO_WRAP);
        byte[] ciphertext = Base64.decode(ctText, Base64.NO_WRAP);

        SecretKey key = getOrCreateKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public boolean hasKey() {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        return prefs.contains(PREF_IV) && prefs.contains(PREF_CT);
    }

    public void delete() throws Exception {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().remove(PREF_IV).remove(PREF_CT).apply();

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS);
    }
}
