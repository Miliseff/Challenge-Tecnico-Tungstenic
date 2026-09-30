package com.example.vault;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class HardcodedKeys {
    public final byte[] fromArray(byte[] data) throws Exception {
        byte[] keyBytes = {108, 97, 107, 100, 115, 108, 106, 107, 97, 108, 107, 106, 108, 107, 108, 115};
        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(1, spec);
        return cipher.doFinal(data);
    }

    public final SecretKeySpec inlineLiteral() {
        return new SecretKeySpec("s3cr3t-k3y-inline".getBytes(), "AES");
    }

    public final SecretKeySpec fromStringLiteral() {
        byte[] raw = "0123456789abcdef".getBytes();
        return new SecretKeySpec(raw, "AES");
    }

    public final SecretKeySpec fromBase64() {
        byte[] decoded = Base64.decode("c2VjcmV0LWtleS1mb3ItdGVzdGluZw==", 0);
        return new SecretKeySpec(decoded, "AES");
    }
}
