package com.example.vault;

import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class SafeCrypto {
    public final byte[] encrypt(byte[] data, Key key) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(1, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(data);
    }

    public final Key newKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    public final SecretKeySpec fromDerived(byte[] derived) {
        return new SecretKeySpec(derived, "AES");
    }

    public final byte[] wrap(byte[] data, Key publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(1, publicKey);
        return cipher.doFinal(data);
    }

    public final byte[] label() {
        return "hello from the app".getBytes();
    }
}
