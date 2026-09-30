package com.example.vault;

import android.util.Base64;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class WeakCrypto {
    public final byte[] legacyDes(byte[] data, byte[] raw) throws Exception {
        DESKeySpec keySpec = new DESKeySpec(raw);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        Key key = factory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(1, key);
        return cipher.doFinal(data);
    }

    public final byte[] streamCipher(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(1, key);
        return cipher.doFinal(data);
    }

    public final Key blowfishKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("Blowfish");
        generator.init(128);
        return generator.generateKey();
    }

    public final byte[] tripleDes(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(1, key);
        return cipher.doFinal(data);
    }

    public final byte[] ecbExplicit(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(1, key);
        return cipher.doFinal(data);
    }

    public final byte[] ecbImplicit(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(1, key);
        return cipher.doFinal(data);
    }

    public final byte[] rsaIsNotEcb(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(1, key);
        return cipher.doFinal(data);
    }
}
