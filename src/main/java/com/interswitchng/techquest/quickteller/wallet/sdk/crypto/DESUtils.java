package com.interswitchng.techquest.quickteller.wallet.sdk.crypto;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.util.encoders.Hex;

import com.interswitchng.techquest.quickteller.wallet.sdk.util.AppUtils;

public class DESUtils {

	public static byte[] encrypt(String clearPINBlock, byte[] pinKey)
	{
		DESedeEngine engine = new DESedeEngine();
        DESedeParameters keyParameters = new DESedeParameters(pinKey);
        engine.init(true, keyParameters);
        byte[] clearPINBlockBytes = Hex.decode(clearPINBlock);
        byte[] encryptedPINBlockBytes = new byte[8];
        int res = engine.processBlock(clearPINBlockBytes, 0, encryptedPINBlockBytes, 0);
        byte[] encodedEncryptedPINBlockBytes = Hex.encode(encryptedPINBlockBytes);
        AppUtils.zeroise(clearPINBlockBytes);
        AppUtils.zeroise(encryptedPINBlockBytes);
        return encodedEncryptedPINBlockBytes;
	}
	
	public static byte[] decrypt(String encryptedPINBlock, byte[] pinKey)
	{
		DESedeEngine engine = new DESedeEngine();
        DESedeParameters keyParameters = new DESedeParameters(pinKey);
        engine.init(false, keyParameters);
        byte[] encryptedPINBlockBytes = Hex.encode(encryptedPINBlock.getBytes());
        byte[] clearPINBlockBytes = new byte[8];
        int res = engine.processBlock(encryptedPINBlockBytes, 0, clearPINBlockBytes, 0);
        byte[] decodedClearPINBlockBytes = Hex.decode(clearPINBlockBytes);
        AppUtils.zeroise(encryptedPINBlockBytes);
        AppUtils.zeroise(clearPINBlockBytes);
        return decodedClearPINBlockBytes;
	}
	
	public static byte[] generateKey()
    {
        SecureRandom sr = new SecureRandom();
        KeyGenerationParameters kgp = new KeyGenerationParameters(sr, DESedeParameters.DES_KEY_LENGTH * 16);
        DESedeKeyGenerator kg = new DESedeKeyGenerator();
        kg.init(kgp);
        byte[] desKeyBytes = kg.generateKey();
        DESedeParameters.setOddParity(desKeyBytes);
        return desKeyBytes;
    }

}
