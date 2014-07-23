package com.interswitchng.techquest.quickteller.wallet.sdk.crypto;

import java.math.BigInteger;

import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class RSAUtils {

	
	
	public static byte[] rsaEncrypt(String publicKeyModulus, String publicKeyExponent, byte[] cipher)
	{
		RSAEngine engine = new RSAEngine();
        RSAKeyParameters publicKeyParameters = getPublicKey(publicKeyModulus, publicKeyExponent);
        engine.init(true, publicKeyParameters);
        byte[] encryptedSecureBytes = engine.processBlock(cipher, 0, cipher.length);
        byte[] encodedEncryptedSecureBytes = Hex.encode(encryptedSecureBytes);
        return encodedEncryptedSecureBytes;
	}
	
	
	 public static RSAKeyParameters getPublicKey(String modulus, String exponent)
     {
         BigInteger modulusByte = new BigInteger(Hex.decode(modulus));
         BigInteger exponentByte = new BigInteger(Hex.decode(exponent));
         RSAKeyParameters pkParameters = new RSAKeyParameters(false, modulusByte, exponentByte);
         return pkParameters;
     }
	
}
