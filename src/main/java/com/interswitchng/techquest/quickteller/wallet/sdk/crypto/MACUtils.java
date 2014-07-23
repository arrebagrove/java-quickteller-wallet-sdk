package com.interswitchng.techquest.quickteller.wallet.sdk.crypto;

import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.util.encoders.Hex;

import com.interswitchng.techquest.quickteller.wallet.sdk.util.HexConverter;

public class MACUtils {

	public static String getMacValue(String macCipherText, byte[] macKey)
	{
		  byte[] macBytes = new byte[4];
		  CBCBlockCipherMac cipher = new CBCBlockCipherMac(new DESedeEngine());
		  DESedeParameters keyParameters = new DESedeParameters(macKey);
		  DESedeEngine engine = new DESedeEngine();
		  engine.init(true, keyParameters);
		  cipher.init(keyParameters);
		  byte[] macDataBytes = macCipherText.getBytes();
		  cipher.update(macDataBytes, 0, macCipherText.length());
		  cipher.doFinal(macBytes, 0);
		  byte[] encodedMacBytes = Hex.encode(macBytes);
		  String mac = new String(encodedMacBytes);
		  return mac;
	  }
	  
}
