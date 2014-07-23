package com.interswitchng.techquest.quickteller.wallet.sdk.util;

import org.bouncycastle.util.encoders.Hex;

public class AppUtils {

	
	public static byte[] hexConverter(String str)
    {
        byte[] myBytes = Hex.decode(str);
        return myBytes;
    }
	
	public static String padLeft(String data, int maxLen, String padStr)
   {
   	if(data == null || data.length() >= maxLen)
   		return data;
   	int len = data.length();
   	int deficitLen = maxLen - len;
   	for(int i=0; i<deficitLen; i++)
   		data = padStr  + data;    	
   	return data;
   }

	public static String padRight(String data, int maxLen, String padStr)
   {
   	if(data == null || data.length() >= maxLen)
   		return data;
   	int len = data.length();
   	int deficitLen = maxLen - len;
   	for(int i=0; i<deficitLen; i++)
   		data += padStr;
   	return data;
   }
   
	
	public static void zeroise(byte[] data) 
	{
		int len = data.length;
		
		for (int i = 0; i < len; i++)
			data[i] = 0;
	}
	
	public static boolean isNullOrEmpty(String string) {
		return string == null || string.equals("");
	}
}
