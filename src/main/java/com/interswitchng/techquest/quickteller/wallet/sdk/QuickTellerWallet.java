package com.interswitchng.techquest.quickteller.wallet.sdk;

import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.DESUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.MACUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.SecurityUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.util.HexConverter;

public class QuickTellerWallet {

	
	
	public static void createPaymentMethodRequest(String subscriberId, String pan, String expiryDate, String paymentMethodTypeCode, String pinKey)
	{
		byte[] pinKeyBytes = HexConverter.fromHex2ByteArray(pinKey.getBytes());
		byte[] macKeyByte = pinKeyBytes;
		String macCipherText = SecurityUtils.getMacCipherText(subscriberId, null, null, null, null, null);
		
		String mac = MACUtils.getMacValue(macCipherText, macKeyByte);
		String pinData = SecurityUtils.getEncryptedExpiryDateBlock(expiryDate, pinKeyBytes);	
		String secure = SecurityUtils.getCreatePaymentMethodSecure(pan, mac, pinKeyBytes, macKeyByte);
			
		System.out.println("MAC Cipher Text: " + macCipherText);
		System.out.println("MAC Value: " + mac);
		System.out.println("Pin Data: " + pinData);
		System.out.println("Secure: " + secure);
	}
	
	public static void createRequest(String subscriberId, String ttid, String pin, String cvv2, String expiryDate, String paymentMethodTypeCode, String pinKey)
	{
		byte[] pinKeyBytes = HexConverter.fromHex2ByteArray(pinKey.getBytes());
		byte[] macKeyByte = pinKeyBytes;
		String macCipherText = SecurityUtils.getMacCipherText(subscriberId, ttid, null, null, null, null);
		
		String mac = MACUtils.getMacValue(macCipherText, macKeyByte);
		String pinData = SecurityUtils.getEncryptedPinCvv2ExpiryDateBlock(pin, cvv2, expiryDate, pinKeyBytes);	
		String secure = SecurityUtils.getSecure(subscriberId, mac, pinKeyBytes, macKeyByte);
			
		System.out.println("MAC Cipher Text: " + macCipherText);
		System.out.println("MAC Value: " + mac);
		System.out.println("TTID Value: " + ttid);
		System.out.println("Pin Data: " + pinData);
		System.out.println("Secure: " + secure);
	}
	
	public static void main(String[] args)
	{
		try
		{
//			String subscriberId = "2348032286229"; // local format
//			String ttid = "138";
//			String pan = "5092032910293811203";
//			String pin = "1111";
//			String cvv2 = "111";
//			String expiryDate = "1501"; // YYMM
//			String paymentMethodTypeCode = "VVC";
			
			String subscriberId = "2348054582896"; // local format
			String ttid = "138";
			String pan = "5060990580000160624";
			String pin = "1111";
			String cvv2 = "455";
			String expiryDate = "1612"; // YYMM
			String paymentMethodTypeCode = "VVC";
			byte[] pinKeyBytes = DESUtils.generateKey();
			String pinKeyHex = HexConverter.fromBinary2Hex(pinKeyBytes);
			pinKeyHex = "3B9BF75D1F917C2C3E13136D5191083E";
			System.out.println("PIN Key: " + pinKeyHex);
			QuickTellerWallet.createPaymentMethodRequest(subscriberId, pan, expiryDate, paymentMethodTypeCode, pinKeyHex);
			QuickTellerWallet.createRequest(subscriberId, ttid, pin, cvv2, expiryDate, paymentMethodTypeCode, pinKeyHex);
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
	}
}
