package com.interswitchng.techquest.quickteller.wallet.sdk.test;

import junit.framework.TestCase;

import org.junit.Test;

import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.MACUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.SecurityUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.util.ConstantsUtil;
import com.interswitchng.techquest.quickteller.wallet.sdk.util.HexConverter;

import static org.junit.Assert.*;

public class CreatePaymentMethodTestDriver{

	private static final String SUBSCRIBER_ID = "2348054582896";
	private static final String PAN = "5060990580000160624";
	private static final String EXPIRY_DATE = "1501"; // YYMM
	private static final String PAYMENT_METHOD_TYPE_CODE = "VVC";
	private static final String PIN_KEY = "3B9BF75D1F917C2C3E13136D5191083E";
	private static final String MAC_KEY = "3B9BF75D1F917C2C3E13136D5191083E";
	private static final String CREATE_PAYMENT_METHOD_MAC_CIPHER_TEXT = "2348054582896default";
	private static final String MAC_VALUE = "2ef0a9ae";
	
	private static final String EXPECTED_MAC_CIPHER_TEXT = "2348054582896default";
	private static final String EXPECTED_MAC_VALUE = "2ef0a9ae";
	private static final String EXPECTED_DATA = "acfad6fda13cbb46";
	private static final String EXPECTED_SECURE = "70cebf0d5b361ba362fbd6e0750c73ebe2271286a8024eba852c15c36a95e6e82c456ec6b5629c6aeeac11e252caf89c4ffc8b65268158aaa5ec5c195731c3a516bf117cb6fc2fed931ebbd49df4cfef58e019ddc4cb6c7889d2578816c00ba0d4713c2081a3c849bedae1c0544ae4eeda0990c0f6e1418f947ae68e100878d297aca14f241baae8e34bbb512698a949c3f1cf38ef4d8ec6c53b1a9b2fcfb3c4e79cdfdabbabb7965b244ae847e350438004736b7b1b77a66f746523f6185549c2b8af84cb975b181a92d02bbd5ed7bd1e50f678550b6618ed2738ec17808866cc5430ce37c0552ece616c43e97410371aac893fd9af7d80108c1cb89808c15d";
	
	@Test
	public void shouldReturnExpectedCreatePaymentMethodMacCipherText() throws Exception
	{
		String macCipherTest = SecurityUtils.getMacCipherText(SUBSCRIBER_ID, null, null, null, null, null);
		assertEquals(EXPECTED_MAC_CIPHER_TEXT, macCipherTest);		
	}
	
	@Test
	public void shouldReturnExpectedCreatePaymentMethodMacValue() throws Exception
	{
		byte[] macKeyBytes = HexConverter.fromHex2ByteArray(MAC_KEY.getBytes());
		String macValue = MACUtils.getMacValue(CREATE_PAYMENT_METHOD_MAC_CIPHER_TEXT, macKeyBytes);
		assertEquals(EXPECTED_MAC_VALUE, macValue);		
	}
	
	@Test
	public void shouldReturnExpectedCreatePaymentMethodSecure() throws Exception
	{
		byte[] pinKeyBytes = HexConverter.fromHex2ByteArray(PIN_KEY.getBytes());
		byte[] macKeyBytes = HexConverter.fromHex2ByteArray(MAC_KEY.getBytes());
		String secure = SecurityUtils.getCreatePaymentMethodSecure(PAN, MAC_VALUE, pinKeyBytes, macKeyBytes);
		assertEquals(EXPECTED_SECURE, secure);		
	}

}
