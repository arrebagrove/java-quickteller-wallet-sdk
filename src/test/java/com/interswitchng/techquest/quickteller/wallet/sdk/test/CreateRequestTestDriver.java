package com.interswitchng.techquest.quickteller.wallet.sdk.test;

import org.junit.Test;

import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.MACUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.SecurityUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.util.ConstantsUtil;
import com.interswitchng.techquest.quickteller.wallet.sdk.util.HexConverter;

import static org.junit.Assert.*;

public class CreateRequestTestDriver {

	private static final String SUBSCRIBER_ID = "2348032286229";
	private static final String PAN = "5092032910293811203";
	private static final String EXPIRY_DATE = "1501"; // YYMM
	private static final String PAYMENT_METHOD_TYPE_CODE = "VVC";
	private static final String TTID = "138";
	private static final String PIN_KEY = "3B9BF75D1F917C2C3E13136D5191083E";
	private static final String MAC_KEY = "3B9BF75D1F917C2C3E13136D5191083E";
	private static final String CREATE_PAYMENT_METHOD_MAC_CIPHER_TEXT = "2348032286229default138";
	private static final String MAC_VALUE = "cb976042";
	
	private static final String EXPECTED_MAC_CIPHER_TEXT = "2348032286229default138";
	private static final String EXPECTED_MAC_VALUE = "cb976042";
	private static final String EXPECTED_PIN_DATA = "d0a087e969ae3cb5";
	private static final String EXPECTED_SECURE = "643d3e828a54bad314c21b69c4174c85b3bbc9fe988b2810b21a4a1f3fc1fca87ccdaf20e1b1a1afad6d327915af64a0fca20746793589648b81841091c356b7085a35a4b813c96b93c0227555b8b35766bc41f8a960e94eda67cdc8cbf833b62d0896c3d823dd8e2ab5f1622ab1b99aad396c86a3e632f2adafef0bdca77447b9509b85b59d075040820cf0f1eb32dfcb775a42c32edee0555c7c3edf4e4b7883a6c0418afd358f27e22e69bacec2b854801637abac7541eedd8e66c444c607e206405f45d245802e42e05c64e1852f7fb7bec28ba50a2c601b1cf1c49655961a05f38335b1387ea154cc6104a47e4ca1dce5fd76d8d52e1c9516a2ee1f8df1";
	
	@Test
	public void shouldReturnExpectedCreateRequestMacCipherText() throws Exception
	{
		String macCipherTest = SecurityUtils.getMacCipherText(SUBSCRIBER_ID, TTID, null, null, null, null);
		assertEquals(EXPECTED_MAC_CIPHER_TEXT, macCipherTest);		
	}
	
	@Test
	public void shouldReturnExpectedCreateRequestMacValue() throws Exception
	{
		byte[] macKeyBytes = HexConverter.fromHex2ByteArray(MAC_KEY.getBytes());
		String macValue = MACUtils.getMacValue(CREATE_PAYMENT_METHOD_MAC_CIPHER_TEXT, macKeyBytes);
		assertEquals(EXPECTED_MAC_VALUE, macValue);		
	}
	
	@Test
	public void shouldReturnExpectedCreateRequestSecure() throws Exception
	{
		byte[] pinKeyBytes = HexConverter.fromHex2ByteArray(PIN_KEY.getBytes());
		byte[] macKeyBytes = HexConverter.fromHex2ByteArray(MAC_KEY.getBytes());
		String secure = SecurityUtils.getSecure(SUBSCRIBER_ID, TTID, MAC_VALUE, pinKeyBytes, macKeyBytes);
		assertEquals(EXPECTED_SECURE, secure);		
	}

}
