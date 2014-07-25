package com.interswitchng.techquest.quickteller.wallet.sdk.test;

import junit.framework.TestCase;

import org.junit.Test;

import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.MACUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.SecurityUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.util.ConstantsUtil;
import com.interswitchng.techquest.quickteller.wallet.sdk.util.HexConverter;

import static org.junit.Assert.*;

public class CreateRequestTestDriver{

	private static final String SUBSCRIBER_ID = "2348054582896";
	private static final String PAN = "5060990580000160624";
	private static final String EXPIRY_DATE = "1501"; // YYMM
	private static final String PAYMENT_METHOD_TYPE_CODE = "VVC";
	private static final String TTID = "138";
	private static final String PIN_KEY = "3B9BF75D1F917C2C3E13136D5191083E";
	private static final String MAC_KEY = "3B9BF75D1F917C2C3E13136D5191083E";
	private static final String CREATE_PAYMENT_METHOD_MAC_CIPHER_TEXT = "2348054582896default138";
	private static final String MAC_VALUE = "11f690ce";
	
	private static final String EXPECTED_MAC_CIPHER_TEXT = "2348054582896default138";
	private static final String EXPECTED_MAC_VALUE = "11f690ce";
	private static final String EXPECTED_PIN_DATA = "e5a7ba794d9e527a";
	private static final String EXPECTED_SECURE = "008fb30ff85723b3b227c4be04b7c59c2267ddd5239bfe47c67f79f7a5c5470ff80d2c9a4b11201ef505fdeb9dc1c2fa494e41364652247fbf2bdcaf6bbe02bcdbf60d06f6f1d5659ca1d73ef876622f3dc9e3f6326f515ac1c77322158a89611491dca42b4bd2221349c347400f99dce3b34afdb69b7362c7bbccb350302b62c13a93a652b8571ae53111514eea4cf97f92c36ec1c71dab4dd7acb1131fad42bc75da6237a5ce58f6264fa64774fff00949aa3cff1e4bcb0f1fd36ebe7573407e2c59090a5bd6c07262f691b077c2090c1886da7841d46cb411ee1ba9934aa857710a6cfbcf078d3d055a31cfb1bbb541cc84d5e8e34a6ab5c6208d01113e5c";
	
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
		String secure = SecurityUtils.getSecure(SUBSCRIBER_ID, MAC_VALUE, pinKeyBytes, macKeyBytes);
		assertEquals(EXPECTED_SECURE, secure);		
	}

}
