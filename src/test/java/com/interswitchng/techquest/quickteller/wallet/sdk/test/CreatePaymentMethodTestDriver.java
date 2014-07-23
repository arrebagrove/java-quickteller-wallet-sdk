package com.interswitchng.techquest.quickteller.wallet.sdk.test;

import org.junit.Test;

import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.MACUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.crypto.SecurityUtils;
import com.interswitchng.techquest.quickteller.wallet.sdk.util.ConstantsUtil;
import com.interswitchng.techquest.quickteller.wallet.sdk.util.HexConverter;

import static org.junit.Assert.*;

public class CreatePaymentMethodTestDriver {

	private static final String SUBSCRIBER_ID = "2348032286229";
	private static final String PAN = "5092032910293811203";
	private static final String EXPIRY_DATE = "1501"; // YYMM
	private static final String PAYMENT_METHOD_TYPE_CODE = "VVC";
	private static final String PIN_KEY = "3B9BF75D1F917C2C3E13136D5191083E";
	private static final String MAC_KEY = "3B9BF75D1F917C2C3E13136D5191083E";
	private static final String CREATE_PAYMENT_METHOD_MAC_CIPHER_TEXT = "2348032286229default";
	private static final String MAC_VALUE = "c6fea8f2";
	
	private static final String EXPECTED_MAC_CIPHER_TEXT = "2348032286229default";
	private static final String EXPECTED_MAC_VALUE = "c6fea8f2";
	private static final String EXPECTED_DATA = "e338b1c4fe769a4c";
	private static final String EXPECTED_SECURE = "0537462c52ac2138dd9372fbcca65973f15b346d1488fdb558d43f00a9a5cc3b59a340a09398183b85e6a392b36e404af04e8a922f0c310b257afa9ab819f39c52323953800b76eaf5af6553ff5516f4e7256c1fb1a96859343dc03e3a07c5e45be741de275c10066acc3c25954637905ed35a033436a14174932e3e62705f38d559279fdc9b5cf4e7a6b3afe6b2c75d7fe59e512fdbbb0f9c2e768845b8a309c008aa6046a1b40b19ecf60c48f9e72423c5dd50b427d719bd9731de2c5e3ee2aacf99096153d0a5cab1bb63b42237db2f1122101fdb0831d650f579f38b1511b8e3fa0487cb4cb78fbd166639bb498fc38d2266c6d4d78d99b69978a5ad8b45";
	
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
