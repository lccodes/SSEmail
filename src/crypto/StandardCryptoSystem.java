package crypto;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;

import encrypt.structures.CryptoSystem;

public class StandardCryptoSystem implements CryptoSystem {

	@Override
	public byte[] SampleKey(int securityParameter) {
		return CryptoPrimitives.randomBytes(securityParameter);
	}

	@Override
	public String F(byte[] key, String input) {
		try {
			return Base64.getEncoder().encodeToString(
					CryptoPrimitives.generateHmac512(key, input));
		} catch (UnsupportedEncodingException e) {
			return null;
		}
	}

	@Override
	public String Enc(byte[] key, String input) {
		try {
			return Base64.getEncoder().encodeToString(
					CryptoPrimitives.encryptAES_CTR_String(key, 
							CryptoPrimitives.randomBytes(key.length/8), 
							input,
							input.length()+3));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | 
				NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | IOException e) {
			return null;
		}
	}

	@Override
	public String Dec(byte[] key, String input) {
		try {
			return new String(CryptoPrimitives.decryptAES_CTR_String(input.getBytes(), 
					Base64.getDecoder().decode(key)));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | 
				NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | IOException e) {
			return null;
		}
	}

	@Override
	public String BitString(int securityParameter) {
		return Base64.getEncoder().encodeToString(CryptoPrimitives.randomBytes(securityParameter));
	}

}
