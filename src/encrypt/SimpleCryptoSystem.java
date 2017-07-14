package encrypt;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;

import encrypt.structures.CryptoSystem;

public class SimpleCryptoSystem implements CryptoSystem {

	@Override
	public byte[] SampleKey(int securityParameter) {
		return CryptoPrimitives.randomBytes(securityParameter);
	}

	@Override
	public String F(byte[] key, String input) {
		try {
			return new String(Base64.getEncoder()
					.encode(CryptoPrimitives.generateHmac(key, input)));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String Enc(byte[] key, String input) {
		try {
			return new String(Base64.getEncoder().encode(
					CryptoPrimitives.encryptAES_CTR_String(key, 
							CryptoPrimitives.randomBytes(key.length/8),
							input.toString(), input.toString().length()+3)));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String Dec(byte[] key, String input) {
		try {
			return new String(CryptoPrimitives.decryptAES_CTR_String(
					Base64.getDecoder().decode(input), key));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String BitString(int securityParameter) {
		// TODO Auto-generated method stub
		SecureRandom random = new SecureRandom();
		StringBuilder string = new StringBuilder();
		if (securityParameter > 0) {
			while(random.ints().iterator().hasNext() && securityParameter-- > 0) {
				string.append(random.ints().iterator().nextInt() % 2);
			}
		}
		return string.toString();
	}

}
