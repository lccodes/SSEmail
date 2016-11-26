package encrypt;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;

import com.google.common.collect.Multimap;

public class EncryptedIndex {
	public final Map<String, String> KEYWORDENCRYPTED;
	public final Map<String, String> FILEENCRYPTED;
	public final byte[][] STATE;
	public final Salt[] SALTS;
	
	public EncryptedIndex(Map<String, String> keyword, Map<String, String> file, 
			byte[][] state, Salt[] salts) {
		this.KEYWORDENCRYPTED = keyword;
		this.FILEENCRYPTED = file;
		this.STATE = state;
		this.SALTS = salts;
	}
	
	/**
	 * Constructs PRF -> AES map from plaintext map
	 * @param key1 : key for keyed hash
	 * @param key2 : key for AES
	 * @param plaintext map
	 * @return encrypted map
	 */
	public static Map<String, String> setupIndex(byte[] prfKey, byte[] aesKey,
			Multimap<String, String> plaintext) {
		Map<String, String> encrypted = new HashMap<String, String>();
		
		try {
			int max = 0;
			Map<String, Integer> lengths = new HashMap<String, Integer>();
			for (Entry<String, Collection<String>> entry : plaintext.asMap().entrySet()) {
				int leng = 0;
				for (String id : entry.getValue()) {
					leng += id.length();
				}
				lengths.put(entry.getKey(), leng);
				max = Math.max(leng, max);
			}
			
			for (Entry<String, Collection<String>> entry : plaintext.asMap().entrySet()) {
				String prfOutput = new String(Base64.getEncoder()
						.encode(CryptoPrimitives.generateHmac(prfKey, entry.getKey())));
				StringBuilder documentIds = new StringBuilder();
				for (String id : entry.getValue()) {
					documentIds.append(id.replace(' ', '%'));
					documentIds.append(" ");
				}
				for (int i = 0; i < max - lengths.get(entry.getKey()); i++) {
					documentIds.append("0");
				}
				if (documentIds.charAt(documentIds.length()-1) == ' ') {
					documentIds.deleteCharAt(documentIds.length()-1);
				}
				
				System.out.println(entry.getKey() + " -- " +documentIds.toString());
				byte[] encryptedIds = CryptoPrimitives.encryptAES_CTR_String(aesKey, 
						CryptoPrimitives.randomBytes(16),
						documentIds.toString(), documentIds.toString().length()+3);
				
				encrypted.put(prfOutput, new String(Base64.getEncoder().encode(encryptedIds)));
			}	
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | IOException e) {
			encrypted = null;
			e.printStackTrace();
		}
		
		return encrypted;
	}
}
