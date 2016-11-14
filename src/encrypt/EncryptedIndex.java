package encrypt;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;
import org.crypto.sse.TextExtractPar;
import org.crypto.sse.TextProc;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

public class EncryptedIndex {
	private final String PATH;
	public final Multimap<String, String> ENCRYPTED;
	public final Salt SALT;
	
	public EncryptedIndex(String saltPath, String path) {
		this.PATH = path;
		Salt salt = null;
		try {
			 salt = Salt.fileToKey(saltPath);
		} catch (IOException e1) {
			System.out.println("Could not find salt file");
			this.ENCRYPTED = null;
			this.SALT = null;
			return;
		}
		this.SALT = salt;
		
		System.out.print("Password: ");
		Scanner scan = new Scanner(System.in);
		byte[] key;
		try {
			key = CryptoPrimitives.keyGenSetM(scan.next(), SALT.SALT, Salt.ICOUNT, Salt.KEYSIZE);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e1) {
			this.ENCRYPTED = null;
			e1.printStackTrace();
			return;
		}
		
		Multimap<String, String> encrypted = ArrayListMultimap.create();
		TextProc.listf(PATH, new ArrayList<File>());
		try {
			TextProc.TextProc(false, PATH);
			Multimap<String, String> plaintext = TextExtractPar.lp1;
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
				String prfOutput = CryptoPrimitives.generateHmac(key, entry.getKey()).toString();
				StringBuilder documentIds = new StringBuilder();
				for (String id : entry.getValue()) {
					documentIds.append(id);
					documentIds.append("~");
				}
				for (int i = 0; i < max - lengths.get(entry.getKey()); i++) {
					documentIds.append("0");
				}
				documentIds.append("~");
				System.out.println(entry.getKey() + " -- " +documentIds.toString());
				byte[] encryptedIds = CryptoPrimitives.encryptAES_CTR_String(key, CryptoPrimitives.randomBytes(16),
						documentIds.substring(0, documentIds.length()-1), documentIds.substring(0, documentIds.length()-1).length()+3);
				
				encrypted.put(prfOutput, encryptedIds.toString());
			}	
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | InvalidKeySpecException | IOException e) {
			encrypted = null;
			e.printStackTrace();
		} finally {
			this.ENCRYPTED = encrypted;
		}
	}
	
	public static void main(String[] args) throws IOException {
		Salt salt = Salt.fileToKey("mySalt");
		try {
			byte[] key = CryptoPrimitives.keyGenSetM("test", salt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			byte[] key2 = CryptoPrimitives.keyGenSetM("test", salt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			byte[] enc = CryptoPrimitives.encryptAES_CTR_String(key, CryptoPrimitives.randomBytes(16), "test", "test".length()+3);
			byte[] out = CryptoPrimitives.decryptAES_CTR_String(enc, key2);
			System.out.println(new String(out));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
