package encrypt;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;
import org.crypto.sse.TextExtractPar;
import org.crypto.sse.TextProc;

import com.google.common.collect.Multimap;

public class EncryptedIndex {
	private final String PATH;
	public final Map<String, String> KEYWORDENCRYPTED;
	public final Map<String, String> FILEENCRYPTED;
	public final Salt SALT;
	
	public EncryptedIndex(String saltPath, String path) {
		this.PATH = path;
		Salt salt = null;
		try {
			 salt = Salt.fileToKey(saltPath);
		} catch (IOException e1) {
			System.out.println("Could not find salt file");
			this.KEYWORDENCRYPTED = null;
			this.FILEENCRYPTED = null;
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
			this.KEYWORDENCRYPTED = null;
			this.FILEENCRYPTED = null;
			e1.printStackTrace();
			return;
		}
		
		Map<String, String> keyword = null;
		Map<String, String> file = null;
		try {
			TextProc.listf(PATH, new ArrayList<File>());
			TextProc.TextProc(false, PATH);
			keyword = setupIndex(key, TextExtractPar.lp1);
			file = setupIndex(key, TextExtractPar.lp2);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
		
		this.KEYWORDENCRYPTED = keyword;
		this.FILEENCRYPTED = file;
	}

	private Map<String, String> setupIndex(byte[] key, Multimap<String, String> plaintext) {
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
				String prfOutput = new String(Base64.getEncoder().encode(CryptoPrimitives.generateHmac(key, entry.getKey())));
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
				byte[] encryptedIds = CryptoPrimitives.encryptAES_CTR_String(key, CryptoPrimitives.randomBytes(16),
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
	
	public static void main(String[] args) throws IOException {
		new EncryptedIndex("mySalt", "test");
		/*Salt salt = Salt.fileToKey("mySalt");
		try {
			Scanner scan = new Scanner(System.in);
			byte[] key = CryptoPrimitives.keyGenSetM(scan.nextLine(), salt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
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
		}*/
	}
}
