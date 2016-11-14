package search;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;

import email.EmailHandler;
import email.Query;
import email.Upload;
import encrypt.EncryptedIndex;
import encrypt.Salt;

public class Tools {
	
	public static boolean createSearchableInbox(String keySaltPath, String folderPath) {
		EncryptedIndex index = new EncryptedIndex(keySaltPath, folderPath);
		if (index.FILEENCRYPTED == null || index.KEYWORDENCRYPTED == null) {
			return false;
		}
		
		EmailHandler handler;
		try {
			handler = new EmailHandler();
			return Upload.uploadEncryptedIndex(handler, index);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}
	
	public static String queryPlaintextToken(Salt salt, String token) {
		try {
			EmailHandler handler = new EmailHandler();
			Scanner scan = new Scanner(System.in);
			System.out.print("Password: ");
			byte[] key = CryptoPrimitives.keyGenSetM(scan.next(), salt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			String prfOutput = new String(Base64.getEncoder().encode(CryptoPrimitives.generateHmac(key, token)));
			String emailBody = new String(Base64.getDecoder().decode(Query.queryToken(handler, prfOutput).get(0)));
			byte[] encrypted = Base64.getDecoder().decode(emailBody);
			byte[] decrypted = CryptoPrimitives.decryptAES_CTR_String(encrypted, key);
			
			scan.close();
			return new String(decrypted);
		} catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException | 
				InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	public static void main(String[] args) throws FileNotFoundException, IOException {
		System.out.println(Tools.queryPlaintextToken(Salt.fileToKey("mySalt"), "monkey"));
	}

}
