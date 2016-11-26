package search;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;

import com.google.api.services.gmail.model.Message;

import email.EmailHandler;
import email.Query;
import email.Upload;
import encrypt.EncryptedIndex;
import encrypt.FSEncryptedIndex;
import encrypt.Salt;

public final class FSTools {
	
	public static boolean createFSSearchableInbox(String prfSaltPath, String aesSaltPath,
			String authSaltPath, String folderPath) {
		EmailHandler handler;
		try {
			handler = new EmailHandler();
			byte[][] state = Query.downloadState(handler);
			EncryptedIndex index = FSEncryptedIndex.newFSEEncryptedIndex(prfSaltPath, aesSaltPath, authSaltPath,
					folderPath, state);
			
			List<Message> messages = Query.getMessages(handler, 
					new String(Base64.getEncoder().encode("STATE".getBytes())));
			for (Message message : messages) {
				handler.SERVICE.users().messages().delete("me", message.getId()).execute();
			}
			
			return Upload.uploadState(handler, index) && Upload.uploadEncryptedIndex(handler, index);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
	}
	
	public static List<String> queryFetchFiles(Salt prfSalt, Salt aesSalt, Salt authSalt, String token) {
		try {
			EmailHandler handler = new EmailHandler();
			
			Scanner scan = new Scanner(System.in);
			System.out.print("PRF assword: ");
			byte[] prfKey = CryptoPrimitives.keyGenSetM(scan.next(), prfSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			System.out.print("AES assword: ");
			byte[] aesKey = CryptoPrimitives.keyGenSetM(scan.next(), aesSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			System.out.print("Auth assword: ");
			byte[] authKey = CryptoPrimitives.keyGenSetM(scan.next(), aesSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			scan.close();
			
			byte[][] encryptedState = Query.downloadState(handler);
			if (encryptedState == null) {
				return new LinkedList<String>();
			}
			byte[][] decryptedBytes = CryptoPrimitives.auth_decrypt_AES_HMAC(authKey, prfKey, encryptedState);
			if (decryptedBytes[0][0] != '1') {
				System.out.println("Corrupted state");
				return null;
			}
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decryptedBytes[1]));
			@SuppressWarnings("unchecked")
			Map<String, Integer> state = (Map<String, Integer>) ois.readObject();
			Integer count = state.get(token);
			List<String> results = new LinkedList<String>();
			if (count == null) {
				return results;
			}
			
			for (int i = 0; i <= count; i++) {
				String fileList = SimpleTools.queryPlaintextToken(prfKey, aesKey, handler, token);
				if (fileList == null) {
					return new LinkedList<String>();
				}
				results.addAll(SimpleTools.fetchFiles(prfKey, aesKey, handler, fileList));
			}
			
			return results;
		} catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | 
				NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
