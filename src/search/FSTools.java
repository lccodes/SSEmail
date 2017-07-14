package search;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
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

import org.bouncycastle.util.Arrays;
import org.crypto.sse.CryptoPrimitives;

import com.google.api.services.gmail.model.Message;

import email.EmailHandler;
import email.Query;
import email.Upload;
import encrypt.EncryptedIndex;
import encrypt.FSEncryptedIndex;
import encrypt.structures.Salt;

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
				handler.SERVICE.users().messages().trash("me", message.getId()).execute();
			}
			
			return Upload.uploadState(handler, index) && Upload.uploadEncryptedIndex(handler, index);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
	}
	
	@SuppressWarnings("unchecked")
	public static List<String> queryFetchFiles(Salt prfSalt, Salt aesSalt, Salt authSalt, String token) {
		try {
			EmailHandler handler = new EmailHandler();
			
			Scanner scan = new Scanner(System.in);
			System.out.print("PRF password: ");
			byte[] prfKey = CryptoPrimitives.keyGenSetM(scan.next(), prfSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			System.out.print("AES password: ");
			byte[] aesKey = CryptoPrimitives.keyGenSetM(scan.next(), aesSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			System.out.print("Auth password: ");
			byte[] authKey = CryptoPrimitives.keyGenSetM(scan.next(), authSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			scan.close();
			
			byte[][] encryptedState = Query.downloadState(handler);
			if (encryptedState == null) {
				System.out.println("Corrupted state!");
				return null;
			}
			
			byte[][] decryptedBytes = CryptoPrimitives.auth_decrypt_AES_HMAC(authKey, prfKey, encryptedState);
			if (decryptedBytes[0][0] != '1') {
				System.out.println("Corrupted state!");
				return null;
			}
			byte[] tocopy = Arrays.copyOf(decryptedBytes[1], decryptedBytes[1].length-3);
			byte[] todec = Base64.getDecoder().decode(new String(tocopy));
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(todec));
			Map<String, Integer> state = (Map<String, Integer>) ois.readObject();
			
			Integer count = state.get(token);
			List<String> results = new LinkedList<String>();
			if (count == null) {
				return results;
			}
			
			for (int i = 0; i <= count; i++) {
				String fileList = SimpleTools.queryPlaintextToken(prfKey, aesKey, handler, token + i);
				if (fileList != null) {
					results.addAll(SimpleTools.fetchFiles(prfKey, aesKey, handler, fileList));
				} else if (i != count){
					System.out.println("WARNING: " + token + i + " index file deleted");
				}
			}
			
			return results;
		} catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | 
				NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException 
				| NoSuchPaddingException | ClassNotFoundException e) {
			e.printStackTrace();
		} 
		return null;
	}
	
	public static void main(String[] args) throws FileNotFoundException, IOException {
		//FSTools.createFSSearchableInbox("mySalt", "aesSalt", "authSalt", "test");
		///*
		List<String> decryptedFiles = FSTools.queryFetchFiles(Salt.fileToSalt("mySalt"), Salt.fileToSalt("aesSalt"), 
				Salt.fileToSalt("authSalt"), "tree");
		System.out.println(decryptedFiles);
		//*/
	}

}
