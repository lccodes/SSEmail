package search;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;

import email.EmailHandler;
import email.Query;
import email.Upload;
import encrypt.EncryptedIndex;
import encrypt.Salt;
import encrypt.SimpleEncryptedIndex;

public class SimpleTools {
	
	public static boolean createSimpleSearchableInbox(String prfSaltPath, String aesSaltPath,
			String folderPath) {
		EncryptedIndex index = SimpleEncryptedIndex
				.newSimpleEncryptedIndex(prfSaltPath, aesSaltPath, folderPath);
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
	
	public static String queryPlaintextToken(byte[] prfKey, byte[] aesKey, 
			EmailHandler handler, String token) {
		try {
			String prfOutput = new String(Base64.getEncoder().encode(CryptoPrimitives.generateHmac(prfKey, token)));
			List<String> results = Query.queryToken(handler, prfOutput);
			if (results.size() == 0) {
				return null;
			}
			String emailBody = new String(Base64.getDecoder().decode(results.get(0)));
			byte[] encrypted = Base64.getDecoder().decode(emailBody);
			byte[] decrypted = CryptoPrimitives.decryptAES_CTR_String(encrypted, aesKey);
			
			return new String(decrypted);
		} catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | 
				InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	public static List<String> fetchFiles(byte[] prfKey, byte[] aesKey, 
			EmailHandler handler, String fileList) {
		List<String> fileNames = Arrays.asList(fileList.split(" "));
		List<String> allFileNames = new LinkedList<String>();
		boolean skip = false;
		try {
			if (Integer.parseInt(fileNames.get(fileNames.size()-1).trim()) == 0) {
				skip = true;
			}
		} catch(NumberFormatException e) {
			skip = false;
		}
		for (int i = 0; i < fileNames.size(); i++) {
			if (i == fileNames.size()-1 && skip) {
				break;
			}
			allFileNames.add(fileNames.get(i));
		}
		
		List<String> plaintexts = new LinkedList<String>();
		for (String fileName : allFileNames) {
			String decryptedFile = SimpleTools.queryPlaintextToken(prfKey, aesKey, handler, fileName.trim()).trim();
			if (decryptedFile == null) {
				System.out.println("WARNING: file " + fileName + " was deleted");
				continue;
			}
			plaintexts.add(decryptedFile);
		}
		
		return plaintexts;
	}
	
	public static List<String> queryFetchFiles(Salt prfSalt, Salt aesSalt, String token) {
		try {
			EmailHandler handler = new EmailHandler();
			
			System.out.print("Password: ");
			Scanner scan = new Scanner(System.in);
			
			byte[] prfKey = CryptoPrimitives.keyGenSetM(scan.next(), prfSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			byte[] aesKey = CryptoPrimitives.keyGenSetM(scan.next(), aesSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			scan.close();
			
			String fileList = SimpleTools.queryPlaintextToken(prfKey, aesKey, handler, token);
			if (fileList == null) {
				return new LinkedList<String>();
			}
			return SimpleTools.fetchFiles(prfKey, aesKey, handler, fileList);
		} catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static void main(String[] args) throws FileNotFoundException, IOException {
		//TODO: lib fte
		//System.out.println(SimpleTools.queryFetchFiles(Salt.fileToKey("mySalt"), "horse"));
	}

}
