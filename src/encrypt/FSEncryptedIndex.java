package encrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.util.Arrays;
import org.crypto.sse.CryptoPrimitives;
import org.crypto.sse.TextExtractPar;
import org.crypto.sse.TextProc;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

public class FSEncryptedIndex {
	public static final int LAMBDA = 2;
	
	public FSEncryptedIndex() {
		throw new UnsupportedOperationException("Cannot instantiate");
	}
	
	@SuppressWarnings("unchecked")
	public static EncryptedIndex newFSEEncryptedIndex(String prfSaltPath, 
			String aesSaltPath, String authSaltPath, String toEncryptPath,
			byte[][] encryptedState) {
		Salt prfSalt = null;
		Salt aesSalt = null;
		Salt authSalt = null;
		try {
			 prfSalt = Salt.fileToSalt(prfSaltPath);
			 aesSalt = Salt.fileToSalt(aesSaltPath);
			 authSalt = Salt.fileToSalt(authSaltPath);
		} catch (IOException e1) {
			System.out.println("Could not find salt files");
			return null;
		}
		
		Scanner scan = new Scanner(System.in);
		try {
			byte[] prfKey = null;
			byte[] aesKey = null;
			byte[] authKey = null;
			System.out.print("Password for PRF: ");
			prfKey = CryptoPrimitives.keyGenSetM(scan.next(), prfSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			System.out.print("Password for AES: ");
			aesKey = CryptoPrimitives.keyGenSetM(scan.next(), aesSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			System.out.print("Password for AUTH: ");
			authKey = CryptoPrimitives.keyGenSetM(scan.next(), authSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			Map<String, Integer> state = new HashMap<String, Integer>();
			if (encryptedState != null) {
				byte[][] decryptedBytes = CryptoPrimitives.auth_decrypt_AES_HMAC(authKey, prfKey, 
						encryptedState);
				if (decryptedBytes[0][0] != '1') {
					System.out.println("Corrupted state");
					return null;
				}
				byte[] tocopy = Arrays.copyOf(decryptedBytes[1], decryptedBytes[1].length-3);
				byte[] todec = Base64.getDecoder().decode(new String(tocopy));
				ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(todec));
				state = (Map<String, Integer>) ois.readObject();
			}
			
			TextProc.listf(toEncryptPath, new ArrayList<File>());
			TextProc.TextProc(false, toEncryptPath);
			Multimap<String, String> keyword = TextExtractPar.lp1;
			Multimap<String, String> concatKeyword = ArrayListMultimap.create();
			for (String kword : keyword.keySet()) {
				Integer count = state.getOrDefault(kword, 0);
				final int skipAt = keyword.get(kword).size();
				int miniCount = 0;
				for (String id : keyword.get(kword)) {
					concatKeyword.put(kword + count, id);
					if (++miniCount >= skipAt) {
						miniCount = 0;
						count++;
					}
				}
				state.put(kword, count);
			}
			
			Map<String, String> encryptedKeyword = EncryptedIndex.setupIndex(prfKey, aesKey, concatKeyword);
			Map<String, String> encryptedFile = EncryptedIndex.setupIndex(prfKey, aesKey, TextExtractPar.lp2);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(state);
			
			byte[] stateByteArray = baos.toByteArray();
			byte[] encodedBytes = Base64.getEncoder().encode(stateByteArray);
			String out = new String(encodedBytes);
			
			byte[][] encryptedOutState = CryptoPrimitives.auth_encrypt_AES_HMAC(authKey, prfKey, 
					CryptoPrimitives.randomBytes(16), out, out.length()+3);
			
			return new EncryptedIndex(encryptedKeyword, encryptedFile, 
					encryptedOutState, new Salt[]{prfSalt,aesSalt,authSalt});
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e1) {
			e1.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			scan.close();
		}
		
		return null;
	}
	
	public static void main(String[] args) throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, ClassNotFoundException {
		//byte[][] state = Query.downloadState(new EmailHandler());
		//EncryptedIndex index = FSEncryptedIndex.newFSEEncryptedIndex("mySalt", "aesSalt", "authSalt", 
		//		"test", state);
	}
}
