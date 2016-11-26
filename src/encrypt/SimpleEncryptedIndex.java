package encrypt;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.NoSuchPaddingException;

import org.crypto.sse.CryptoPrimitives;
import org.crypto.sse.TextExtractPar;
import org.crypto.sse.TextProc;

public class SimpleEncryptedIndex {
	
	public SimpleEncryptedIndex() {
		throw new UnsupportedOperationException("Do not instantiate");
	}
	
	public static EncryptedIndex newSimpleEncryptedIndex(String prfSaltPath, 
			String aesSaltPath, String toEncryptPath) {
		Salt prfSalt = null;
		Salt aesSalt = null;
		try {
			 prfSalt = Salt.fileToKey(prfSaltPath);
			 aesSalt = Salt.fileToKey(aesSaltPath);
		} catch (IOException e1) {
			System.out.println("Could not find salt file");
			return null;
		}
		
		Scanner scan = new Scanner(System.in);
		byte[] prfKey;
		byte[] aesKey;
		try {
			System.out.print("Password for PRF: ");
			prfKey = CryptoPrimitives.keyGenSetM(scan.next(), prfSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
			System.out.print("Password for AES: ");
			aesKey = CryptoPrimitives.keyGenSetM(scan.next(), aesSalt.SALT, Salt.ICOUNT, Salt.KEYSIZE);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e1) {
			e1.printStackTrace();
			return null;
		} finally {
			scan.close();
		}
		
		Map<String, String> keyword = null;
		Map<String, String> file = null;
		try {
			TextProc.listf(toEncryptPath, new ArrayList<File>());
			TextProc.TextProc(false, toEncryptPath);
			keyword = EncryptedIndex.setupIndex(prfKey, aesKey, TextExtractPar.lp1);
			file = EncryptedIndex.setupIndex(prfKey, aesKey, TextExtractPar.lp2);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchProviderException | NoSuchPaddingException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
		
		return new EncryptedIndex(keyword, file, null, new Salt[]{prfSalt,aesSalt});
	}
	
	public static void main(String[] args) throws IOException {
		//new SimpleEncryptedIndex("mySalt", "test");
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
