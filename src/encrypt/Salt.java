package encrypt;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.crypto.sse.CryptoPrimitives;

public class Salt {
	public final byte[] SALT;
	
	public static final int ICOUNT = 100;
	public static final int SALTSIZE = 32;
	public static final int KEYSIZE = 128;
	
	public Salt(byte[] salt) {
		this.SALT = salt;
	}
	
	public static Salt saltGen(String saltName) throws IOException {
		byte[] salt = CryptoPrimitives.randomBytes(SALTSIZE);
		Files.write(Paths.get("creds/"+saltName), salt);
		
		return new Salt(salt);
	}
	
	public static Salt fileToSalt(String file) throws FileNotFoundException, IOException {		
		return new Salt(Files.readAllBytes(Paths.get("creds/" + file)));
	}

}
