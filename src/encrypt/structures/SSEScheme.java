package encrypt.structures;

import java.util.List;
import java.util.Set;

import com.google.common.collect.Multimap;

public interface SSEScheme {
	/**
	 * Sets up an SSE scheme
	 * @param securityParameter : security param
	 * @param lambda
	 * @param data : data structures
	 * @return EncryptedSystem
	 */
	public EncryptedSystem setup(int securityParameter, int lambda, List<Multimap<String, String>> data);
	
	public Token tokenize(EncryptedSystem encryptedSystem, int level, String query);
	
	public Set<String> query(EncryptedSystem encryptedSystem, Token token);
	
	public Token update(EncryptedSystem encryptedSystem, int level, String query, String value, int op);
	
	public void put(EncryptedSystem encryptedSystem, Token token);
	
	public void restruct(EncryptedSystem encryptedSystem);
}
