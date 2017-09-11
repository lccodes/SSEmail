package email;

import java.util.List;
import java.util.Set;

import com.google.common.collect.Multimap;

import encrypt.structures.EncryptedSystem;
import encrypt.structures.SSEScheme;

public class SSEManager {
	private final SSEScheme SCHEME;
	private final EmailHandler HANDLER;
	
	private boolean setup;
	
	public SSEManager(SSEScheme scheme, EmailHandler handler) {
		this.SCHEME = scheme;
		this.HANDLER = handler;
		
		this.setup = false;
	}
	
	/**
	 * Init the SSE system on the remote server and locally
	 * @param localDir
	 * @param securityParameter
	 * @param lambda
	 * @param data
	 * @return
	 */
	public boolean setup(String localDir, int securityParameter, int lambda, List<Multimap<String, String>> data) {
		if (setup) {
			return !this.setup;
		}
		
		EncryptedSystem system = this.SCHEME.setup(securityParameter, lambda, data);
		if(!Upload.uploadEncryptedSystem(this.HANDLER, system) || !system.saveKeys(localDir)) {
			return this.setup;
		}
		
		this.setup = true;
		return this.setup;
	}
	
	/**
	 * Queries w/ plaintext query using REDS
	 * @param level
	 * @param query
	 * @return plaintext results
	 */
	public Set<String> query(int level, String query) {
		//TODO
		//Tokenize
		//Query
		//Decrypt results using level
		return null;
	}
	
	/**
	 * Puts plaintext query+value update token on REDS
	 * @param level
	 * @param query
	 * @param value
	 * @param op
	 * @return success
	 */
	public boolean update(int level, String query, String value, int op) {
		//TODO
		//Tokenize
		//Put
		return false;
	}
	
	/**
	 * Restructs REDS
	 * @return success
	 */
	public boolean restruct() {
		//TODO
		//Reconstruct
		return false;
	}

}
