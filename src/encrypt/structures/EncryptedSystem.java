package encrypt.structures;

import java.util.Map;

public class EncryptedSystem {
	public final Map<String, byte[]> KEYS;
	public final EncryptedState STATE;
	public final Map<String, String> DXO;
	public final Map<String, String> DXN;
	
	public EncryptedSystem(Map<String, byte[]> keys, EncryptedState state, 
			Map<String, String> dxO, Map<String, String> dxN) {
		this.KEYS = keys;
		this.STATE = state;
		this.DXO = dxO;
		this.DXN = dxN;
	}
}
