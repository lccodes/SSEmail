package encrypt.schemes;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import com.google.common.collect.Multimap;

import encrypt.structures.CryptoSystem;
import encrypt.structures.EncryptedState;
import encrypt.structures.EncryptedSystem;
import encrypt.structures.LabelLabel;
import encrypt.structures.LabelValue;
import encrypt.structures.SSEScheme;
import encrypt.structures.Token;
import encrypt.structures.ValueValue;

public class Kumo implements SSEScheme {
	private final CryptoSystem CRYPTO;
	
	public static final String EDITMINUS = "1";
	public static final String EDITPLUS = "2";
	
	public Kumo(CryptoSystem crypto) {
		this.CRYPTO = crypto;
	}

	@Override
	public EncryptedSystem setup(int securityParameter, int lambda, List<Multimap<String, String>> data) {
		Map<String, byte[]> keys = new HashMap<String, byte[]>();
		for (int i = 0; i < data.size(); i++) {
			keys.put(i + "-" + 1, this.CRYPTO.SampleKey(securityParameter));
			keys.put(i + "-" + 2, this.CRYPTO.SampleKey(securityParameter));
		}
		
		EncryptedState encryptedState = new EncryptedState(1);
		
		Map<String, String> O = new HashMap<String, String>();
		Map<String, String> N = new HashMap<String, String>();
		
		SortedSet<LabelLabel> T = new TreeSet<LabelLabel>();
		
		int j = 0;
		for (Multimap<String, String> map : data) {
			for (String k : map.keys()) { //TODO: Do I need to be random? and what is i
				int count = 1;
				int version = 1;
				encryptedState.addL(new LabelValue(k, j));
				for (String v : map.get(k)) {
					String label = this.CRYPTO.F(keys.get(j + "-" + 1), 
							k + version + "" + count);
					String value = this.CRYPTO.Enc(keys.get(j + "-" + 2), 
							v + EDITPLUS);
					T.add(new LabelLabel(label, value));
					encryptedState.putO(new LabelValue(k, j), new ValueValue(version, count));
					count++;
				}
			}
			j++;
		}
		
		int numEntries = 0;
		for (Multimap<String, String> entry : data) {
			numEntries += entry.size(); //TODO: Confirm I'm v count not k count
		}
		
		for(int i = 0; i < lambda - numEntries; i++) {
			String rand1 = this.CRYPTO.BitString(securityParameter); //TODO: Confirm this is what I need
			String rand2 = this.CRYPTO.BitString(securityParameter);
			
			String label = this.CRYPTO.F(keys.get("1-1"), rand1 + "11");
			String value = this.CRYPTO.Enc(keys.get("1-2"), rand2 + EDITPLUS);
			
			T.add(new LabelLabel(label, value));
			encryptedState.putO(new LabelValue(rand1, 1), new ValueValue(1, 1));
		}
		
		for (LabelLabel ll : T) {
			O.put(ll.KEY, ll.VALUE);
		}
		
		encryptedState.incrementVersion();
		
		return new EncryptedSystem(keys, encryptedState, O, N);
	}

	@Override
	public Token tokenize(EncryptedSystem encryptedSystem, int level, String query) {
		int versionN = encryptedSystem.STATE.getVersion(); //TODO: Is this the default?
		int countN = 0;
		ValueValue currentN = encryptedSystem.STATE.getN(new LabelValue(query, level));
		if (currentN != null) {
			versionN = currentN.V1;
			countN = currentN.V2;
		}
		
		int versionO = encryptedSystem.STATE.getVersion();
		int countO = 0;
		ValueValue currentO = encryptedSystem.STATE.getO(new LabelValue(query, level));
		if (currentO != null) {
			versionO = currentO.V1;
			countO = currentO.V2;
		}
		
		encryptedSystem.STATE.addS(new LabelValue(query, level));
		
		//#4
		List<String> token = new LinkedList<String>();
		for (int i = 0; i <= countO; i++) {
			token.add(this.CRYPTO.F(encryptedSystem.KEYS.get(level + "-1"), query + versionO + "" + i));
		}
		for (int j = 0; j <= countN; j++) {
			token.add(this.CRYPTO.F(encryptedSystem.KEYS.get(level + "-1"), query + versionN + "" + j));
		}
		return new Token(token, countO);
	}

	@Override
	public Set<String> query(EncryptedSystem encryptedSystem, Token token) {
		Set<String> results = new HashSet<String>();
		for (int i = 0; i <= token.COUNTO; i++) {
			if (encryptedSystem.DXO.containsKey(token.TK.get(i))) {
				results.add(encryptedSystem.DXO.get(token.TK.get(i)));
			}
		}
		for (int j = 0; j <= token.COUNTN; j++) {
			if (encryptedSystem.DXN.containsKey(token.TK.get(j))) {
				results.add(encryptedSystem.DXN.get(token.TK.get(j)));
			}
		}
		return results;
	}

	@Override
	public Token update(EncryptedSystem encryptedSystem, int level, String query, String value, int op) {
		int count = 1;
		if (!encryptedSystem.STATE.containsL(new LabelValue(query, level))) {
			encryptedSystem.STATE.addL(new LabelValue(query, level));
			encryptedSystem.STATE.putN(new LabelValue(query, level), 
					new ValueValue(encryptedSystem.STATE.getVersion(), 1));
		} else {
			ValueValue vv = encryptedSystem.STATE.getN(new LabelValue(query, level));
			if (vv != null) {
				count = vv.V2+1;
				vv = new ValueValue(encryptedSystem.STATE.getVersion(), count);
			} else {
				vv = new ValueValue(encryptedSystem.STATE.getVersion(), 1);
			}
			encryptedSystem.STATE.putN(new LabelValue(query,level), vv);
		}
		String tk1 = this.CRYPTO.F(encryptedSystem.KEYS.get(level + "-1"), query 
				+ encryptedSystem.STATE.getVersion() + "" + count);
		String tk2 = this.CRYPTO.Enc(encryptedSystem.KEYS.get(level + "-2"), value + op);
		List<String> tokens = new LinkedList<String>();
		tokens.add(tk1);
		tokens.add(tk2);
		return new Token(tokens, 1);
	}

	@Override
	public void put(EncryptedSystem encryptedSystem, Token token) {
		encryptedSystem.DXN.put(token.TK.get(0), token.TK.get(1)); //TODO: #random: how to store L, S on server
	}

	@Override
	public void restruct(EncryptedSystem encryptedSystem) {
		for(LabelValue lv : encryptedSystem.STATE.getS()) {
			ValueValue versionCount = encryptedSystem.STATE.getO(lv);
			if (versionCount != null) {
				 encryptedSystem.STATE.removeO(lv);
				 List<String> token = new LinkedList<String>();
				 List<String> result = new LinkedList<String>();
				 for (int i = 0; i < versionCount.V2; i++) {
					 String otk = this.CRYPTO.F(encryptedSystem.KEYS.get(lv.VALUE + "-1"),
							 lv.LABEL + versionCount.V1 + "" + i);
					 token.add(otk);
					 result.add(encryptedSystem.DXO.get(otk));
				 }
				 List<String> V = new LinkedList<String>();
				 for (String ct : result) {
					 String vedit = this.CRYPTO.Dec(encryptedSystem.KEYS.get(lv.VALUE + "-2"),
							 ct); //TODO: Is this really dec(enc(x))
					 V.add(vedit.substring(0, vedit.length()-1)); //TODO: Is this what we really want?
				 }
				 int countN = 1;
				 ValueValue vv = encryptedSystem.STATE.getN(lv);
				 if (vv != null) {
					 countN = vv.V2;
				 }
				 for (String v : V) { //TODO: How does this work?
					 String tk1 = this.CRYPTO.F(encryptedSystem.KEYS.get(lv.VALUE + "-1"),
							 lv.LABEL + encryptedSystem.STATE.getVersion() + "" + countN);
					 String tk2 = this.CRYPTO.Enc(encryptedSystem.KEYS.get(lv.VALUE + "-2"),
							 v + EDITPLUS);
					 encryptedSystem.DXN.put(tk1, tk2);
					 countN++;
				 }
			}
			
			while(encryptedSystem.STATE.sizeO() != 0) {
				ValueValue versionCountO = encryptedSystem.STATE.getO(lv);
				if (versionCountO.V2 - 1 < 1) {
					encryptedSystem.STATE.removeO(lv);
				} else {
					encryptedSystem.STATE.putO(lv, new ValueValue(versionCountO.V1, versionCountO.V2-1));
				}
				String otk = this.CRYPTO.F(encryptedSystem.KEYS.get(lv.VALUE + "-1"),
						 lv.LABEL + versionCountO.V1 + "" + versionCountO.V2);
				String ct = encryptedSystem.DXO.get(otk);
				ValueValue versionCountN = encryptedSystem.STATE.getN(lv);
				if (versionCountN == null) {
					versionCountN = new ValueValue(encryptedSystem.STATE.getVersion(), 1);
				}
				String tk1 = this.CRYPTO.F(encryptedSystem.KEYS.get(lv.VALUE + "-1"), lv.LABEL + versionCountN.V1 + ""
						+ versionCountN.V2);
				String tk2 = this.CRYPTO.Enc(encryptedSystem.KEYS.get(lv.VALUE + "-2"),
						this.CRYPTO.Dec(encryptedSystem.KEYS.get(lv.VALUE + "-2"), ct));
				encryptedSystem.DXN.put(tk1, tk2);
				encryptedSystem.STATE.putN(lv, new ValueValue(versionCountO.V1, versionCountO.V2 + 1));
			}
			encryptedSystem.STATE.restruct();
			encryptedSystem.DXO.clear();
			encryptedSystem.DXO.putAll(encryptedSystem.DXN);
			encryptedSystem.DXN.clear();
		}
	}

}
