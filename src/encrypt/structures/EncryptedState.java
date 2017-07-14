package encrypt.structures;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class EncryptedState {
	private int version;
	private Set<LabelValue> L, S;
	private Map<LabelValue, ValueValue> O, N; 
	
	public EncryptedState(int version) {
		this.version = version;
		this.L = new HashSet<LabelValue>();
		this.S = new HashSet<LabelValue>();
		this.O = new HashMap<LabelValue, ValueValue>();
		this.N = new HashMap<LabelValue, ValueValue>();
	}
	
	public void addL(LabelValue labelValue) {
		this.L.add(labelValue);
	}
	
	public void addS(LabelValue toAdd) {
		this.S.add(toAdd);
	}
	
	public void putN(LabelValue i, ValueValue j) {
		this.N.put(i, j);
	}
	
	public void putO(LabelValue labelValue, ValueValue valueValue) {
		this.O.put(labelValue, valueValue);
	}
	
	public boolean containsL(LabelValue test) {
		return this.L.contains(test);
	}
	
	public boolean containsS(LabelValue test) {
		return this.S.contains(test);
	}
	
	public ValueValue getO(LabelValue key) {
		return this.O.get(key);
	}
	
	public ValueValue getN(LabelValue key) {
		return this.N.get(key);
	}
	
	public int getVersion() {
		return this.version;
	}
	
	public void incrementVersion() {
		this.version++;
	}
	
	public Set<LabelValue> getS() {
		return this.S;
	}

	public void removeO(LabelValue lv) {
		this.O.remove(lv);
	}

	public int sizeO() {
		return this.O.size();
	}

	public void restruct() {
		this.O.clear();
		this.O.putAll(this.N);
		this.N.clear();
		this.S.clear();
		this.version++;
	}
}
