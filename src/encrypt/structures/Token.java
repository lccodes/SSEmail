package encrypt.structures;

import java.util.List;

public class Token {
	public final List<String> TK;
	public final int COUNTO;
	public final int COUNTN;
	
	public Token(List<String> tk, int countO) {
		this.TK = tk;
		this.COUNTO = countO;
		this.COUNTN = this.TK.size() - this.COUNTO;
	}
}
