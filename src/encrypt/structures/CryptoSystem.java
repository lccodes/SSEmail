package encrypt.structures;

public interface CryptoSystem {
	public byte[] SampleKey(int securityParameter);
	
	public String F(byte[] key, String input);
	
	public String Enc(byte[] key, String input);
	
	public String Dec(byte[] key, String input);

	public String BitString(int securityParameter);
}
