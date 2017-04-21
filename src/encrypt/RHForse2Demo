import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.crypto.NoSuchPaddingException;


import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;


public class RHForse2Demo {
	
	//The global state for restructuring
	static int state_global_version = 1;
	
	// A set that stores all labels of the multi-map
	static Collection<String> state_set_labels = new HashSet<String>();
	
	//A set that stores all labels that have been searched for
	static Collection<String> state_set_search = new HashSet<String>();
	
	//An old dictionary that stores the version/count for every label
	static Multimap<String, Integer[]> state_old_DX = ArrayListMultimap.create(); 
	
	//A new dictionary that stores the version/count for every label
	static Multimap<String, Integer[]> state_new_DX = ArrayListMultimap.create(); 	
	
	
	//A dictionary that will hold the encrypted multi-map
	public Multimap<String, byte[]> old_dictionary = ArrayListMultimap.create(); 	
	
	//A dictionary that will hold the encrypted multi-map
	public Multimap<String, byte[]> new_dictionary = ArrayListMultimap.create(); 
	
	//size of the value
	public static int sizeOfFileIdentifer = 100;
	
	//a buffer(stash) used by the user to de-amortize the restructuring. In case
	//the tuple size of a particular keyword is larger than the public parameter, we stash
	//remaining to be added in the next restructuring step
	//This is very important for security reasons
	public static List<byte[]> stash_1 = new ArrayList<byte[]>(); 
	public static List<byte[]> stash_2 = new ArrayList<byte[]>(); 
	public static Multimap<String, byte[]> stash_MM_1 = ArrayListMultimap.create(); 
	public static Multimap<String, byte[]> stash_MM_2 = ArrayListMultimap.create(); 
	
	public RHForse2Demo (Multimap<String, byte[]> old_dictionary, Multimap<String, byte[]> new_dictionary){
		this.old_dictionary = old_dictionary;
		this.new_dictionary = new_dictionary;
	}


	
	public Multimap<String, byte[]> getOld_dictionary() {
		return old_dictionary;
	}


	public void setOld_dictionary(Multimap<String, byte[]> old_dictionary) {
		this.old_dictionary = old_dictionary;
	}


	public Multimap<String, byte[]> getNew_dictionary() {
		return new_dictionary;
	}


	public void setNew_dictionary(Multimap<String, byte[]> new_dictionary) {
		this.new_dictionary = new_dictionary;
	}

	// ***********************************************************************************************//

	///////////////////// Key Generation /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] keyGen(int keySize, String password, String filePathString, int icount)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		File f = new File(filePathString);
		byte[] salt = null;

		if (f.exists() && !f.isDirectory()) {
			salt = CryptoPrimitives.readAlternateImpl(filePathString);
		} else {
			salt = CryptoPrimitives.randomBytes(keySize/8);
			CryptoPrimitives.write(salt, "salt", "salt");
		}

		byte[] key = CryptoPrimitives.keyGenSetM(password, salt, icount, keySize);
		return key;

	}
	
	// ***********************************************************************************************//

	///////////////////// Setup /////////////////////////////

	// ***********************************************************************************************//





	public static Multimap<String, byte[]> setup(byte[] key1, byte[] key2, String[] listOfKeyword, Multimap<String, String> lookup) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		
		Multimap<String, byte[]> old_dx = ArrayListMultimap.create();
		
		for (String l : listOfKeyword){
			//add the label to the set of labels
			state_set_labels.add(l);
			
			// initialize temporary counter/version
			int count =1;
			int version = 1;
			
			//compute the label/values
			for (String v : lookup.get(l)){
				byte[] label = CryptoPrimitives.generateHmac(key1, l+version+count);
				byte[] value = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16), v+"+", sizeOfFileIdentifer);
				old_dx.put(new String(label, "ISO-8859-1"), value);
				count =count+1;
			}	
			state_old_DX.put(l, new Integer[]{version, count-1});

		}
		
		return old_dx;
	}
	
	// ***********************************************************************************************//

	///////////////////// Setup Parallel /////////////////////////////

	// ***********************************************************************************************//
	
	
	public static RHForse2 constructEMMParGMM(final byte[] key1, final byte[] key2, final Multimap<String, String> lookup) throws InterruptedException, ExecutionException, IOException {

		final Multimap<String, byte[]> old_dictionary = ArrayListMultimap.create();
		final Multimap<String, byte[]> new_dictionary = ArrayListMultimap.create();


		List<String> listOfKeyword = new ArrayList<String>(lookup.keySet());
		int threads = 0;
		if (Runtime.getRuntime().availableProcessors() > listOfKeyword.size()) {
			threads = listOfKeyword.size();
		} else {
			threads = Runtime.getRuntime().availableProcessors();
		}

		ExecutorService service = Executors.newFixedThreadPool(threads);
		ArrayList<String[]> inputs = new ArrayList<String[]>(threads);

		for (int i = 0; i < threads; i++) {
			String[] tmp;
			if (i == threads - 1) {
				tmp = new String[listOfKeyword.size() / threads + listOfKeyword.size() % threads];
				for (int j = 0; j < listOfKeyword.size() / threads + listOfKeyword.size() % threads; j++) {
					tmp[j] = listOfKeyword.get((listOfKeyword.size() / threads) * i + j);
				}
			} else {
				tmp = new String[listOfKeyword.size() / threads];
				for (int j = 0; j < listOfKeyword.size() / threads; j++) {

					tmp[j] = listOfKeyword.get((listOfKeyword.size() / threads) * i + j);
				}
			}
			inputs.add(i, tmp);
		}

		System.out.println("End of Partitionning  \n");

		List<Future<Multimap<String, byte[]>>> futures = new ArrayList<Future<Multimap<String, byte[]>>>();
		for (final String[] input : inputs) {
			Callable<Multimap<String, byte[]>> callable = new Callable<Multimap<String, byte[]>>() {
				public Multimap<String, byte[]> call() throws Exception {

					Multimap<String, byte[]> output = setup(key1,key2, input, lookup);
					return output;
				}
			};
			futures.add(service.submit(callable));
		}

		service.shutdown();

		for (Future<Multimap<String, byte[]>> future : futures) {
			Set<String> keys = future.get().keySet();

			for (String k : keys) {
				old_dictionary.putAll(k, future.get().get(k));
			}

		}
		state_global_version ++;

		return new RHForse2(old_dictionary, new_dictionary);
	}
	
	
	// ***********************************************************************************************//

	///////////////////// Search Token generation /////////////////////
	
	// ***********************************************************************************************//

	public static String[][] token(byte[] key1, byte[]  key2, String keyword) throws UnsupportedEncodingException {

		int new_version = 0;
		int new_counter = 0;
		int old_version = 0;
		int old_counter = 0;
		
		if (state_new_DX.containsKey(keyword)){
			Integer[] temp = state_new_DX.get(keyword).iterator().next();
			new_version = temp[0];
			new_counter = temp[1];
		}


		if (state_old_DX.containsKey(keyword)){
			Integer[] temp = state_old_DX.get(keyword).iterator().next();
			old_version = temp[0];
			old_counter = temp[1];

		}		
		
		//adding the searched for kewyord to the set
		//if and only if the label keyword exists in the old dictionary.
		//this to ensure the correctness of the de-amortized restructuring 		
		if (old_counter>0){
			state_set_search.add(keyword);
		}
		
		String[][] stoken = new String[2][];

		String[] temp1 = new String[old_counter];
		String[] temp2 = new String[new_counter];

		for (int i = 1; i <= old_counter;i++){
			temp1[i-1] = new String(CryptoPrimitives.generateHmac(key1, keyword+old_version+i), "ISO-8859-1");
		}
		
		stoken[0] = temp1;
		for (int i = 1; i <= new_counter;i++){
			temp2[i-1] = new String(CryptoPrimitives.generateHmac(key1, keyword+new_version+i), "ISO-8859-1");
		}
		stoken[1] = temp2;
		return stoken;
	}	
	
	// ***********************************************************************************************//

	///////////////////// Query (test alg) /////////////////////////////

	// ***********************************************************************************************//	
	
	public static List<byte[]> query(String[][] stoken, RHForse2 emm){

		List<byte[]> result = new ArrayList<byte[]>();
		
		
		
		for (int i = 0; i < stoken[0].length ; i++){
			result.add(emm.getOld_dictionary().get(stoken[0][i]).iterator().next());
		}
		
		
		for (int i = 0; i < stoken[1].length ; i++){
			result.add(emm.getNew_dictionary().get(stoken[1][i]).iterator().next());
		}
		
		return result;
	}	
	
	// ***********************************************************************************************//

	///////////////////// Decryption Algorithm /////////////////////////////

	// ***********************************************************************************************//

	public static List<String> resolve(byte[] key2, List<byte[]> list) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{


		List<String> result = new ArrayList<String>();
		List<String> suppress = new ArrayList<String>();

		for (byte[] ct : list) {
			String decr = new String(CryptoPrimitives.decryptAES_CTR_String(ct, key2)).split("\t\t\t")[0];
			if (decr.substring(decr.length()-1, decr.length()).equals("+")){
				result.add(decr.substring(0, decr.length()-1));
			}
			else{
				suppress.add(decr.substring(0, decr.length()-1));
			}
		}
		
		for (String decr : suppress){
			if (result.contains(decr)){
				result.remove(decr);
			}
		}
		return result;
	}
	
	// ***********************************************************************************************//

	///////////////////// Token Update /////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] tokenUp(byte[] key1, byte[] key2, String label, String value, String op) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		byte[][] tokenUp = new byte[2][];
		
		int version =0;
		int counter =0;
		if (!state_set_labels.contains(label)){
			version = state_global_version;
			counter =1;
			state_set_labels.add(label);
			state_new_DX.put(label, new Integer[]{version, counter});
		}
		else{
			if (state_new_DX.containsKey(label)){
				Integer[] temp = state_new_DX.get(label).iterator().next();
				version = temp[0];
				counter = temp[1];
				counter ++;
				state_new_DX.removeAll(label);
				state_new_DX.put(label, new Integer[]{state_global_version, counter});
			}
			else{
				counter = 1;
				version = state_global_version;
				state_new_DX.put(label, new Integer[]{version, counter});

			}
		}
		
		System.out.println("Version "+version+" counter "+counter);
		tokenUp[0] = CryptoPrimitives.generateHmac(key1, label+version+counter);
		tokenUp[1] = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16), value+op, sizeOfFileIdentifer);
		
		return tokenUp;
	}
	
	
	// ***********************************************************************************************//

	///////////////////// Update /////////////////////////////

	// ***********************************************************************************************//

	public static void update(byte[][] tokenUp, RHForse2 emm) throws UnsupportedEncodingException {

		Multimap<String, byte[]> temp = emm.getNew_dictionary();
		temp.put(new String(tokenUp[0] ,"ISO-8859-1"), tokenUp[1]);
		
		emm.setNew_dictionary(temp);

	}
	
	// ***********************************************************************************************//

	///////////////////// Restruct /////////////////////////////

	// ***********************************************************************************************//

	public static void deamortized_restruct(byte[] key1, byte[] key2, RHForse2 emm, int public_parameter) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
	
		//Client computation 
		// computation of a sample of a Bernoulli distribution
		byte[] rnd  = CryptoPrimitives.randomBytes(4);
		int sample = 0;
		double parameter = ((double)state_set_search.size()) / state_old_DX.keySet().size();
		if (CryptoPrimitives.getLongFromByte(rnd, 32)/Math.pow(2, 31) < parameter){
			sample++;
		}
		
		System.out.println("The prob in (0,1) "+CryptoPrimitives.getLongFromByte(rnd, 32)/Math.pow(2, 33));
		System.out.println("The value of the search set "+state_set_search.size()+" and the number of remaining labels "+state_old_DX.keySet().size());
		System.out.println("The value of the parameter "+parameter);
		System.out.println("The value of the sample "+sample);
		
		//Filling the stashes with at least public_parameter sub-tokens
		if ((sample == 1) && (state_set_search.size() >0) && (stash_MM_1.keySet().size() < public_parameter)){
			
			System.out.println("Enter sample 1");

			
			String label = state_set_search.iterator().next();
			state_set_search.remove(label);
			int old_version = 0;
			int old_counter = 0;
			
			if (state_old_DX.containsKey(label)){
				Integer[] temp = state_old_DX.get(label).iterator().next();
				old_version = temp[0];
				old_counter = temp[1];
			}
			
			//remove label from old dictionary
			state_old_DX.removeAll(label);
			
			//add all tokens to the statsh_1 (a stash that contains the searched for token)
			
			for (int i = 1; i <= old_counter;i++){
				String l = new String(CryptoPrimitives.generateHmac(key1, label+old_version+i), "ISO-8859-1");
				stash_1.add(emm.getOld_dictionary().get(l).iterator().next());
			}
			
			
			//compute the Result set to insert
			List<String> result = new ArrayList<String>();
			result = RHForse2.resolve(key2, stash_1);

			stash_1 = new ArrayList<byte[]>(); 
			
			// setting the counter / version right
			int new_version = 0;
			int new_counter = 0;
			
			if (state_new_DX.containsKey(label)){
				Integer[] temp = state_new_DX.get(label).iterator().next();
				new_version = temp[0];
				new_counter = temp[1];
			}
			else{
				new_counter=0;
				new_version = state_global_version;
			}
			
			
			//Calculating the new label/values to insert in the new dictionary

			for (String val : result){
				new_counter ++;
				String l = new String(CryptoPrimitives.generateHmac(key1, label+new_version+new_counter), "ISO-8859-1");
				byte[] v = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16), val+"+", sizeOfFileIdentifer);
				stash_MM_1.put(l, v);
			}
			
			// Updating the new state DX
			state_new_DX.removeAll(label);
			state_new_DX.put(label, new Integer[]{state_global_version,new_counter});

		}
		else if ((stash_MM_2.size()<public_parameter) && (state_old_DX.keySet().size()>0)){
			
			System.out.println("Enter sample 0");

			while ((stash_MM_2.size() < public_parameter) && (state_old_DX.keySet().size() >0)){
				
				//select a label that has not been searched for
				//TO DO , we need to randomize the order of the state_old_DX.keySet()
				// as well as the search set
				String label="";
				Iterator<String> it = state_old_DX.keySet().iterator();
				while(it.hasNext()){
					label = it.next();
					if (!state_set_search.contains(label)){
						break;
					}
				}
				//getting the counters
				Integer[] temp = state_old_DX.get(label).iterator().next();
				int old_version = temp[0];
				int old_counter = temp[1];
				
				//updating the state
				state_old_DX.removeAll(label);
				if (old_counter > 1){
					state_old_DX.put(label, new Integer[]{old_version,old_counter-1});
				}
				
				String l = new String(CryptoPrimitives.generateHmac(key1, label+old_version+old_counter), "ISO-8859-1");
				String value = new String(CryptoPrimitives.decryptAES_CTR_String(emm.getOld_dictionary().get(l).iterator().next(), key2)).split("\t\t\t")[0];	
				System.out.println("The value is equal to "+value);
				
				// setting the counter / version right
				int new_version = 0;
				int new_counter = 0;
				if (state_new_DX.containsKey(label)){
					temp = state_new_DX.get(label).iterator().next();
					new_version = temp[0];
					new_counter = temp[1];
					new_counter++;
					String l2 = new String(CryptoPrimitives.generateHmac(key1, label+new_version+new_counter), "ISO-8859-1");
					byte[] v = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16), value, sizeOfFileIdentifer);
					stash_MM_2.put(l2, v);	
					// updating the new state DX
					state_new_DX.removeAll(label);
					state_new_DX.put(label, new Integer[]{state_global_version,new_counter});
		
				}
				else{
					new_counter=1;
					new_version = state_global_version;
					String l2 = new String(CryptoPrimitives.generateHmac(key1, label+new_version+new_counter), "ISO-8859-1");
					byte[] v = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16), value, sizeOfFileIdentifer);
					stash_MM_2.put(l2, v);	
					// updating the new state DX
					state_new_DX.removeAll(label);
					state_new_DX.put(label, new Integer[]{state_global_version,new_counter});
				}	
			}
		}
		
		System.out.println("\t Insertion");
		System.out.println("Content of the search set "+state_set_search);
		System.out.println("Content of the remaining label "+state_old_DX.keySet());

		
		int counter=0;
		if ((sample == 1)  && (stash_MM_1.keySet().size()>0)){
			while ((counter<public_parameter) && (stash_MM_1.keySet().size()>0)){
				Multimap<String, byte[]> temp = emm.getNew_dictionary();
				String label = stash_MM_1.keySet().iterator().next();
				byte[] value = stash_MM_1.get(label).iterator().next();
				stash_MM_1.removeAll(label);
				temp.put(label, value);		
				emm.setNew_dictionary(temp);
				counter++;
			}
		}
		else if ((sample == 0) && (stash_MM_2.keySet().size()>0)){
			while ((counter<public_parameter) && (stash_MM_2.keySet().size()>0)){
				Multimap<String, byte[]> temp = emm.getNew_dictionary();
				String label = stash_MM_2.keySet().iterator().next();
				byte[] value = stash_MM_2.get(label).iterator().next();
				stash_MM_2.removeAll(label);
				temp.put(label, value);		
				emm.setNew_dictionary(temp);
				counter++;
			}
			
		}
		
		if ((state_old_DX.keySet().size() == 0) && (stash_MM_1.keySet().size()==0) && (stash_MM_2.keySet().size()==0)){
			state_global_version ++;
			state_old_DX = state_new_DX;
			state_new_DX = ArrayListMultimap.create(); 
			Multimap<String, byte[]> temp = emm.getNew_dictionary();
			emm.setOld_dictionary(temp);
			Multimap<String, byte[]> temp2 = ArrayListMultimap.create();
			emm.setNew_dictionary(temp2);
		}
		
		
		
	}
	
}
