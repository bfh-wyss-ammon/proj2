package src.proj2;

import java.math.*;
import java.security.*;


public class GroupSign {
	
	
	// sets the size of the key material
	public final int modulus = 2048;

	// sets how many rounds of the miller rabin test are run
	public final int prime_certainty = 256;
	
	
	// the public key and the generator (is equal to n+1)
		private BigInteger n;
		private BigInteger nsquared;
		private BigInteger g;

		// the random generator used for cryptographic operations
		private SecureRandom rand;

		// the private key
		private BigInteger lambda;
		private BigInteger p;
		private BigInteger q;
	
	
	public GroupSign(){
		rand = new SecureRandom();
		
	}
	
	private void keyGen(){
	    BigInteger p = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);
	    BigInteger q = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);
	}
	
	

	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
