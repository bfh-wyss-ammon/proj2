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
		private BigInteger generator;
		private BigInteger a;
		private BigInteger g;
		private BigInteger h;

		// the random generator used for cryptographic operations
		private SecureRandom rand;

		// the private key
		private BigInteger lambda;
		private BigInteger p;
		private BigInteger q;
		
		
		private BigInteger bigQ;
		private BigInteger bigP;
	
	
	public GroupSign(){
		rand = new SecureRandom();
		keyGen();
		
	}
	
	private void keyGen(){
		this.generator=new BigInteger("2");
	    BigInteger p = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);
	    BigInteger q = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);
	    this.n = p.multiply(q);
	    this.nsquared = n.multiply(n);
	    
	    this.a = randomElementOfQRn();
	    this.g = randomElementOfQRn();
	    this.h = randomElementOfQRn();
	    
		//this.bigQ = this.p.subtract(BigInteger.ONE).multiply(this.q.subtract(BigInteger.ONE)).divide(this.p.subtract(BigInteger.ONE).gcd(this.q.subtract(BigInteger.ONE)));

 
	}
	
	private BigInteger randomElementOfQRn(){
		
		BigInteger a = new BigInteger(modulus,this.prime_certainty,rand);
		BigInteger check = this.generator.modPow(a, this.nsquared).subtract(BigInteger.ONE).divide(this.n);
		while(!relPrime(check,n)){
			a = new BigInteger(modulus,this.prime_certainty,rand);
			check = this.generator.modPow(a, this.nsquared).subtract(BigInteger.ONE).divide(this.n);
			
		}
		return a;
	}
	
	
	private boolean relPrime(BigInteger a, BigInteger b){
	
		return a.gcd(b).intValue()==1;
		
	}
	

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		GroupSign grpS = new GroupSign();
	}

}
