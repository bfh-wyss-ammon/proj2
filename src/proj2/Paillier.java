package proj2;

import java.math.*;
import java.security.SecureRandom;

/**
 * @author gabe 
 * this class implements the homomorphic crypto scheme
 */
public class Paillier {
	// sets the size of the key material
	public final int modulus = 2048;
	
	// sets how many rounds of the miller rabin test are run
	public final int prime_certainty = 256;


	
	//the public key and the generator (is equal to n+1)
	private BigInteger n;
	private BigInteger nsquared;
	private BigInteger g;

	
	//the random generator used for cryptographic operations
	private SecureRandom rand;
	
	//the private key
	private BigInteger lambda;
	private BigInteger p;
	private BigInteger q;

	/**
	 * create a new instance of this cryptosystem with new keys
	 */
	public Paillier() {
		 rand= new SecureRandom();
		try {
			keyGen();
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("There was an error in keygen");
		}

	}

	/**
	 * @param n the public key
	 * @param p part of the private key
	 * @param q part of the private key
	 * @param lambda part of the private key
	 * create a new instance of this cryptosystem with known keys
	 */
	public Paillier(BigInteger n, BigInteger p, BigInteger q, BigInteger lambda) {
		 rand= new SecureRandom();
		 this.n = n;
		 this.g = n.add(BigInteger.ONE);
		 this.nsquared = this.n.multiply(this.n);
		 this.p =p;
		 this.q =q;
		 this.lambda = lambda;
	}
	public void keyGen() throws Exception {
		
		//find the public key
		p = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);
		q = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);
		this.n = this.p.multiply(this.q);
		this.nsquared = this.n.multiply(this.n);
		this.g= this.n.add(BigInteger.ONE);
		
		//find and check the secret key
		this.lambda = this.p.subtract(BigInteger.ONE).multiply(this.q.subtract(BigInteger.ONE))
				.divide(this.p.subtract(BigInteger.ONE).gcd(this.q.subtract(BigInteger.ONE)));
		if (this.g.modPow(this.lambda, this.nsquared).subtract(BigInteger.ONE).divide(this.n).gcd(this.n).intValue() != 1) {
			throw new Exception();
		}
	}

	/**
	 * @param m takes BigInt m as message
	 * @return returns the encrypted ciphertext of m
	 */
	public BigInteger encryption(BigInteger m) {
		if(this.nsquared != null){
			BigInteger r = new BigInteger(this.modulus, this.rand);
			return this.g.modPow(m, this.nsquared).multiply(r.modPow(this.n, this.nsquared)).mod(this.nsquared);
		}else{
			return null;
		}
		

	}

	/**
	 * @param c takes BigInt c as ciphertext
	 * @return returns the decrypted cleartext of c
	 */
	public BigInteger decryption(BigInteger c) {
		if(this.n != null && this.lambda !=null && this.nsquared != null && this.g != null){
			BigInteger u = this.g.modPow(this.lambda, this.nsquared).subtract(BigInteger.ONE).divide(this.n).modInverse(this.n);
			return c.modPow(this.lambda, this.nsquared).subtract(BigInteger.ONE).divide(this.n).multiply(u).mod(this.n);
		}else{
			return null;
		}

	}
	
	/**
	 * @param c1 ciphertext to be added
	 * @param c2 ciphertext to be added 
	 * @param n the public key
	 * @return the encrypted result of the addition
	 */
	 public BigInteger homomorphicAdd(BigInteger c1, BigInteger c2){
		return c1.multiply(c2).mod(this.nsquared);
	}

	public static void main(String[] str) {
		Paillier paillier = new Paillier();
		BigInteger m1 = new BigInteger("200");
		BigInteger m2 = new BigInteger("60");

		long time = System.currentTimeMillis();
		BigInteger c1 = paillier.encryption(m1);
		BigInteger c2 = paillier.encryption(m2);
		System.out.println("Time to encrypt two numbers in ms: " + (System.currentTimeMillis()-time)   );


		System.out.println("Ciphertext c1: " + c1.intValue());
		System.out.println("Ciphertext c2: " + c2.intValue());

		time = System.currentTimeMillis();
		BigInteger dec1 =paillier.decryption(c1);
		BigInteger dec2 =paillier.decryption(c2);
		System.out.println("Time to decrypt two numbers in ms: " + (System.currentTimeMillis()-time)   );
		
		
		System.out.println("Decrypted c1: " + dec1.intValue());
		System.out.println("Decrypted c2: " + dec2.intValue());

		
		
		System.out.println("original sum: " + m1.add(m2).intValue());
		
		time = System.currentTimeMillis();
		BigInteger res =paillier.homomorphicAdd(c1,c2);
		System.out.println("Time to homo-add two numbers in ms: " + (System.currentTimeMillis()-time)   );

		
		System.out.println("decrypted sum: " + paillier.decryption(res).intValue() );

	}
}