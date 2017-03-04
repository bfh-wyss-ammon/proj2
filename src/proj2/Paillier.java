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

	
	//the generator (is equal to n+1)
	private BigInteger g;
	
	//the public key
	private BigInteger n;
	private BigInteger nsquared;
	private BigInteger p;
	private BigInteger q;
	
	//the random generator used for cryptographic operations
	private SecureRandom rand;
	
	//the private key
	private BigInteger lambda;

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
		BigInteger r = new BigInteger(this.modulus, this.rand);
		return this.g.modPow(m, this.nsquared).multiply(r.modPow(this.n, this.nsquared)).mod(this.nsquared);

	}

	/**
	 * @param c takes BigInt c as ciphertext
	 * @return returns the decrypted cleartext of c
	 */
	public BigInteger decryption(BigInteger c) {
		BigInteger u = g.modPow(lambda, nsquared).subtract(BigInteger.ONE).divide(n).modInverse(n);
		return c.modPow(lambda, nsquared).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
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

		BigInteger c1 = paillier.encryption(m1);
		BigInteger c2 = paillier.encryption(m2);

		System.out.println("Ciphertext c1: " + c1.intValue());
		System.out.println("Ciphertext c2: " + c2.intValue());

		System.out.println("Decrypted c1: " + paillier.decryption(c1).intValue());
		System.out.println("Decrypted c2: " + paillier.decryption(c2).intValue());

		System.out.println("original sum: " + m1.add(m2).intValue());
		System.out.println("decrypted sum: " + paillier.decryption(paillier.homomorphicAdd(c1,c2)).intValue());

	}
}