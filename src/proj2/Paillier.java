package proj2;

import java.math.*;
import java.security.SecureRandom;

/**
 * @author gabe this class implements the homomorphic crypto scheme
 */
public class Paillier {
	// sets the size of the key material
	public final int modulus = 2048;
	// sets how many rounds of the miller rabin test are run
	public final int prime_certainty = 256;

	
	//the generator
	private BigInteger g;
	
	private BigInteger p;
	private BigInteger q;
	
	//the random generator used for cryptographic operations
	private SecureRandom rand;
	
	private BigInteger lambda;
	public BigInteger n;
	public BigInteger nsquared;

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
		p = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);
		q = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);

		this.n = this.p.multiply(this.q);
		this.nsquared = this.n.multiply(this.n);

		this.g = new BigInteger("2");
		lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
				.divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));

		if (g.modPow(lambda, nsquared).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
			throw new Exception();
		}
	}

	public BigInteger Encryption(BigInteger m, BigInteger r) {
		System.out.println("g pot: " + g.modPow(m, nsquared));
		System.out.println("r pot: " + r.modPow(n, nsquared));

		return g.modPow(m, nsquared).multiply(r.modPow(n, nsquared)).mod(nsquared);
	}

	public BigInteger Encryption(BigInteger m) {
		BigInteger r = new BigInteger(modulus, rand);
		return g.modPow(m, nsquared).multiply(r.modPow(n, nsquared)).mod(nsquared);

	}

	public BigInteger Decryption(BigInteger c) {
		BigInteger u = g.modPow(lambda, nsquared).subtract(BigInteger.ONE).divide(n).modInverse(n);
		return c.modPow(lambda, nsquared).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
	}

	public static void main(String[] str) {
		Paillier paillier = new Paillier();
		BigInteger m1 = new BigInteger("20000000");
		BigInteger m2 = new BigInteger("60");

		BigInteger c1 = paillier.Encryption(m1);
		BigInteger c2 = paillier.Encryption(m2);

		System.out.println("Ciphertext c1: " + c1.intValue());
		System.out.println("Ciphertext c2: " + c2.intValue());

		System.out.println("Decrypted c1: " + paillier.Decryption(c1).intValue());
		System.out.println("Decrypted c2: " + paillier.Decryption(c2).intValue());

		BigInteger product_em1em2 = c1.multiply(c2).mod(paillier.nsquared);
		BigInteger sum_m1m2 = m1.add(m2).mod(paillier.n);
		System.out.println("original sum: " + sum_m1m2.toString());
		System.out.println("decrypted sum: " + paillier.Decryption(product_em1em2).toString());

	}
}