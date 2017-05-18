package Project2Crypto.Project2Crypto;

import java.io.Serializable;
import java.math.BigInteger;

public class GroupSignPublicKey implements Serializable {
	
	// this is aka l(n) and l(P)
	public final static int modulus = 2048;

	public final static int lE = 504;
	public final static int lQ = 282;

	// length of c
	public final static int lc = 160;

	// length of e and s
	public final static int le = 60;

	// sets how many rounds of the miller rabin test are run
	public final static int prime_certainty = 100;
	
	
	private final BigInteger n;
	private final BigInteger a;
	private final BigInteger g;
	private final BigInteger h;
	private final BigInteger bigQ;
	private final BigInteger bigP;
	private final BigInteger bigF;
	private final BigInteger bigG;
	private final BigInteger bigH;
	private final BigInteger w;
	
	
	public GroupSignPublicKey(BigInteger n, BigInteger a, BigInteger g, BigInteger h, BigInteger bigQ, BigInteger bigP,
			BigInteger bigF, BigInteger bigG, BigInteger bigH, BigInteger w) {
		this.n = n;
		this.a = a;
		this.g = g;
		this.h = h;
		this.bigQ = bigQ;
		this.bigP = bigP;
		this.bigF = bigF;
		this.bigG = bigG;
		this.bigH = bigH;
		this.w = w;
	}
	public BigInteger n() {
		return n;
	}
	public BigInteger a() {
		return a;
	}
	public BigInteger g() {
		return g;
	}
	public BigInteger h() {
		return h;
	}
	public BigInteger bigQ() {
		return bigQ;
	}
	public BigInteger bigP() {
		return bigP;
	}
	public BigInteger bigF() {
		return bigF;
	}
	public BigInteger bigG() {
		return bigG;
	}
	public BigInteger bigH() {
		return bigH;
	}
	
	public BigInteger w(){
		return w;
	}
	
	
	

}
