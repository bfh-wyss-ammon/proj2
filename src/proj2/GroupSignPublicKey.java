package src.proj2;

import java.io.Serializable;
import java.math.BigInteger;

public class GroupSignPublicKey implements Serializable {
	
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
