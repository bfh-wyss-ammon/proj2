package src.proj2;

import java.math.BigInteger;

public class GroupSignSignature {
	
	private final BigInteger u;
	private final BigInteger bigU1;
	private final BigInteger bigU2;
	private final BigInteger bigU3;
	private final BigInteger zx;
	private final BigInteger zr;
	private final BigInteger ze;
	private final BigInteger zbigR;
	private final String c;
	private final BigInteger m;
	



	public GroupSignSignature(BigInteger u, BigInteger bigU1, BigInteger bigU2, BigInteger bigU3, BigInteger zx, BigInteger zr,
			BigInteger ze, BigInteger zbigR, String c, BigInteger m) {
		this.u = u;
		this.bigU1 = bigU1;
		this.bigU2 = bigU2;
		this.bigU3 = bigU3;
		this.zx = zx;
		this.zr = zr;
		this.ze = ze;
		this.zbigR = zbigR;
		this.c = c;
		this.m = m;
	}
	
	public BigInteger u(){
		return u;
	}
	public BigInteger bigU1(){
		return bigU1;
	}
	public BigInteger bigU2(){
		return bigU2;
	}
	public BigInteger bigU3(){
		return bigU3;
	}
	public BigInteger zx(){
		return zx;
	}
	public BigInteger zr(){
		return zr;
	}
	public BigInteger ze(){
		return ze;
	}

	public BigInteger zbigR(){
		return zbigR;
	}
	public String c(){
		return c;
	}
	public BigInteger m(){
		return m;
	}
	
	

}
