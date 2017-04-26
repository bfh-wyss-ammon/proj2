package src.proj2;

import java.math.BigInteger;

public class GroupSignMemberKey {
	
	private final GroupSignPublicKey vk;
	private final BigInteger x;
	private final BigInteger w;
	private final BigInteger y;
	private final BigInteger e;
	private final BigInteger r;
	private final BigInteger bigE;
	private final BigInteger bigY;
	private final BigInteger commitment;
	
	
	
	
	public GroupSignMemberKey(GroupSignPublicKey vk, BigInteger w, BigInteger x, BigInteger y, BigInteger e, BigInteger r, BigInteger bigE, BigInteger bigY, BigInteger commitment) {
		this.vk = vk;
		this.w = w; 
		this.x = x;
		this.y = y;
		this.e = e;
		this.r = r;
		this.bigE = bigE;
		this.bigY =bigY;
		this.commitment = commitment;
	}
	
	public BigInteger bigY(){
		return bigY;
	}
	
	public BigInteger commitment(){
		return commitment;
	}
	
	public BigInteger bigE(){
		return bigE;
	}
	public GroupSignPublicKey vk() {
		return vk;
	}
	public BigInteger x() {
		return x;
	}
	public BigInteger y() {
		return y;
	}
	public BigInteger e() {
		return e;
	}
	public BigInteger r() {
		return r;
	}
	
	
	

}
