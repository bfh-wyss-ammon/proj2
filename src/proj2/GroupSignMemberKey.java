package src.proj2;

import java.math.BigInteger;

public class GroupSignMemberKey {
	
	private final GroupSignPublicKey vk;
	private final BigInteger x;
	private final BigInteger y;
	private final BigInteger e;
	private final BigInteger r;
	
	
	
	
	public GroupSignMemberKey(GroupSignPublicKey vk, BigInteger x, BigInteger y, BigInteger e, BigInteger r) {
		this.vk = vk;
		this.x = x;
		this.y = y;
		this.e = e;
		this.r = r;
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
