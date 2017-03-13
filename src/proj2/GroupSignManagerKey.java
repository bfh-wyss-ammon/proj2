package src.proj2;

import java.math.BigInteger;

public class GroupSignManagerKey {
	
	private final GroupSignPublicKey vk;
	private final BigInteger Xg;
	private final BigInteger[] bigY;
	
	
	
	public GroupSignManagerKey(GroupSignPublicKey vk, BigInteger xg, BigInteger[] bigY) {
	
		this.vk = vk;
		Xg = xg;
		this.bigY = bigY;
	}
	public GroupSignPublicKey vk() {
		return vk;
	}
	public BigInteger Xg() {
		return Xg;
	}
	public BigInteger[] bigY() {
		return bigY;
	}
	
	

}
