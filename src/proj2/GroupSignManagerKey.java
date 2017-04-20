package src.proj2;

import java.math.BigInteger;
import java.util.ArrayList;

public class GroupSignManagerKey {
	
	private final GroupSignPublicKey vk;
	private final BigInteger Xg;
	private final ArrayList<BigInteger> bigY;
	
	
	public GroupSignManagerKey(GroupSignPublicKey vk, BigInteger xg) {
	
		this.vk = vk;
		this.Xg = xg;
		this.bigY = new ArrayList<BigInteger>();
	}
	public GroupSignPublicKey vk() {
		return vk;
	}
	public BigInteger Xg() {
		return Xg;
	}
	public ArrayList<BigInteger> bigY() {
		return bigY;
	}
	
	public void join(BigInteger bigY){
		this.bigY.add(bigY);
	}
	
	

}
