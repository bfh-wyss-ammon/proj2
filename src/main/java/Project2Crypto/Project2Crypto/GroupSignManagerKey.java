package Project2Crypto.Project2Crypto;

import java.math.BigInteger;
import java.util.ArrayList;

public class GroupSignManagerKey  {
	
	private final GroupSignPublicKey vk;
	private final BigInteger Xg;
	private final ArrayList<BigInteger> bigY;
	private final BigInteger p;
	private final BigInteger q;
	
	
	public GroupSignManagerKey(GroupSignPublicKey vk, BigInteger xg, BigInteger p, BigInteger q) {
	
		this.p=p;
		this.q=q;
		this.vk = vk;
		this.Xg = xg;
		this.bigY = new ArrayList<BigInteger>();
	}
	
	public BigInteger p(){
		return p;
	}
	
	public BigInteger q(){
		return q;
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
