package Project2Crypto.Project2Crypto;

import java.math.BigInteger;

public class GroupSignJoinRequest {
	
	private final BigInteger bigY;
	private final BigInteger commitment;
	
	
	public GroupSignJoinRequest(BigInteger bigY, BigInteger commitment){
		this.bigY = bigY;
		this.commitment = commitment;
		
	}
	
	public BigInteger bigY(){
		return bigY;
	}
	
	public BigInteger commitment(){
		return commitment;
	}
	
	
	

}
