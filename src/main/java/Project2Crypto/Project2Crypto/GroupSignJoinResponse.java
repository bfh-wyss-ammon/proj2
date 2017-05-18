package Project2Crypto.Project2Crypto;

import java.math.BigInteger;

public class GroupSignJoinResponse {
	
	private final BigInteger wi;
	private final BigInteger yi;
	private final BigInteger Ei;
	private final BigInteger ri;
	private final BigInteger e;
	
	
	public GroupSignJoinResponse(BigInteger wi, BigInteger yi, BigInteger Ei, BigInteger ri, BigInteger e){
		this.wi = wi;
		this.yi = yi;
		this.Ei = Ei;
		this.ri = ri;
		this.e = e;
		
	}
	
	public BigInteger e(){
		return e;
	}
	
	public BigInteger wi(){
		return wi;
	}
	
	public BigInteger yi(){
		return yi;
	}
	
	public BigInteger Ei(){
		return Ei;
	}
	
	public BigInteger ri()
	{
		return ri;
	}
	
	

}
