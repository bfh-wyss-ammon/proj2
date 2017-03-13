package src.proj2;

import java.math.*;
import java.security.*;
import java.util.ArrayList;


public class GroupSign {
	
	
	// sets the size of the key material
	public final int modulus = 1024;

	// sets how many rounds of the miller rabin test are run
	public final int prime_certainty = 50;
	
	
	public final int number_of_groupmembers = 100;
	
	
	//store the key once they are generated
	private GroupSignPublicKey vk;
	private GroupSignManagerKey gsmk;
	private GroupSignMemberKey[] sk;
	
	
	// the group public key and the generator (is equal to n+1)
		private BigInteger n;
		private BigInteger nsquared;
		private BigInteger generator;
		private BigInteger a;
		private BigInteger g;
		private BigInteger h;
		private BigInteger bigQ;
		private BigInteger bigP;
		private BigInteger bigF;
		private BigInteger bigG;
		private BigInteger bigH;

		// the random generator used for cryptographic operations
		private SecureRandom rand;
		private MessageDigest md;
		
		
		//the group members private key
		private BigInteger[] x = new BigInteger[number_of_groupmembers];
		private BigInteger[] r = new BigInteger[number_of_groupmembers];
		private ArrayList<BigInteger> e = new ArrayList<BigInteger>();
		private BigInteger[] y = new BigInteger[number_of_groupmembers];
		private BigInteger[] bigE = new BigInteger[number_of_groupmembers];
		
		
		//the group manager private key
		private BigInteger Xg;
		private BigInteger Xh;
		private BigInteger[] bigY = new BigInteger[number_of_groupmembers];

		
		// the private key
		private BigInteger lambda;
		private BigInteger p;
		private BigInteger q;
		
		

	
	
	public GroupSign(){
		rand = new SecureRandom();
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		keyGen();
		
	}
	
	private void keyGen(){
		this.generator=new BigInteger("2");
	    BigInteger p = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);
	    BigInteger q = new BigInteger(this.modulus / 2, this.prime_certainty, this.rand);
	    this.n = p.multiply(q);
	    this.nsquared = n.multiply(n);
	    
	    this.a = randomElementOfQRn();
	    this.g = randomElementOfQRn();
	    this.h = randomElementOfQRn();
	    
	    this.bigQ = new BigInteger(this.modulus-1,this.prime_certainty,this.rand);
	    this.bigP = this.bigQ.multiply(new BigInteger("2")).add(BigInteger.ONE);
	    
	    this.bigF = bigP.subtract(BigInteger.ONE).modPow((bigP.subtract(BigInteger.ONE)).divide(bigQ), bigP);
	    
	    this.Xg = new BigInteger(this.modulus-1,this.rand);
	    this.Xh = new BigInteger(this.modulus-1,this.rand);
	    
	    this.bigG = bigF.modPow(Xg, this.bigP);
	    this.bigH = bigF.modPow(Xh, this.bigP);
	    
	    
	    for(int i=0;i<this.number_of_groupmembers;i++){
	    	this.x[i] = new BigInteger(this.modulus-1,this.rand);
	    	this.r[i] = new BigInteger(this.modulus, this.rand);
	    	
	    }
	    
	    BigInteger two = new BigInteger("2");
	    while(this.e.size() < this.number_of_groupmembers){
		    BigInteger bigE = new BigInteger(this.modulus,this.prime_certainty,this.rand);
		    
		    BigInteger el = bigE.subtract(two.pow(bigE.bitCount()));
		    if(!this.e.contains(el)) {
		    	this.e.add(el);
		    	//System.out.println(el.toString(16));
		    	//System.out.println("" + el.bitLength());
		    	this.bigE[this.e.size()-1]=bigE;
		    }
	    }
	    
	    
	    //y[i] is the one we are looking for
	    //there must be a faster way to do this... (current brute force)
	    //y[i]=res[i]^E[i] mod n 
	    for(int i = 0; i<number_of_groupmembers;i++){
	    	BigInteger res = this.a.multiply(g.modPow(x[i],this.n)).multiply(h.modPow(r[i], this.n)).mod(this.n);

	    	this.y[i] = new BigInteger(this.modulus,this.rand);
	    	if(   !y[i].modPow(bigE[i], this.n).equals(res)   ){
	    		this.y[i] = new BigInteger(this.modulus,this.prime_certainty,this.rand);
	    	}
	    }
	    
	    for(int i = 0; i<number_of_groupmembers;i++){
	    	this.bigY[i]=bigG.modPow(this.x[i], this.bigP);
	    }
	    
	    
	    
	    //now that we have all the variables, we can construct the key objects
	    this.vk = new GroupSignPublicKey(this.n, this.a, this.g, this.h, this.bigQ, this.bigP, this.bigF, this.bigG, this.bigH);
	    this.gsmk = new GroupSignManagerKey(this.vk, this.Xg, this.bigY);
	    for(int i = 0; i<number_of_groupmembers;i++){
	    	this.sk[i]= new GroupSignMemberKey(this.vk, this.x[i], this.y[i], this.e.get(i), this.r[i]);
	    }
	    
	    
	}
	
	private GroupSignSignature sign(byte[] message, GroupSignMemberKey sk){
		
		//hashing
		md.update(message,0, message.length);
		BigInteger c = new BigInteger(1,md.digest());
		
		//all the variables we need
		BigInteger r = new BigInteger(this.modulus/2,rand);
		BigInteger bigR = new BigInteger(this.modulus-1,this.rand);
		BigInteger u = sk.vk().h().modPow(r, sk.vk().n());
		BigInteger bigU1 = sk.vk().bigF().modPow(bigR, sk.vk().bigP());
		BigInteger bigU2 = sk.vk().bigG().modPow(bigR.add(sk.x()), sk.vk().bigP());
		BigInteger bigU3 = sk.vk().bigH().modPow(bigR.add(sk.e()), sk.vk().bigP());
		
		//lS is unknown what could it be?
		Integer lS = 1;
		BigInteger rx = new BigInteger(this.modulus-1 + 256 + lS ,this.rand);
		BigInteger rr = new BigInteger(this.modulus/2 + 256 + lS, this.rand);
		BigInteger re = new BigInteger(sk.e().bitLength() + 256 + lS,this.rand);
		BigInteger bigRr = new BigInteger(this.modulus-1,this.rand);
		BigInteger v = u.modPow(re, sk.vk().n()).multiply(sk.vk().g().modPow(rx.negate(),sk.vk().n())).multiply(sk.vk().h().modPow(rr, sk.vk().n())).mod(sk.vk().n());
		BigInteger bigV1;
		BigInteger bigV2;
		BigInteger bigV3;
		BigInteger zx;
		BigInteger zr;
		BigInteger ze;
		BigInteger zbigR;


		
		
		
		
		
		
		//return the new signature
		return new GroupSignSignature(u,bigU1,bigU2,bigU3, zx,zr,ze,zbigR, c, message);
		
		
	}
	
	private BigInteger randomElementOfQRn(){
		
		BigInteger a = new BigInteger(modulus,this.prime_certainty,rand);
		BigInteger check = this.generator.modPow(a, this.nsquared).subtract(BigInteger.ONE).divide(this.n);
		while(!relPrime(check,n)){
			a = new BigInteger(modulus,this.prime_certainty,rand);
			check = this.generator.modPow(a, this.nsquared).subtract(BigInteger.ONE).divide(this.n);
			
		}
		return a;
	}
	
	
	private boolean relPrime(BigInteger a, BigInteger b){
	
		return a.gcd(b).intValue()==1;
		
	}
	

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		GroupSign grpS = new GroupSign();
	}

}
