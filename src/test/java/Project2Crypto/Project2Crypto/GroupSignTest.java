package Project2Crypto.Project2Crypto;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Timestamp;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

public class GroupSignTest {
	
	private GroupSignPublicKey vk;
	private GroupSign authoritySign;
	private SecureRandom rand;
	
	@Before
	public void setup() {
		authoritySign = new GroupSign(true); 
		vk = authoritySign.vk();
		this.rand = new SecureRandom();
	}
	
	@Test
	public void MemberJoin() {
		GroupSignMemberKey sk = GroupSignHelper.joinClientInit(rand, vk);
		// client -> sendet bigY und commitment zum nachweis des berechneten privaten schlüssels
		GroupSignJoinRequest req = new GroupSignJoinRequest(sk.bigY(),sk.commitment());
		GroupSignJoinResponse resp = authoritySign.joinToGroupServer(req);
		sk = GroupSignHelper.joinClientResponse(vk, resp, sk);
		assertNotNull(sk);
		
		byte[] testmessage = new BigInteger("1990").toByteArray();
		GroupSignSignature sigma_testmessage = GroupSignHelper.sign(rand, testmessage, sk, vk);

		// gute nachricht | signier
		assertTrue(GroupSignHelper.verify(vk, testmessage, sigma_testmessage));
		
		// fake news
		assertFalse(GroupSignHelper.verify(vk, new BigInteger("1995").toByteArray(), sigma_testmessage));
	}
	
	@Test
	public void MultiMemberJoin() {
		
		int mCount = 9;
		
		GroupSignMemberKey[] sks = new GroupSignMemberKey[mCount];
		for(int i = 0; i < mCount; i++) {
			sks[i] = GroupSignHelper.joinClientInit(rand, vk);
			// client -> sendet bigY und commitment zum nachweis des berechneten privaten schlüssels
			GroupSignJoinRequest req = new GroupSignJoinRequest(sks[i].bigY(),sks[i].commitment());
			GroupSignJoinResponse resp = authoritySign.joinToGroupServer(req);
			sks[i] = GroupSignHelper.joinClientResponse(vk, resp, sks[i]);
		}
		byte[] testmessage = new BigInteger("1990").toByteArray();
		
		GroupSignSignature[] gss = new GroupSignSignature[mCount];
		for(int i = 0; i < mCount; i++) {			
			gss[i] = GroupSignHelper.sign(rand, testmessage, sks[i], vk);
		}
		
		for(int i = 0; i < mCount; i++) {
			int pId = authoritySign.open(vk, authoritySign.gsmk(), testmessage, gss[i]);
			System.out.print("=>"+i+":" + pId);
			assertEquals(pId, i);
		}
		
	}
	
	@Test
	public void SignALot() {
		System.out.println("speeed");
		GroupSignMemberKey sk = GroupSignHelper.joinClientInit(rand, vk);
		// client -> sendet bigY und commitment zum nachweis des berechneten privaten schlüssels
		GroupSignJoinRequest req = new GroupSignJoinRequest(sk.bigY(),sk.commitment());
		GroupSignJoinResponse resp = authoritySign.joinToGroupServer(req);
		sk = GroupSignHelper.joinClientResponse(vk, resp, sk);
		assertNotNull(sk);
		
		byte[] testmessage = new BigInteger("1990").toByteArray();
		GroupSignSignature[] gss = new GroupSignSignature[100];
		
		long startTime = System.currentTimeMillis();	      
		for(int i = 0; i < 100; i++) {
			gss[i] = GroupSignHelper.sign(rand, testmessage, sk, vk);
		}
		 long stopTime = System.currentTimeMillis();
	     float elapsedTime = (stopTime - startTime);
	     System.out.print("time for 100 sign is:");
	     System.out.println(elapsedTime);
	     System.out.println(elapsedTime / 1000);
	     
	     startTime = System.currentTimeMillis();	
		for(int i = 0; i < 100; i++) {
			assertTrue(GroupSignHelper.verify(vk, testmessage, gss[i]));
		}
		stopTime = System.currentTimeMillis();
	     elapsedTime = (stopTime - startTime);
	     System.out.print("time for 100 vaild is:");
	     System.out.println(elapsedTime);
	     System.out.println(elapsedTime / 1000);
		
		
	}
	

}
