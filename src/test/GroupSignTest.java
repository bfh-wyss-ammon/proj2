package src.test;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import src.proj2.GroupSign;
import src.proj2.GroupSignManagerKey;
import src.proj2.GroupSignMemberKey;
import src.proj2.GroupSignPublicKey;
import src.proj2.GroupSignSignature;

public class GroupSignTest {
	
	private GroupSign mGroupSign;
	GroupSignMemberKey mPrivateKey1;
	GroupSignMemberKey mPrivateKey2; 
	GroupSignPublicKey mPublicKey;
	GroupSignManagerKey mManagerKey;
	
	
	@Before
	public void setup() {
		mGroupSign = new GroupSign();
		mPrivateKey1 = mGroupSign.sk(0);
		mPrivateKey2 = mGroupSign.sk(1);
		mManagerKey = mGroupSign.gsmk();
		mPublicKey = mGroupSign.vk();
	
	}
	
	@Test
	public void MessageValidationTest() {
		byte[] testmessage = new BigInteger("1990").toByteArray();
		
		GroupSignSignature sigma_testmessage = mGroupSign.sign(testmessage, mPrivateKey1);
		
		assertEquals(true, mGroupSign.verify(mPublicKey, testmessage, sigma_testmessage));
		
	}
	
	@Test
	public void OpenGroupAndMember() {
		byte[] testmessage = new BigInteger("1990").toByteArray();		
		GroupSignSignature sigma_testmessage = mGroupSign.sign(testmessage, mPrivateKey2);
				
		assertEquals(1, mGroupSign.open(mPublicKey, mManagerKey, testmessage, sigma_testmessage));
	}
	

}
