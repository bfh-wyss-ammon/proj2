package test;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;
import proj2.*;

public class PaillierTest {
	
	@Test
	public void EqualTest() {
		BigInteger i = BigInteger.valueOf(5);
		
		Paillier pailler = new Paillier();
		BigInteger encodedValue = pailler.encryption(i);
		BigInteger decodedValue = pailler.decryption(encodedValue);
		
		System.out.println("check value: " + i);
		System.out.println("encoded value: " + encodedValue);
		System.out.println("decoded value: " + decodedValue);
		
		assertEquals(i, decodedValue);
	}

}
