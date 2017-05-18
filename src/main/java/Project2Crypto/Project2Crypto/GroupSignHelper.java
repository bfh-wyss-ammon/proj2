package Project2Crypto.Project2Crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;

public class GroupSignHelper {
	public static BigInteger GetHash(ArrayList<byte[]> values) {
		try {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		BigInteger last = new BigInteger("0");
		for (byte[] value : values){
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		
			try {
				outputStream.write(last.toByteArray());
				outputStream.write(value);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			byte toBeHashedValue[] = outputStream.toByteArray();
			md.update(toBeHashedValue, 0, toBeHashedValue.length);
			last = new BigInteger(1, md.digest());
		}
		return last;
		}
		catch(Exception ex) {
			//todo: error handling
		}
		return null;
	}
	
	public static GroupSignMemberKey joinClientResponse(GroupSignPublicKey publicKey, GroupSignJoinResponse resp, GroupSignMemberKey initKey){
		
		return new GroupSignMemberKey(publicKey,resp.wi(),initKey.x(),resp.yi(),resp.e(),resp.ri().add(initKey.r()), resp.Ei(),initKey.bigY(),initKey.commitment() );
		
	}
	
	public static BigInteger RandValModP(SecureRandom rand, int maxlength, BigInteger p) {
		BigInteger ret = new BigInteger(maxlength, rand).mod(p);
		while (ret.bitLength() != maxlength) {
			ret = new BigInteger(maxlength, rand).mod(p);
		}
		return ret;
	}
	
	public static BigInteger RandomElementOfQRn(SecureRandom rand, int modulus, BigInteger n, BigInteger p, BigInteger q) {
		BigInteger a = RandValModP(rand, modulus, n);

		while (!QuadraticResidue(a, p, q)) {
			a = RandValModP(rand, modulus, n);
		}
		return a;
	}
	
	public static GroupSignMemberKey joinClientInit(SecureRandom rand, GroupSignPublicKey publicKey){
		
		BigInteger xi = GroupSignHelper.RandValModP(rand, GroupSignPublicKey.modulus, publicKey.n());
		
		
		BigInteger bigY = publicKey.bigG().modPow(xi, publicKey.bigP());
		
		BigInteger ri = new BigInteger (GroupSignPublicKey.modulus, GroupSignPublicKey.prime_certainty, rand);
		while(!ri.gcd(publicKey.n()).equals(BigInteger.ONE)){
				ri = new BigInteger(GroupSignPublicKey.modulus, GroupSignPublicKey.prime_certainty, rand);
		}		
		BigInteger commitment = publicKey.g().modPow(xi, publicKey.n()).multiply(publicKey.h().modPow(ri, publicKey.n())).mod(publicKey.n());
				
		return new GroupSignMemberKey(publicKey, null, xi, null, null, ri, null, bigY, commitment);	
	}
	
	public static boolean QuadraticResidue(BigInteger a, BigInteger p, BigInteger q) {
		BigInteger two = BigInteger.ONE.add(BigInteger.ONE);

		BigInteger test1 = p.subtract(BigInteger.ONE).divide(two);
		BigInteger test2 = q.subtract(BigInteger.ONE).divide(two);

		return a.mod(p).modPow(test1, p).equals(BigInteger.ONE)
				&& a.mod(q).modPow(test2, q).equals(BigInteger.ONE);
	}
	
	public static byte[] ConvertToBytes(Object object) throws IOException {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutput out = new ObjectOutputStream(bos)) {
			out.writeObject(object);
			return bos.toByteArray();
		}
	}
	
	public static BigInteger totient(BigInteger n) {
		BigInteger phi = new BigInteger("1");
		BigInteger i = new BigInteger("2");
		while (i.compareTo(n) < 0) {
			if ((i.gcd(n)).equals(BigInteger.ONE))
				phi = phi.add(BigInteger.ONE);
			i = i.add(BigInteger.ONE);
		}
		return phi;
	}
	
	public static BigInteger randValModP(SecureRandom rand, int maxlength, BigInteger p) {
		BigInteger ret = new BigInteger(maxlength, rand).mod(p);
		while (ret.bitLength() != maxlength) {
			ret = new BigInteger(maxlength, rand).mod(p);
		}
		return ret;
	}

	public static BigInteger randVal(SecureRandom rand, int length) {
		BigInteger ret = new BigInteger(length, rand);
		while (ret.bitLength() != length) {
			ret = new BigInteger(length, rand);
		}
		return ret;
	}
	
	public static boolean verify(GroupSignPublicKey vk, byte[] message, GroupSignSignature sigma) {
		if (sigma.ze().bitLength() != (GroupSignPublicKey.le + GroupSignPublicKey.lc + GroupSignPublicKey.le)
				&& sigma.zx().bitLength() != (GroupSignPublicKey.lQ + GroupSignPublicKey.lc + GroupSignPublicKey.le))
			return false;

		boolean isValid = false;
		BigInteger vPart1 = vk.a().multiply(vk.w()).modPow(sigma.c().negate(), vk.n());
		BigInteger vPart2 = vk.g().modPow(sigma.zx().negate(), vk.n());
		BigInteger vPart3 = vk.h().modPow(sigma.zr(), vk.n());
		BigInteger vPart4 = sigma.c().multiply(new BigInteger("2").pow(GroupSignPublicKey.lE - 1)).add(sigma.ze());
		BigInteger vPart5 = sigma.u().modPow(vPart4, vk.n());

		BigInteger v = vPart1.multiply(vPart2).mod(vk.n()).multiply(vPart3).mod(vk.n()).multiply(vPart5).mod(vk.n());

		BigInteger bigV1 = sigma.bigU1().modPow(sigma.c().negate(), vk.bigP())
				.multiply(vk.bigF().modPow(sigma.zbigR(), vk.bigP())).mod(vk.bigP());
		BigInteger bigV2 = sigma.bigU2().modPow(sigma.c().negate(), vk.bigP())
				.multiply(vk.bigG().modPow(sigma.zbigR().add(sigma.zx()), vk.bigP())).mod(vk.bigP());
		BigInteger bigV3 = sigma.bigU3().modPow(sigma.c().negate(), vk.bigP())
				.multiply(vk.bigH().modPow(sigma.zbigR().add(sigma.ze()), vk.bigP())).mod(vk.bigP());

		
		ArrayList<byte[]> input = new ArrayList<byte[]>();
		try {
			input.add(GroupSignHelper.ConvertToBytes(vk));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		input.add(sigma.u().toByteArray());
		input.add(v.toByteArray());
		input.add(sigma.bigU1().toByteArray());
		input.add(sigma.bigU2().toByteArray());
		input.add(sigma.bigU3().toByteArray());
		input.add(bigV1.toByteArray());
		input.add(bigV2.toByteArray());
		input.add(bigV3.toByteArray());
		input.add(message);
		BigInteger c = GroupSignHelper.GetHash(input);
		isValid = c.equals(sigma.c());

		return isValid;
	}
	
	public static GroupSignSignature sign(SecureRandom rand, byte[] message, GroupSignMemberKey sk, GroupSignPublicKey vk) {
		// all the variables we need
		BigInteger r = GroupSignHelper.randVal(rand, GroupSignPublicKey.modulus / 2);
		BigInteger bigR = GroupSignHelper.randValModP(rand, GroupSignPublicKey.lQ, vk.bigQ());
		BigInteger u = vk.h().modPow(r, vk.n()).multiply(sk.y()).mod(vk.n()).multiply(sk.w()).mod(vk.n());
		
		
		
		BigInteger bigU1 = sk.vk().bigF().modPow(bigR, vk.bigP());
		BigInteger bigU2 = sk.vk().bigG().modPow(bigR.add(sk.x()), vk.bigP());
		BigInteger bigU3 = sk.vk().bigH().modPow(bigR.add(sk.e()), vk.bigP());



		BigInteger rx = GroupSignHelper.randVal(rand, GroupSignPublicKey.lQ + GroupSignPublicKey.lc + GroupSignPublicKey.le);
		BigInteger rr = GroupSignHelper.randVal(rand, GroupSignPublicKey.modulus / 2 + GroupSignPublicKey.lc + GroupSignPublicKey.le);
		BigInteger re = GroupSignHelper.randVal(rand, GroupSignPublicKey.le + GroupSignPublicKey.lc + GroupSignPublicKey.le);
		BigInteger bigRr = GroupSignHelper.randValModP(rand, GroupSignPublicKey.lQ, vk.bigQ());

		BigInteger v = u.modPow(re, vk.n()).multiply(vk.g().modPow(rx.negate(), vk.n()))
				.multiply(vk.h().modPow(rr, vk.n())).mod(vk.n());
		BigInteger bigV1 = vk.bigF().modPow(bigRr, vk.bigP());
		BigInteger bigV2 = vk.bigG().modPow(bigRr.add(rx), vk.bigP());
		BigInteger bigV3 = vk.bigH().modPow(bigRr.add(re), vk.bigP());

		// generate hashing challenge
		ArrayList<byte[]> input = new ArrayList<byte[]>();
		try {
			input.add(GroupSignHelper.ConvertToBytes(vk));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		input.add(u.toByteArray());
		input.add(v.toByteArray());
		input.add(bigU1.toByteArray());
		input.add(bigU2.toByteArray());
		input.add(bigU3.toByteArray());
		input.add(bigV1.toByteArray());
		input.add(bigV2.toByteArray());
		input.add(bigV3.toByteArray());
		input.add(message);
		BigInteger c = GroupSignHelper.GetHash(input);		
		BigInteger zx = rx.add(c.multiply(sk.x()));

		BigInteger res = sk.r().negate().subtract(r.multiply(sk.bigE()));
		BigInteger zr = rr.add(c.multiply(res));

		res = c.multiply(sk.e());
		BigInteger ze = re.add(res);

		BigInteger zbigR = bigRr.add(c.multiply(bigR).mod(vk.bigQ()));

		// return the new signature
		return new GroupSignSignature(u, bigU1, bigU2, bigU3, zx, zr, ze, zbigR, c, message);

	}
}
