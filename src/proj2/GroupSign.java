package src.proj2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.*;
import java.security.*;
import java.util.ArrayList;

public class GroupSign {

	// sets the size of the key material

	// this is aka l(n) and l(P)
	public final int modulus = 2048;

	public final int lE = 504;
	public final int lQ = 282;

	// length of c
	public final int lc = 160;

	// length of e and s
	public final int le = 60;

	// sets how many rounds of the miller rabin test are run
	public final int prime_certainty = 100;

	//public final int number_of_groupmembers = 2;

	// store the key once they are generated
	private GroupSignPublicKey vk;
	private GroupSignManagerKey gsmk;
	private ArrayList<GroupSignMemberKey> skList = new ArrayList<GroupSignMemberKey>();

	// the group public key and the generator (is equal to n+1)
	private BigInteger p;
	private BigInteger q;
	private BigInteger n;
	private BigInteger nsquared;
	private BigInteger generator;
	private BigInteger a;
	private BigInteger g;
	private BigInteger h;
	private BigInteger w;
	private BigInteger bigQ;
	private BigInteger bigP;
	private BigInteger bigF;
	private BigInteger bigG;
	private BigInteger bigH;

	// the random generator used for cryptographic operations
	private SecureRandom rand;
	private MessageDigest md;

	// the group members private key
	//private BigInteger[] x = new BigInteger[number_of_groupmembers];
	//private BigInteger[] r = new BigInteger[number_of_groupmembers];
	//private ArrayList<BigInteger> e = new ArrayList<BigInteger>();
	//private BigInteger[] y = new BigInteger[number_of_groupmembers];
	//private BigInteger[] bigE = new BigInteger[number_of_groupmembers];

	// the group manager private key
	private BigInteger Xg;
	private BigInteger Xh;
	//private BigInteger[] bigY = new BigInteger[number_of_groupmembers];

	public GroupSign() {
		rand = new SecureRandom();
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		while (true) {
			if (keyGen())
				break;
		}

	}

	private boolean keyGen() {
		this.generator = new BigInteger("2");
		this.p = (new BigInteger((this.modulus / 2), this.prime_certainty, this.rand));
		this.q = (new BigInteger((this.modulus / 2), this.prime_certainty, this.rand));
		this.n = p.multiply(q);
		this.nsquared = n.multiply(n);

		// some easy checks
		if (this.n.bitLength() != this.modulus || !this.p.isProbablePrime(prime_certainty)
				|| !this.q.isProbablePrime(prime_certainty))
			return false;

		BigInteger alpha = new BigInteger(this.modulus, this.rand);
		this.a = randomElementOfQRn();
		this.h = randomElementOfQRn();
		this.g = h.modPow(alpha, this.n);
		this.w = randomElementOfQRn();


		this.bigQ = new BigInteger(this.lQ, this.prime_certainty, this.rand);
		BigInteger multiplicator = new BigInteger("2").pow(this.modulus - this.lQ);
		this.bigP = bigQ.multiply(multiplicator).add(BigInteger.ONE);

		while (true) {
			if (bigP.bitLength() != this.modulus)
				return false;
			if (bigP.bitLength() == this.modulus) {
				if (bigP.isProbablePrime(1) && bigP.isProbablePrime(this.prime_certainty))
					break;
			}
			multiplicator = multiplicator.add(BigInteger.ONE);
			this.bigP = bigQ.multiply(multiplicator).add(BigInteger.ONE);

		}

		// checks
		if (!this.bigP.isProbablePrime(prime_certainty) || !this.bigQ.isProbablePrime(prime_certainty))
			return false;

		this.bigF = new BigInteger(this.modulus, this.rand).mod(this.bigP);
		this.bigF = this.bigF.modPow((bigP.subtract(BigInteger.ONE)).divide(bigQ), bigP);

		this.Xg = randValModP(this.lQ, this.bigQ);
		this.Xh = randValModP(this.lQ, this.bigQ);

		this.bigG = bigF.modPow(Xg, this.bigP);
		this.bigH = bigF.modPow(Xh, this.bigP);
/**
		for (int i = 0; i < this.number_of_groupmembers; i++) {
			this.x[i] = new BigInteger(this.lQ, this.rand).mod(this.bigQ);
			this.r[i] = new BigInteger(this.modulus, this.rand).mod(this.n);

		}

		BigInteger twoToLE = new BigInteger("2").pow(this.lE - 1);
		while (this.e.size() < this.number_of_groupmembers) {
			BigInteger e = new BigInteger(this.le, this.rand);
			BigInteger bigE = twoToLE.add(e);
		
			boolean repeat = true;
			while (repeat) {
				e = new BigInteger(this.le, this.rand);
				bigE = twoToLE.add(e);
				if (e.bitLength() == this.le && bigE.bitLength() == this.lE
						&& bigE.isProbablePrime(this.prime_certainty))
					repeat = false;
			}
			this.e.add(e);
			this.bigE[this.e.size() - 1] = bigE;

		}

		for (int i = 0; i < number_of_groupmembers; i++) {
			BigInteger res = this.a.multiply(g.modPow(x[i], this.n)).multiply(h.modPow(r[i], this.n)).mod(this.n);
			BigInteger totient = this.p.subtract(BigInteger.ONE).multiply(this.q.subtract(BigInteger.ONE));
			BigInteger privat = bigE[i].modInverse(totient);

			// encrypt res
			this.y[i] = res.modPow(privat, this.n);
		}

		for (int i = 0; i < number_of_groupmembers; i++) {
			this.bigY[i] = bigG.modPow(this.x[i], this.bigP);
		}
**/
		// now that we have all the variables, we can construct the key objects
		this.vk = new GroupSignPublicKey(this.n, this.a, this.g, this.h, this.bigQ, this.bigP, this.bigF, this.bigG,
				this.bigH,this.w);

		this.gsmk = new GroupSignManagerKey(this.vk, this.Xg);
		
		/**
		for (int i = 0; i < number_of_groupmembers; i++) {
			this.sk[i] = new GroupSignMemberKey(this.vk, this.x[i], this.y[i], this.e.get(i), this.r[i], this.bigE[i]);
		}
**/
		return true;
	}
	
	private BigInteger getHash(ArrayList<byte[]> values){		
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
	

	public GroupSignSignature sign(byte[] message, GroupSignMemberKey sk) {
		// all the variables we need
		BigInteger r = randVal(this.modulus / 2);
		BigInteger bigR = randValModP(this.lQ, this.bigQ);
		BigInteger u = sk.vk().h().modPow(r, sk.vk().n()).multiply(sk.y()).mod(sk.vk().n());
		BigInteger bigU1 = sk.vk().bigF().modPow(bigR, sk.vk().bigP());
		BigInteger bigU2 = sk.vk().bigG().modPow(bigR.add(sk.x()), sk.vk().bigP());
		BigInteger bigU3 = sk.vk().bigH().modPow(bigR.add(sk.e()), sk.vk().bigP());



		BigInteger rx = randVal(this.lQ + this.lc + this.le);
		BigInteger rr = randVal(this.modulus / 2 + this.lc + this.le);
		BigInteger re = randVal(this.le + this.lc + this.le);
		BigInteger bigRr = randValModP(this.lQ, this.bigQ);

		BigInteger v = u.modPow(re, sk.vk().n()).multiply(sk.vk().g().modPow(rx.negate(), sk.vk().n()))
				.multiply(sk.vk().h().modPow(rr, sk.vk().n())).mod(sk.vk().n());
		BigInteger bigV1 = sk.vk().bigF().modPow(bigRr, sk.vk().bigP());
		BigInteger bigV2 = sk.vk().bigG().modPow(bigRr.add(rx), sk.vk().bigP());
		BigInteger bigV3 = sk.vk().bigH().modPow(bigRr.add(re), sk.vk().bigP());

		// generate hashing challenge
		ArrayList<byte[]> input = new ArrayList<byte[]>();
		try {
			input.add(convertToBytes(vk));
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
		BigInteger c = getHash(input);
		
		
		BigInteger zx = rx.add(c.multiply(sk.x()));

		BigInteger res = sk.r().negate().subtract(r.multiply(sk.bigE()));
		BigInteger zr = rr.add(c.multiply(res));

		res = c.multiply(sk.e());
		BigInteger ze = re.add(res);

		BigInteger zbigR = bigRr.add(c.multiply(bigR).mod(vk.bigQ()));

		// return the new signature
		return new GroupSignSignature(u, bigU1, bigU2, bigU3, zx, zr, ze, zbigR, c, message);

	}

	public boolean verify(GroupSignPublicKey vk, byte[] message, GroupSignSignature sigma) {
		if (sigma.ze().bitLength() != (this.le + this.lc + this.le)
				&& sigma.zx().bitLength() != (this.lQ + this.lc + this.le))
			return false;

		boolean isValid = false;
		BigInteger vPart1 = vk.a().modPow(sigma.c().negate(), vk.n());
		BigInteger vPart2 = vk.g().modPow(sigma.zx().negate(), vk.n());
		BigInteger vPart3 = vk.h().modPow(sigma.zr(), vk.n());
		BigInteger vPart4 = sigma.c().multiply(new BigInteger("2").pow(this.lE - 1)).add(sigma.ze());
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
			input.add(convertToBytes(vk));
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
		BigInteger c = getHash(input);
		System.out.println("calculated hash: " + c.toString(16));
		System.out.println("signature hash: " + sigma.c().toString(16));
		isValid = c.equals(sigma.c());

		return isValid;
	}

	public int open(GroupSignPublicKey vk, GroupSignManagerKey gsmk, byte[] message, GroupSignSignature sigma) {
		if (!verify(vk, message, sigma))
			return -1;
		BigInteger bigU1 = sigma.bigU1().modPow(gsmk.Xg(), vk.bigP());

		int i=0;
		for (BigInteger bigY : gsmk.bigY()) {
			if (bigU1.multiply(bigY).mod(vk.bigP()).equals(sigma.bigU2()))
				i++;
		}

		return i;
	}

	private byte[] convertToBytes(Object object) throws IOException {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutput out = new ObjectOutputStream(bos)) {
			out.writeObject(object);
			return bos.toByteArray();
		}
	}

	private boolean quadraticResidue(BigInteger a) {
		BigInteger two = BigInteger.ONE.add(BigInteger.ONE);

		BigInteger test1 = this.p.subtract(BigInteger.ONE).divide(two);
		BigInteger test2 = this.q.subtract(BigInteger.ONE).divide(two);

		return a.mod(this.p).modPow(test1, this.p).equals(BigInteger.ONE)
				&& a.mod(this.q).modPow(test2, this.q).equals(BigInteger.ONE);
	}

	private BigInteger randomElementOfQRn() {
		BigInteger a = randValModP(this.modulus, this.n);

		while (!quadraticResidue(a)) {
			a = randValModP(this.modulus, this.n);
		}
		return a;

	}

	private BigInteger randValModP(int maxlength, BigInteger p) {
		BigInteger ret = new BigInteger(maxlength, this.rand).mod(p);
		while (ret.bitLength() != maxlength) {
			ret = new BigInteger(maxlength, this.rand).mod(p);
		}
		return ret;
	}

	private BigInteger randVal(int length) {
		BigInteger ret = new BigInteger(length, this.rand);
		while (ret.bitLength() != length) {
			ret = new BigInteger(length, this.rand);
		}
		return ret;
	}

	public GroupSignPublicKey vk() {
		if (this.vk != null)
			return vk;
		return null;
	}

	public GroupSignMemberKey sk(int memberId) {
		if (this.skList.get(memberId) != null)
			return skList.get(memberId);
		return null;
	}

	public GroupSignManagerKey gsmk() {
		if (this.gsmk != null)
			return gsmk;
		return null;
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

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		GroupSign grpS = new GroupSign();
		byte[] testmessage = new BigInteger("1990").toByteArray();
		GroupSignMemberKey sk = grpS.sk(1);
		GroupSignPublicKey vk = grpS.vk();
		GroupSignManagerKey gsmk = grpS.gsmk();
		GroupSignSignature sigma_testmessage = grpS.sign(testmessage, sk);

		boolean valid = grpS.verify(vk, testmessage, sigma_testmessage);
		if (valid) {
			System.out.println("the signature verified correctly");
		} else {
			System.out.println("error");
		}

		byte[] othermessage = new BigInteger("1965").toByteArray();
		valid = grpS.verify(vk, othermessage, sigma_testmessage);
		if (valid) {
			System.out.println("error");
		} else {
			System.out.println("the signature was rejected correctly");
		}

		int member = grpS.open(vk, gsmk, testmessage, sigma_testmessage);
		System.out.println("The message was signed by member " + member);

	}

}
