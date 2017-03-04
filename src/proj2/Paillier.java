package proj2;
import java.util.*;
import java.math.*;
import java.security.SecureRandom;

public class Paillier {

private BigInteger g;
private int modulus;

private BigInteger p;
private BigInteger q;
private SecureRandom rand = new SecureRandom();
private BigInteger lambda;
public BigInteger n;
public BigInteger nsquared;


public Paillier(int modulus, int prime_certainty) {
keyGen(modulus, prime_certainty);
}


public Paillier() {
keyGen(512, 64);
}

public void keyGen(int modulus, int prime_certainty) {
p = new BigInteger(modulus / 2, prime_certainty, rand);
q = new BigInteger(modulus / 2, prime_certainty, rand);

n = p.multiply(q);
nsquared = n.multiply(n);
this.modulus=modulus;
g = new BigInteger("2");
lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).divide(
p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));

if (g.modPow(lambda, nsquared).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
System.out.println("g is not good. Choose g again.");
System.exit(1);
}
System.out.println("p: " + p);
System.out.println("q: " + q);
System.out.println("n: " + n);
System.out.println("nsquared " + nsquared);
System.out.println("lambda: " + lambda);
}


public BigInteger Encryption(BigInteger m, BigInteger r) {
	System.out.println("g pot: " + g.modPow(m, nsquared));
	System.out.println("r pot: " + r.modPow(n, nsquared));

return g.modPow(m, nsquared).multiply(r.modPow(n, nsquared)).mod(nsquared);
}


public BigInteger Encryption(BigInteger m) {
BigInteger r = new BigInteger(modulus, rand);

System.out.println("g pot: " + g.modPow(m, nsquared));
System.out.println("r pot: " + r.modPow(n, nsquared));
System.out.println("r: " + r);

return g.modPow(m, nsquared).multiply(r.modPow(n, nsquared)).mod(nsquared);

}


public BigInteger Decryption(BigInteger c) {
BigInteger u = g.modPow(lambda, nsquared).subtract(BigInteger.ONE).divide(n).modInverse(n);
return c.modPow(lambda, nsquared).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
}


public static void main(String[] str) {
Paillier paillier = new Paillier();
BigInteger m1 = new BigInteger("20");
BigInteger m2 = new BigInteger("60");

BigInteger c1 = paillier.Encryption(m1);
BigInteger c2 = paillier.Encryption(m2);


System.out.println("Ciphertext c1: " + c1.intValue() );
System.out.println("Ciphertext c2: " + c2.intValue() );

System.out.println("Decrypted c1: " + paillier.Decryption(c1).intValue() );
System.out.println("Decrypted c2: " + paillier.Decryption(c2).intValue() );



BigInteger product_em1em2 = c1.multiply(c2).mod(paillier.nsquared);
BigInteger sum_m1m2 = m1.add(m2).mod(paillier.n);
System.out.println("original sum: " + sum_m1m2.toString());
System.out.println("decrypted sum: " + paillier.Decryption(product_em1em2).toString());




}
}