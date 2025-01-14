package bankcard;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.KeyBuilder;
public class RsaConfig {
	public static KeyPair generateKeyPair() {
		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
		keyPair.genKeyPair();
		return keyPair;
	}
	//tra ve kich thuoc publickey
	public static short serializePublicKey(RSAPublicKey key, byte[] buffer, short offset) {
		//tra ve luy thua cong khai exponentLength co length=3
		
		// Structure of x509EncodedKeySpec
		// [Exponent length][Exponent bytes][Modulus length][Modulus Bytes]
		//			2 bytes		3 bytes			2 bytes			128 bytes
		
		// Set buffer for exponent bytes
		short exponentLength = key.getExponent(buffer, (short) (offset + 2));
		
		//tra ve modun khoa, so bit dich = offset,  modulusLength co length=128
		
		short modulusLength = key.getModulus(buffer, (short) (offset + 2 + exponentLength + 2));
		
		// Set exponent length
		Util.setShort(buffer, offset, exponentLength);
		// Set Modulus length
		Util.setShort(buffer, (short) (offset + 2 + exponentLength), modulusLength);
		return (short) (4 + exponentLength + modulusLength);
	}
}
