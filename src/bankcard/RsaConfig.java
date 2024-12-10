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
		short exponentLength = key.getExponent(buffer, (short) (offset + 2));
		//tra ve modun khoa, so bit dich = offset,  modulusLength co length=128
		short modulusLength = key.getModulus(buffer, (short) (offset + 2 + exponentLength + 2));
		Util.setShort(buffer, offset, exponentLength);
		Util.setShort(buffer, (short) (offset + 2 + exponentLength), modulusLength);
		return (short) (10 + exponentLength + modulusLength);
	}
}
