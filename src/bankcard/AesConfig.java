package bankcard;

import javacard.framework.JCSystem;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacardx.crypto.Cipher;

public class AesConfig {
    private final Cipher cipher;

    public AesConfig() {
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    }

    // Function to apply PKCS7 padding
    private short applyPadding(byte[] input, short offset, short length) {
        short paddedLength = (short) (length + (16 - (length % 16))); // Next multiple of 16
        byte paddingValue = (byte) 0x00; // Padding byte value

        // Copy original data and add padding
        Util.arrayFillNonAtomic(input, (short) length, (short) (paddedLength-length), (byte) 0x00);

        return paddedLength;
    }

    // Remove PKCS7 padding
    private short removePadding(byte[] output, short length) {
        byte paddingValue = 0x00;
        short paddingLength = 0;
        for (short i = (short) (length - 1); i >= 0; i--) {
	        if (output[i] == paddingValue) {
		        paddingLength ++;
	        }
        }
        
        return (short) (length - paddingLength); // Return the original length without padding
    }

    // Encrypt and copy encrypted data into output array, return padded length
    public short encode(byte[] input, short offset, short length, AESKey key, byte[] output) {
        if (length < 1) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Apply padding and get padded length
        short paddedLength = applyPadding(input, offset, length);

        // Initialize cipher for encryption
        cipher.init(key, Cipher.MODE_ENCRYPT);

        // Perform encryption, copy result into the output array
        cipher.doFinal(input, (short) 0, paddedLength, output, (short) 0);

        // Return the padded length, indicating the length of the encrypted data
        return paddedLength;
    }

    // Decrypt and copy decrypted data into output array, return original length after removing padding
    public short decode(byte[] input, short inOffset, short inLength, AESKey key, byte[] output, short outOffset) {
        if ((short) (inLength % 16) != 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Initialize cipher for decryption
        cipher.init(key, Cipher.MODE_DECRYPT);

        // Perform decryption, copy result into output array
        cipher.doFinal(input, inOffset, inLength, output, outOffset);

        // Remove padding and return the original length of the data
        return removePadding(output, inLength);
    }
}
