package bankcard;

import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.security.MessageDigest;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.Signature;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.KeyBuilder;
import javacardx.apdu.ExtendedLength;
public class CitizenCard extends Applet implements ExtendedLength
{
	
	private static final byte[]PIN_DEFAULT= new byte[]{(byte)'1',(byte)'2',(byte)'3',(byte)'4',(byte)'5',(byte)'6'};
	private static final byte PIN_RETRY = 5;
	private final byte[] pin;
	private byte retry;
	private byte tryRemaining;
	private final MessageDigest messageDigest;
    private boolean isValidated;
    private final AESKey key;
    private final AesConfig aes;
    
    private static final byte INS_VERIFY=(byte)0x00;
    private static final byte INS_CREATE=(byte)0x01;
    private static final byte INS_GET=(byte)0x02;
    private static final byte INS_UPDATE=(byte)0x03;
    private static final byte PIN=(byte)0x04;
    private static final byte FORGET_PIN=0x0A;
	private static final byte BANK_INFORMATION=(byte)0x05;
	private static final byte SIGNATURE=(byte)0x06;
	private static final byte INFORMATION=(byte)0x07;
	private static final byte CARD_ID=(byte)0x0A;
	
	private static final byte BALANCE=(byte)0x08;
	private static final byte AVATAR=(byte)0x09;
	private static final byte INS_RESET_TRY_PIN=(byte)0x10;
    
    private byte[] cardId;
    private byte[] createDate;
    private byte[] expirationDate;
    private short dataLen;
    
    // Java card
    private byte[] personalInformation;
    
    
    private short MAX_SIZE = (short)15360;
    private byte[] avatar;
    private byte[] avatarBuffer;
    private short sizeAvatar = 0;
    
    private short informationDataLength = 0;
    
    private final Signature signature;
    private final byte[] signatureBuf;
    private RSAPrivateKey privateKey;
	private RSAPublicKey publicKey;
    
    public CitizenCard(){
    	aes= new AesConfig();
	    pin = new byte[16];
	    cardId = new byte[12];
	    retry = PIN_RETRY;
	    tryRemaining = PIN_RETRY;
	    isValidated = false;
	    messageDigest=MessageDigest.getInstance(MessageDigest.ALG_MD5,false);
	    messageDigest.doFinal(PIN_DEFAULT,(short)0,(short)PIN_DEFAULT.length,pin,(short)0);
        key=(AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, false);
      
        // numberCard= new byte[16];
        avatarBuffer = new byte[MAX_SIZE];
        avatar = new byte[MAX_SIZE];
        personalInformation = new byte[1024];
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        
        signatureBuf = JCSystem.makeTransientByteArray((short) (KeyBuilder.LENGTH_RSA_1024 / 8), JCSystem.CLEAR_ON_RESET);
    }
    
    public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = processAPDU(apdu);
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_VERIFY:
			verify(buf, apdu);
			break;
		case INS_CREATE:
			create(buf, apdu);
			break;
		case INS_GET:
			get(apdu);
			break;
		case INS_UPDATE:
			update(buf, apdu);
		    break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	public byte[] processAPDU(APDU apdu) {
		short pointer = 7;                  // Con tr  ch v trí lu tr trong buf_temp
		short byteRead = 0;               // S byte ã c t APDU
		short totalDataLen = 0;             // Tng s byte ca d liu
		byte[] buf = apdu.getBuffer();

		// Kim tra xem APDU có phi là Extended APDU hay không
		if (buf[ISO7816.OFFSET_LC] == 0x00) {  // Nu LC là 0x00 thì là Extended APDU
			// Kim tra xem LC có phi 2 byte hay 3 byte
			if (buf[ISO7816.OFFSET_LC + 1] != 0x00) {
				// Nu LC có 3 byte (do byte th 2 có giá tr 0x00)
				dataLen = UtilLC.getLong(buf, (short) (ISO7816.OFFSET_LC) ); // Ly 3 byte
			} else {
				// Nu LC có 2 byte
				dataLen = UtilLC.getShort(buf, (short) (ISO7816.OFFSET_LC) ); // Ly 2 byte
			}
		} else {
			// Nu không phi Extended APDU, ch ly LC là 1 byte
			dataLen = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
		}
		totalDataLen = dataLen;
		short standardLen = (short) (totalDataLen + (16 - (totalDataLen % 16)));
		
		byte[] buf_temp = new byte[(short) (standardLen +8)];
		byteRead = (short) (apdu.setIncomingAndReceive());
		Util.arrayCopy(buf, ISO7816.OFFSET_CLA, buf_temp, (short) 0, (short) 7);
		Util.arrayCopy(buf, ISO7816.OFFSET_EXT_CDATA, buf_temp, pointer, byteRead);
		totalDataLen -= byteRead; 
		pointer += byteRead;
		byteRead = apdu.receiveBytes((short) 0);
		
		while (totalDataLen > 0) {
			Util.arrayCopy(buf, (short)0, buf_temp, pointer, byteRead);
			
			pointer += byteRead;
			totalDataLen -= byteRead;
			
			byteRead = apdu.receiveBytes((short) 0);
		}

		return buf_temp;
	}
    // 00 02 05 07
    private void get(APDU apdu) throws ISOException{
		// if(personalInformation.length == 0){
			// return;
		// }
		byte[] buf=apdu.getBuffer();
		if(buf[ISO7816.OFFSET_P1]!=BANK_INFORMATION){
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		switch(buf[ISO7816.OFFSET_P2]){
		case INFORMATION:
			getInformation(apdu);
			break;
		case BALANCE:
			getBalance(apdu);
			break;
		case AVATAR:
			getAvatar(apdu);
			break;
		case CARD_ID:
			getCardId(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}
	private void getBalance(APDU apdu){
	    byte[]buf=apdu.getBuffer();
	    // short length= (byte)getLength(aes.decode(numberBalance,(short)0,(short)numberBalance.length,key, buf,(short)0),(short)0);
	    // apdu.setOutgoingAndSend((short)0,length);
    }
	private void update(byte[] buf, APDU apdu) throws ISOException{
		
		switch(buf[ISO7816.OFFSET_P1]){
		case BANK_INFORMATION:
			break;
		case PIN:
			updatePin(buf, apdu);
			return;
		case FORGET_PIN:
			forgetPin(buf, apdu);
			return;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		byte P2=buf[ISO7816.OFFSET_P2];
		if(P2==AVATAR){
			updateAvatar(buf, apdu);
			return;
		}
		
		// if(buf[ISO7816.OFFSET_LC]==(byte)0x00){
			// ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		// }
		
		switch(P2){
		case INFORMATION:
			updateInformation(buf);
			break;
		case BALANCE:
			updateBalance(buf);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}
	private void updateInformation(byte[]buf){
	    byte offset;
	    short length;
	    JCSystem.beginTransaction();
	    offset=ISO7816.OFFSET_CDATA;
	    length=(short) buf[offset];
	    // nameCard = aes.encode(buf,(short)(offset+1),length,key,nameCard);
	   
	    JCSystem.commitTransaction();
    }
    private void updateBalance(byte[]buf){
	    short offset=ISO7816.OFFSET_CDATA;
	    short length=buf[ISO7816.OFFSET_LC];
	    JCSystem.beginTransaction();
	    // numberBalance = aes.encode(buf,(short)offset,length,key,numberBalance);
	    JCSystem.commitTransaction();
    }
    
    private void forgetPin(byte[] buf, APDU apdu) throws ISOException{
	    // byte[]buf=apdu.getBuffer();
	    byte offsetCData = ISO7816.OFFSET_EXT_CDATA;
	    short length = dataLen;
	    if (length != 6){
		    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	    }
	    byte[]temp=JCSystem.makeTransientByteArray((short) pin.length, JCSystem.CLEAR_ON_DESELECT);
		messageDigest.reset();
		messageDigest.doFinal(buf, offsetCData, length, temp, (short) 0);
	    apdu.setOutgoingAndSend(ISO7816.OFFSET_EXT_CDATA, (short)1);
    }
    
	private void updatePin(byte[] buf, APDU apdu) throws ISOException{
	    // byte[]buf=apdu.getBuffer();
	    byte offsetCData=ISO7816.OFFSET_EXT_CDATA;
	    // short length=(short) buf[offset]
	    short length = 6;
;
	    if(match(buf,(byte)(offsetCData),length)){
		    offsetCData+=(byte)(length);
		    // length=(short)buf[offset];
		    update(buf, offsetCData, length);
		    return;
	    }
	    buf[ISO7816.OFFSET_EXT_CDATA]=getTryRemaining();
	    apdu.setOutgoingAndSend(ISO7816.OFFSET_EXT_CDATA,(short)1);
	    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    
    
    //kiem tra ma pin nhap vao va ma pin hien tai
    //checkma pin(bam) va ma pin dang co (bam) trong the
    public boolean match(byte[]buf,byte offset,short length){
		if(tryRemaining==(byte)0x00){
			return false;
		
		}
		byte[]temp=JCSystem.makeTransientByteArray((short) pin.length, JCSystem.CLEAR_ON_DESELECT);
		messageDigest.reset();
		messageDigest.doFinal(buf, (short) offset, length, temp, (short) 0);
		if(Util.arrayCompare(pin,(short)0,temp,(short)0,(short)pin.length)==(byte)0x00){
			this.tryRemaining=retry;
			this.isValidated=true;
			return true;
		}
		tryRemaining--;
		return false;
	}
    public void update(byte[]buf,byte offset,short length){
		if(length<1){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		messageDigest.reset();
		messageDigest.doFinal(buf,(short)offset,length,pin,(short)0);
		tryRemaining=retry;
	}
	private short getLength(byte[]output,short outOffset){
		short length;
		for(length=(short)(output.length-1);length>=0;length--){
			if(output[length]!=(byte)0x00){
				break;
			}
		}
		return (short)(length-outOffset+1);
	}
	
	private void getCardId(APDU apdu) {
		if (cardId[0] == 0x00) {
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND); 
		}
		
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopyNonAtomic(cardId, (short) 0, buffer, (short) 0 , (short) 12);
		apdu.setOutgoingAndSend((short) 0, (short) 12);
	}
	
	//giai ma --->lay du lieu ---> gui den app
    private void getInformation(APDU apdu) {
    	informationDataLength = getArrayLen(personalInformation);
    	
    	if (informationDataLength == 0)
    		ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    	
		byte[] buffer = apdu.getBuffer();
		byte offset;
		
		offset = (byte) 0x00;
		
		informationDataLength = aes.decode(personalInformation,(short)0,(short)informationDataLength,key, buffer,(short)0);

		apdu.setOutgoingAndSend((short) 0, (short) informationDataLength);
	}
	
	private void normalizeData(byte[] data, short offset) {
		Util.arrayFillNonAtomic(data, offset, (short) (data.length - offset), (byte) 0x00);
	}
	
	private short getArrayLen(byte[] data) {
		short count = 0;
		for (short i = (short) (data.length - 1); i >= 0; i--) {
			if (data[i] != 0x00) {
				break;
			}
			count++;
		}
		return (short) (((short) data.length) - count);
	}
	
	private void getAvatar(APDU apdu) {
		short avtSize = aes.decode(avatar,(short)0,sizeAvatar,key,avatarBuffer,(short)0);
		avtSize = getArrayLen(avatarBuffer);
		
		
		short maxLength = apdu.setOutgoing();
		short length = 0;
		short pointer = 0;
		//bo dem apdu
		apdu.setOutgoingLength(avtSize);
		while (avtSize > 0) {
			length = getMin(avtSize, maxLength);
			apdu.sendBytesLong(avatarBuffer, pointer, length);
			avtSize -= length;
			pointer += length;
		}
	}
	
	private short getMin(short lengthOne,short lengthTwo){
	    if(lengthOne<=lengthTwo){
		    return lengthOne;
	    }
	    return lengthTwo;
    }
    
    // 00 03 05 09
	private void updateAvatar(byte[] buf, APDU apdu){
	    Util.arrayCopyNonAtomic(buf,ISO7816.OFFSET_EXT_CDATA,avatarBuffer,(short) 0,dataLen);
        sizeAvatar = dataLen;
	    short paddedAvatar = aes.encode(avatarBuffer,(short)0,dataLen,key,avatar);
	    sizeAvatar = paddedAvatar;
	    normalizeData(avatar, paddedAvatar);
    }
    
    private void verify(byte[] buf, APDU apdu){
		byte[] bufApdu=apdu.getBuffer();
		byte offset=ISO7816.OFFSET_EXT_CDATA;
		short length=dataLen;
		if(checkPin(buf,offset,length)){
			return;
		}
		bufApdu[(short) 0]=getTryRemaining();
		apdu.setOutgoingAndSend((short) 0,(short)1);
		ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	}
	private void create(byte[]buf, APDU apdu) throws ISOException{
		// byte[] buf=apdu.getBuffer();
		switch(buf[ISO7816.OFFSET_P1]){
		case BANK_INFORMATION:
			createInformation(buf, apdu);
			break;
			//00 01 06 00
		case SIGNATURE:
			createSignature(buf, apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}
	//app  --gui du lieu -->  ma hoa ---> luu vao the
	public void createInformation(byte[] buf, APDU apdu) throws ISOException{
		// if(nameCard[0x00]!=0x00){
			// ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		// }
		// byte[]buf= processAPDU(apdu);
		byte[] apduBuf = apdu.getBuffer();
		if(dataLen==(byte)0x00){
		     ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	     }
	     short offset;
	     short offsetPin;
	     short length;
	     
	     JCSystem.beginTransaction();
	     
	     length = dataLen;
	     offsetPin = (short) (length + 1); // 62 - 6 + 8 = 61, 61 62 63 64 65 66
	     
	     // PIN code
	     messageDigest.reset();
	     messageDigest.doFinal(buf,(short)offsetPin, (short) 6, pin,(short)0);
	     
	     // personal information
	     offset = (short) ISO7816.OFFSET_EXT_CDATA; // offset C Ext data
	     key.setKey(pin, (short)0);
	     informationDataLength = (short) (length - 7);
	     
	     // Get card ID
	     Util.arrayCopyNonAtomic(buf, offset, cardId, (short) 0, (short) 12);     
	     
	     informationDataLength = aes.encode(buf, (short)(offset), (short) (length - 7),  key, personalInformation);
	     normalizeData(personalInformation, (short)(informationDataLength+1));
	     
	     JCSystem.commitTransaction();
	     KeyPair keyPair=RsaConfig.generateKeyPair();
	     privateKey=(RSAPrivateKey)keyPair.getPrivate();
	     publicKey=(RSAPublicKey) keyPair.getPublic();
	    
	     length=RsaConfig.serializePublicKey(publicKey,buf,(short)0);
	     
	     Util.arrayCopyNonAtomic(buf, (short) 0, apduBuf, (short) 0, length);
	    //gui public key -> App, App nhan duoc public key => thong bao thanh cong khoi tao thong tin
	     apdu.setOutgoingAndSend((short)0,length);
	}
    private boolean checkPin(byte[]buf,byte offset,short length){
	    if(tryRemaining==(byte)0x00){
		    return false;
	    }
	    byte[]temp=JCSystem.makeTransientByteArray((short) pin.length, JCSystem.CLEAR_ON_DESELECT);
		messageDigest.reset();
		messageDigest.doFinal(buf, (short) offset, length, temp, (short) 0);
		if(Util.arrayCompare(pin,(short)0,temp,(short)0,(short)pin.length)==(byte)0x00){
			this.tryRemaining=retry;
			this.isValidated=true;
			return true;
		}
		tryRemaining--;
		return false;
    }
    public void updatePin(byte[]buf,byte offset,short length){
		if(length<1){
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		messageDigest.reset();
		messageDigest.doFinal(buf,(short)offset,length,pin,(short)0);
		tryRemaining=retry;
	}
    public byte[]getPIN(){
		return pin;
	}
	public byte getTryRemaining(){
		return tryRemaining;
	}
	public boolean isValidated(){
		return isValidated;
	}
	
	private void createSignature(byte[] buffer, APDU apdu) throws ISOException {
		short length = dataLen;
		
		if (length == (byte) 0x00) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		signature.init(privateKey, Signature.MODE_SIGN);
		signature.sign(buffer, (short) ISO7816.OFFSET_EXT_CDATA, length, signatureBuf, (short) 0);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) signatureBuf.length);
		apdu.sendBytesLong(signatureBuf, (short) 0, (short) signatureBuf.length);
	}
	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new CitizenCard().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

}
