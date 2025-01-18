package Lab1;

import javacard.framework.*;

public class Th1Bai5 extends Applet {
    private byte[] studentId;
    private byte[] name;
    private byte[] dob;
    private byte[] town;
    private byte[] studentInfo;

    private static byte DELIMITER = (byte) '$';

    // INS
    private static final byte INS_ENTER_INFO = (byte) 0x00;
    private static final byte INS_GET_INFO = (byte) 0x01;

    // P1
    private static final byte P1_ID = (byte) 0x01;
    private static final byte P1_NAME = (byte) 0x02;
    private static final byte P1_DOB = (byte) 0x03;
    private static final byte P1_ADDRESS = (byte) 0x04;
    private static final byte P1_FULL_INFO = (byte) 0x05;

    private Th1Bai5() {
        studentId = null;
        name = null;
        dob = null;
        town = null;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Th1Bai5().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_ENTER_INFO:
                enterStudentInfo(apdu);
                break;
            case INS_GET_INFO:
                getStudentInfo(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // Enter student information
    private void enterStudentInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = (short) apdu.setIncomingAndReceive();

        short offset = ISO7816.OFFSET_CDATA;

        studentInfo = new byte[length];

        Util.arrayCopy(buffer, offset, studentInfo, (short) 0, length);
        
        // Data: [student code]$[name]$[dob]$[address]
        
        // Student Id
        short delimiterPos = findDelimiter(buffer, offset, length, DELIMITER);
        short fieldLength = (short) (delimiterPos - offset);
        studentId = new byte[fieldLength];
        Util.arrayCopy(buffer, offset, studentId, (short) 0, fieldLength);
        offset = (short) (delimiterPos + 1);

        // Full name
        delimiterPos = findDelimiter(buffer, offset, length, DELIMITER);
        fieldLength = (short) (delimiterPos - offset);
        name = new byte[fieldLength];
        Util.arrayCopy(buffer, offset, name, (short) 0, fieldLength);
        offset = (short) (delimiterPos + 1);

        // Date of birth
        delimiterPos = findDelimiter(buffer, offset, length, DELIMITER);
        fieldLength = (short) (delimiterPos - offset);
        dob = new byte[fieldLength];
        Util.arrayCopy(buffer, offset, dob, (short) 0, fieldLength);
        offset = (short) (delimiterPos + 1);

        // Hometown address
        fieldLength = (short) (length - offset + 5);
        town = new byte[fieldLength];
        Util.arrayCopy(buffer, offset, town, (short) 0, fieldLength);
    }

    /**
     * Function to find position of delimiter
     * @param delimiter byte that present delimiter
     * @return position of next delimiter from start
     */
    private short findDelimiter(byte[] buffer, short start, short length, byte delimiter) {
        for (short i = start; i < (short) (start + length); i++) {
            if (buffer[i] == delimiter) {
                return i;
            }
        }
        ISOException.throwIt(ISO7816.SW_WRONG_DATA); // If delimiter is not found
        return -1; // This line will never execute due to the exception
    }

    private void getStudentInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte[] fieldToSend = null;
        short length = 0;

        switch (p1) {
            case P1_ID:
                fieldToSend = studentId;
                length = (short) studentId.length;
                break;
            case P1_NAME:
                fieldToSend = name;
                length = (short) name.length;
                break;
            case P1_DOB:
                fieldToSend = dob;
                length = (short) dob.length;
                break;
            case P1_ADDRESS:
                fieldToSend = town;
                length = (short) town.length;
                break;
            case P1_FULL_INFO:
                fieldToSend = studentInfo;
                length = (short) studentInfo.length;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Send the selected field back to the terminal
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(fieldToSend, (short) 0, length);
    }
}
