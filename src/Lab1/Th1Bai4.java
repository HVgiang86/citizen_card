package Lab1;

import javacard.framework.*;

public class Th1Bai4 extends Applet {

    private byte[] fullName;
    private byte[] dateOfBirth;

    // INS
    private static final byte INS_ENTER_INFO = (byte) 0x00;
    private static final byte INS_GET_INFO = (byte) 0x01;

    // P1
    private static final byte P1_NAME = (byte) 0x01;
    private static final byte P1_DOB = (byte) 0x02;
    private static final byte P1_BOTH = (byte) 0x03;

    private Th1Bai4() {
        fullName = null;
        dateOfBirth = null;
    }

    // Applet installation
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Th1Bai4().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    // Process APDU commands
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_ENTER_INFO:
                enterInfo(apdu);
                break;
            case INS_GET_INFO:
                getStudentInfo(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void enterInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        switch (p1) {
            case P1_NAME:
                enterFullName(apdu);
                break;
            case P1_DOB:
                enterDateOfBirth(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void enterFullName(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = (short) apdu.setIncomingAndReceive();

        fullName = new byte[length];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, fullName, (short) 0, length);
    }

    private void enterDateOfBirth(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = (short) apdu.setIncomingAndReceive();

        dateOfBirth = new byte[length];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, dateOfBirth, (short) 0, length);
    }

    // Get student information
    private void getStudentInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte[] fieldToSend = null;
        short length = 0;

        switch (p1) {
            case P1_NAME: // Full name
                if (fullName != null) {
                    fieldToSend = fullName;
                    length = (short) fullName.length;
                }
                break;
            case P1_DOB: // Date of birth
                if (dateOfBirth != null) {
                    fieldToSend = dateOfBirth;
                    length = (short) dateOfBirth.length;
                }
                break;
            case P1_BOTH: // Both full name and date of birth
                if (fullName != null && dateOfBirth != null) {
                    length = (short) (fullName.length + dateOfBirth.length + 1); // +1 for delimiter
                    fieldToSend = new byte[length];

                    // Combine full name and date of birth with a delimiter (e.g., '|')
                    Util.arrayCopy(fullName, (short) 0, fieldToSend, (short) 0, (short) fullName.length);
                    fieldToSend[fullName.length] = (byte) '|';
                    Util.arrayCopy(dateOfBirth, (short) 0, fieldToSend, (short) (fullName.length + 1), (short) dateOfBirth.length);
                }
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (fieldToSend != null) {
            apdu.setOutgoing();
            apdu.setOutgoingLength(length);
            apdu.sendBytesLong(fieldToSend, (short) 0, length);
        } else {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
    }
}
