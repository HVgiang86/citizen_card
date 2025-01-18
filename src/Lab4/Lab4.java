package Lab4;
import javacard.framework.*;

public class Lab4 extends Applet {

	// 'DIEM_THI'
    private static final byte[] DEFAULT_AID = {0x44, 0x49, 0x45, 0x4D, 0x5F, 0x54, 0x48, 0x49}; 
    
    // 'CT050413' instead of SV01 :D
    private static final byte[] DEFAULT_STUDENT_ID = {0x43, 0x54, 0x30, 0x35, 0x30, 0x34, 0x31, 0x33}; 
    private static final byte MAX_SUBJECTS = 0x09; // 9 subjects

    // INS
    private static final byte INS_ADD_SCORE = (byte) 0x01;
    private static final byte INS_PRINT_SCORES = (byte) 0x02;
    private static final byte INS_EDIT_SCORE = (byte) 0x03;
    private static final byte INS_DELETE_SCORE = (byte) 0x04;

    private byte[] studentID;
    private byte[] scores; 
    private byte subjectCount;

    protected Lab4(byte[] bArray, short bOffset, byte bLength) {
        byte aidLength = bArray[bOffset];
        if (aidLength == 0) {
            register();
        } else {
            register(bArray, (short) (bOffset + 1), aidLength);
        }

        short offset = (short) (bOffset + 1 + aidLength + 1); 
        byte controlLength = bArray[offset];
        offset += (short) (controlLength + 1);

        studentID = new byte[DEFAULT_STUDENT_ID.length];
        Util.arrayCopy(DEFAULT_STUDENT_ID, (short) 0, studentID, (short) 0, (short) studentID.length);

        scores = new byte[MAX_SUBJECTS * 2];
        subjectCount = 0;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Lab4(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte instruction = buffer[ISO7816.OFFSET_INS];
        apdu.setIncomingAndReceive();

        switch (instruction) {
            case INS_ADD_SCORE:
                addScore(apdu, buffer);
                break;
            case INS_PRINT_SCORES:
                printScores(apdu);
                break;
            case INS_EDIT_SCORE:
                editScore(apdu, buffer);
                break;
            case INS_DELETE_SCORE:
                deleteScore(apdu, buffer);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void addScore(APDU apdu, byte[] buffer) {
        if (subjectCount >= MAX_SUBJECTS) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte subjectID = buffer[ISO7816.OFFSET_CDATA];
        byte score = buffer[ISO7816.OFFSET_CDATA + 1];

        for (short i = 0; i < subjectCount * 2; i += 2) {
            if (scores[i] == subjectID) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }

        short offset = (short) (subjectCount * 2);
        scores[offset] = subjectID;
        scores[(short) (offset + 1)] = score;
        subjectCount++;

        printScores(apdu);
    }

    private void printScores(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (subjectCount * 2));
        apdu.sendBytesLong(scores, (short) 0, (short) (subjectCount * 2));
    }

    private void editScore(APDU apdu, byte[] buffer) {
        byte subjectID = buffer[ISO7816.OFFSET_CDATA];
        byte newScore = buffer[ISO7816.OFFSET_CDATA + 1];

        for (short i = 0; i < subjectCount * 2; i += 2) {
            if (scores[i] == subjectID) {
                scores[(short) (i + 1)] = newScore;
                printScores(apdu);
                return;
            }
        }

        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }

    private void deleteScore(APDU apdu, byte[] buffer) {
        byte subjectID = buffer[ISO7816.OFFSET_CDATA];

        for (short i = 0; i < subjectCount * 2; i += 2) {
            if (scores[i] == subjectID) {
                Util.arrayCopy(scores, (short) (i + 2), scores, i, (short) ((subjectCount * 2) - (i + 2)));
                subjectCount--;
                printScores(apdu);
                return;
            }
        }

        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
}
