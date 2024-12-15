package bankcard;
public class UtilLC {
    public static short getShort(byte[] buf, short offset) {
        short highByte = (short) (buf[offset+1] & 0xFF);
        short lowByte = (short) (buf[offset +2] & 0xFF);
        return (short) ((highByte << 8) | lowByte);
    }

    public static short getLong(byte[] buf, short offset) {
        short byte1 = (short) (buf[offset] & 0xFF);
        short byte2 = (short) (buf[offset + 1] & 0xFF);
        short byte3 = (short) (buf[offset + 2] & 0xFF);

        return (short) ((byte2 << 8) | byte3);
    }
}

