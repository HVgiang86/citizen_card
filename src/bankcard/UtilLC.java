package bankcard;
public class UtilLC {
	// Hàm ly giá tr 2 byte thành short
    public static short getShort(byte[] buf, short offset) {
        short highByte = (short) (buf[offset] & 0xFF);
        short lowByte = (short) (buf[offset + 1] & 0xFF);
        return (short) ((highByte << 8) | lowByte); // Kt hp 2 byte thành mt short
    }

    // Hàm ly giá tr 3 byte thành short (cn dùng vi LC 3 byte)
    public static short getLong(byte[] buf, short offset) {
        short byte1 = (short) (buf[offset] & 0xFF);
        short byte2 = (short) (buf[offset + 1] & 0xFF);
        short byte3 = (short) (buf[offset + 2] & 0xFF);

        // Chuyn i 3 byte thành short (gii hn 16-bit)
        return (short) ((byte1 << 8) | (byte2 << 4) | byte3);
    }
}

