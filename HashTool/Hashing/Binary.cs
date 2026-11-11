namespace HashTool.Hashing
{
    internal static class Binary
    {
        public static uint RotL(uint value, int bits)
        {
            return (value << bits) | (value >> (32 - bits));
        }

        public static uint RotR(uint value, int bits)
        {
            return (value >> bits) | (value << (32 - bits));
        }

        public static ulong RotL(ulong value, int bits)
        {
            return (value << bits) | (value >> (64 - bits));
        }

        public static ulong RotR(ulong value, int bits)
        {
            return (value >> bits) | (value << (64 - bits));
        }

        public static uint Swap(uint value)
        {
            return (value << 24) | ((value & 0xFF00) << 8) | ((value >> 8) & 0xFF00) | (value >> 24);
        }

        public static uint ReadUInt32LE(byte[] data, int offset)
        {
            return (uint)data[offset]
                | ((uint)data[offset + 1] << 8)
                | ((uint)data[offset + 2] << 16)
                | ((uint)data[offset + 3] << 24);
        }

        public static uint ReadUInt32BE(byte[] data, int offset)
        {
            return ((uint)data[offset] << 24)
                | ((uint)data[offset + 1] << 16)
                | ((uint)data[offset + 2] << 8)
                | data[offset + 3];
        }

        public static ulong ReadUInt64LE(byte[] data, int offset)
        {
            return (ulong)ReadUInt32LE(data, offset)
                | ((ulong)ReadUInt32LE(data, offset + 4) << 32);
        }

        public static ulong ReadUInt64BE(byte[] data, int offset)
        {
            return ((ulong)ReadUInt32BE(data, offset) << 32)
                | ReadUInt32BE(data, offset + 4);
        }

        public static void WriteUInt32LE(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }

        public static void WriteUInt32BE(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)(value >> 24);
            data[offset + 1] = (byte)(value >> 16);
            data[offset + 2] = (byte)(value >> 8);
            data[offset + 3] = (byte)value;
        }

        public static void WriteUInt64BE(byte[] data, int offset, ulong value)
        {
            WriteUInt32BE(data, offset, (uint)(value >> 32));
            WriteUInt32BE(data, offset + 4, (uint)value);
        }

        public static void Mul64(ulong left, ulong right, out ulong high, out ulong low)
        {
            ulong leftLow = (uint)left;
            ulong leftHigh = left >> 32;
            ulong rightLow = (uint)right;
            ulong rightHigh = right >> 32;

            ulong lowProduct = leftLow * rightLow;
            ulong mid = leftHigh * rightLow + (lowProduct >> 32);
            ulong midLow = leftLow * rightHigh + (uint)mid;

            low = (midLow << 32) | (uint)lowProduct;
            high = leftHigh * rightHigh + (mid >> 32) + (midLow >> 32);
        }

        public static ulong MulFold(ulong left, ulong right)
        {
            ulong high;
            ulong low;
            Mul64(left, right, out high, out low);
            return low ^ high;
        }

        public static byte[] HexToBytes(string hex)
        {
            if ((hex.Length & 1) != 0)
            {
                throw new System.ArgumentException("Hexadecimal length must be even.");
            }

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = System.Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}
