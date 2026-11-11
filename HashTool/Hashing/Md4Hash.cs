namespace HashTool.Hashing
{
    public sealed class Md4Hash : HashFunction
    {
        private readonly byte[] _buffer = new byte[64];
        private readonly uint[] _state = new uint[4];
        private readonly BlockProcessor _process;
        private int _filled;
        private ulong _length;

        public Md4Hash()
        {
            _process = ProcessBlocks;
        }

        public override string Name { get { return "MD4"; } }

        public override string Group { get { return "MD"; } }

        public override void Initialize()
        {
            _state[0] = 0x67452301;
            _state[1] = 0xEFCDAB89;
            _state[2] = 0x98BADCFE;
            _state[3] = 0x10325476;
            _filled = 0;
            _length = 0;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            Absorb(_buffer, ref _filled, 64, data, offset, count, _process);
            _length += (ulong)count;
        }

        public override byte[] FinalizeHash()
        {
            ulong bits = _length << 3;
            int filled = _filled;
            byte[] tail = new byte[filled < 56 ? 64 - filled : 128 - filled];
            tail[0] = 0x80;
            Binary.WriteUInt32LE(tail, tail.Length - 8, (uint)bits);
            Binary.WriteUInt32LE(tail, tail.Length - 4, (uint)(bits >> 32));
            Update(tail, 0, tail.Length);

            byte[] result = new byte[16];
            for (int i = 0; i < 4; i++)
            {
                Binary.WriteUInt32LE(result, i * 4, _state[i]);
            }
            return result;
        }

        private unsafe void ProcessBlocks(byte[] data, int offset, int blocks)
        {
            uint a0 = _state[0], b0 = _state[1], c0 = _state[2], d0 = _state[3];
            fixed (byte* start = &data[offset])
            {
                uint* x = (uint*)start;
                for (int block = 0; block < blocks; block++, x += 16)
                {
                    uint x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
                    uint x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
                    uint x8 = x[8], x9 = x[9], x10 = x[10], x11 = x[11];
                    uint x12 = x[12], x13 = x[13], x14 = x[14], x15 = x[15];
                    uint a = a0, b = b0, c = c0, d = d0;

                    a = R1(a, b, c, d, x0, 3); d = R1(d, a, b, c, x1, 7); c = R1(c, d, a, b, x2, 11); b = R1(b, c, d, a, x3, 19);
                    a = R1(a, b, c, d, x4, 3); d = R1(d, a, b, c, x5, 7); c = R1(c, d, a, b, x6, 11); b = R1(b, c, d, a, x7, 19);
                    a = R1(a, b, c, d, x8, 3); d = R1(d, a, b, c, x9, 7); c = R1(c, d, a, b, x10, 11); b = R1(b, c, d, a, x11, 19);
                    a = R1(a, b, c, d, x12, 3); d = R1(d, a, b, c, x13, 7); c = R1(c, d, a, b, x14, 11); b = R1(b, c, d, a, x15, 19);

                    a = R2(a, b, c, d, x0, 3); d = R2(d, a, b, c, x4, 5); c = R2(c, d, a, b, x8, 9); b = R2(b, c, d, a, x12, 13);
                    a = R2(a, b, c, d, x1, 3); d = R2(d, a, b, c, x5, 5); c = R2(c, d, a, b, x9, 9); b = R2(b, c, d, a, x13, 13);
                    a = R2(a, b, c, d, x2, 3); d = R2(d, a, b, c, x6, 5); c = R2(c, d, a, b, x10, 9); b = R2(b, c, d, a, x14, 13);
                    a = R2(a, b, c, d, x3, 3); d = R2(d, a, b, c, x7, 5); c = R2(c, d, a, b, x11, 9); b = R2(b, c, d, a, x15, 13);

                    a = R3(a, b, c, d, x0, 3); d = R3(d, a, b, c, x8, 9); c = R3(c, d, a, b, x4, 11); b = R3(b, c, d, a, x12, 15);
                    a = R3(a, b, c, d, x2, 3); d = R3(d, a, b, c, x10, 9); c = R3(c, d, a, b, x6, 11); b = R3(b, c, d, a, x14, 15);
                    a = R3(a, b, c, d, x1, 3); d = R3(d, a, b, c, x9, 9); c = R3(c, d, a, b, x5, 11); b = R3(b, c, d, a, x13, 15);
                    a = R3(a, b, c, d, x3, 3); d = R3(d, a, b, c, x11, 9); c = R3(c, d, a, b, x7, 11); b = R3(b, c, d, a, x15, 15);

                    a0 += a;
                    b0 += b;
                    c0 += c;
                    d0 += d;
                }
            }
            _state[0] = a0;
            _state[1] = b0;
            _state[2] = c0;
            _state[3] = d0;
        }

        private static uint R1(uint a, uint b, uint c, uint d, uint x, int s)
        {
            return Binary.RotL(a + (d ^ (b & (c ^ d))) + x, s);
        }

        private static uint R2(uint a, uint b, uint c, uint d, uint x, int s)
        {
            return Binary.RotL(a + ((b & c) | (d & (b | c))) + x + 0x5A827999u, s);
        }

        private static uint R3(uint a, uint b, uint c, uint d, uint x, int s)
        {
            return Binary.RotL(a + (b ^ c ^ d) + x + 0x6ED9EBA1u, s);
        }
    }
}
