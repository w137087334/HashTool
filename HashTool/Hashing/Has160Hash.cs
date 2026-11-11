namespace HashTool.Hashing
{
    public sealed class Has160Hash : HashFunction
    {
        private static readonly int[] Index = new int[]
        {
            18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8, 9, 10, 11, 17, 12, 13, 14, 15,
            22, 3, 6, 9, 12, 23, 15, 2, 5, 8, 20, 11, 14, 1, 4, 21, 7, 10, 13, 0,
            26, 12, 5, 14, 7, 27, 0, 9, 2, 11, 24, 4, 13, 6, 15, 25, 8, 1, 10, 3,
            30, 7, 2, 13, 8, 31, 3, 14, 9, 4, 28, 15, 10, 5, 0, 29, 11, 6, 1, 12
        };

        private static readonly int[] Rot = new int[]
        {
            5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13
        };

        private readonly byte[] _buffer = new byte[64];
        private readonly uint[] _state = new uint[5];
        private readonly uint[] _words = new uint[32];
        private readonly BlockProcessor _process;
        private int _filled;
        private ulong _length;

        public Has160Hash()
        {
            _process = ProcessBlocks;
        }

        public override string Name { get { return "HAS-160"; } }

        public override string Group { get { return "MD"; } }

        public override void Initialize()
        {
            _state[0] = 0x67452301;
            _state[1] = 0xEFCDAB89;
            _state[2] = 0x98BADCFE;
            _state[3] = 0x10325476;
            _state[4] = 0xC3D2E1F0;
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

            byte[] result = new byte[20];
            for (int i = 0; i < 5; i++)
            {
                Binary.WriteUInt32LE(result, i * 4, _state[i]);
            }
            return result;
        }

        private unsafe void ProcessBlocks(byte[] data, int offset, int blocks)
        {
            uint s0 = _state[0], s1 = _state[1], s2 = _state[2], s3 = _state[3], s4 = _state[4];
            fixed (byte* start = &data[offset])
            fixed (uint* x = _words)
            fixed (int* index = Index)
            fixed (int* rot = Rot)
            {
                uint* input = (uint*)start;
                for (int block = 0; block < blocks; block++, input += 16)
                {
                    for (int i = 0; i < 16; i++)
                    {
                        x[i] = input[i];
                    }

                    x[16] = x[0] ^ x[1] ^ x[2] ^ x[3];
                    x[17] = x[4] ^ x[5] ^ x[6] ^ x[7];
                    x[18] = x[8] ^ x[9] ^ x[10] ^ x[11];
                    x[19] = x[12] ^ x[13] ^ x[14] ^ x[15];
                    x[20] = x[3] ^ x[6] ^ x[9] ^ x[12];
                    x[21] = x[2] ^ x[5] ^ x[8] ^ x[15];
                    x[22] = x[1] ^ x[4] ^ x[11] ^ x[14];
                    x[23] = x[0] ^ x[7] ^ x[10] ^ x[13];
                    x[24] = x[5] ^ x[7] ^ x[12] ^ x[14];
                    x[25] = x[0] ^ x[2] ^ x[9] ^ x[11];
                    x[26] = x[4] ^ x[6] ^ x[13] ^ x[15];
                    x[27] = x[1] ^ x[3] ^ x[8] ^ x[10];
                    x[28] = x[2] ^ x[7] ^ x[8] ^ x[13];
                    x[29] = x[3] ^ x[4] ^ x[9] ^ x[14];
                    x[30] = x[0] ^ x[5] ^ x[10] ^ x[15];
                    x[31] = x[1] ^ x[6] ^ x[11] ^ x[12];

                    uint a = s0, b = s1, c = s2, d = s3, e = s4;
                    for (int i = 0; i < 20; i++)
                    {
                        uint next = e + Binary.RotL(a, rot[i]) + (d ^ (b & (c ^ d))) + x[index[i]];
                        e = d; d = c; c = (b << 10) | (b >> 22); b = a; a = next;
                    }
                    for (int i = 0; i < 20; i++)
                    {
                        uint next = e + Binary.RotL(a, rot[i]) + (b ^ c ^ d) + x[index[20 + i]] + 0x5A827999u;
                        e = d; d = c; c = (b << 17) | (b >> 15); b = a; a = next;
                    }
                    for (int i = 0; i < 20; i++)
                    {
                        uint next = e + Binary.RotL(a, rot[i]) + (c ^ (b | ~d)) + x[index[40 + i]] + 0x6ED9EBA1u;
                        e = d; d = c; c = (b << 25) | (b >> 7); b = a; a = next;
                    }
                    for (int i = 0; i < 20; i++)
                    {
                        uint next = e + Binary.RotL(a, rot[i]) + (b ^ c ^ d) + x[index[60 + i]] + 0x8F1BBCDCu;
                        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = next;
                    }

                    s0 += a;
                    s1 += b;
                    s2 += c;
                    s3 += d;
                    s4 += e;
                }
            }
            _state[0] = s0;
            _state[1] = s1;
            _state[2] = s2;
            _state[3] = s3;
            _state[4] = s4;
        }
    }
}
