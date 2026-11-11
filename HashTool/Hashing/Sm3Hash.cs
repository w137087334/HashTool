namespace HashTool.Hashing
{
    public sealed class Sm3Hash : HashFunction
    {
        private static readonly uint[] T = BuildT();

        private readonly byte[] _buffer = new byte[64];
        private readonly uint[] _state = new uint[8];
        private readonly uint[] _w = new uint[68];
        private readonly BlockProcessor _process;
        private int _filled;
        private ulong _length;

        public Sm3Hash()
        {
            _process = ProcessBlocks;
        }

        public override string Name { get { return "SM3"; } }

        public override string Group { get { return "SM3"; } }

        public override void Initialize()
        {
            _state[0] = 0x7380166F;
            _state[1] = 0x4914B2B9;
            _state[2] = 0x172442D7;
            _state[3] = 0xDA8A0600;
            _state[4] = 0xA96F30BC;
            _state[5] = 0x163138AA;
            _state[6] = 0xE38DEE4D;
            _state[7] = 0xB0FB0E4E;
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
            Binary.WriteUInt64BE(tail, tail.Length - 8, bits);
            Update(tail, 0, tail.Length);

            byte[] result = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                Binary.WriteUInt32BE(result, i * 4, _state[i]);
            }
            return result;
        }

        private unsafe void ProcessBlocks(byte[] data, int offset, int blocks)
        {
            uint s0 = _state[0], s1 = _state[1], s2 = _state[2], s3 = _state[3];
            uint s4 = _state[4], s5 = _state[5], s6 = _state[6], s7 = _state[7];
            fixed (byte* start = &data[offset])
            fixed (uint* w = _w)
            fixed (uint* t = T)
            {
                uint* input = (uint*)start;
                for (int block = 0; block < blocks; block++, input += 16)
                {
                    for (int i = 0; i < 16; i++)
                    {
                        w[i] = Binary.Swap(input[i]);
                    }
                    for (int j = 16; j < 68; j++)
                    {
                        uint x = w[j - 16] ^ w[j - 9] ^ Binary.RotL(w[j - 3], 15);
                        x = x ^ ((x << 15) | (x >> 17)) ^ ((x << 23) | (x >> 9));
                        w[j] = x ^ Binary.RotL(w[j - 13], 7) ^ w[j - 6];
                    }

                    uint a = s0, b = s1, c = s2, d = s3, e = s4, f = s5, g = s6, h = s7;
                    for (int j = 0; j < 16; j++)
                    {
                        uint a12 = (a << 12) | (a >> 20);
                        uint sum = a12 + e + t[j];
                        uint ss1 = (sum << 7) | (sum >> 25);
                        uint tt1 = (a ^ b ^ c) + d + (ss1 ^ a12) + (w[j] ^ w[j + 4]);
                        uint tt2 = (e ^ f ^ g) + h + ss1 + w[j];
                        d = c;
                        c = (b << 9) | (b >> 23);
                        b = a;
                        a = tt1;
                        h = g;
                        g = (f << 19) | (f >> 13);
                        f = e;
                        e = tt2 ^ ((tt2 << 9) | (tt2 >> 23)) ^ ((tt2 << 17) | (tt2 >> 15));
                    }
                    for (int j = 16; j < 64; j++)
                    {
                        uint a12 = (a << 12) | (a >> 20);
                        uint sum = a12 + e + t[j];
                        uint ss1 = (sum << 7) | (sum >> 25);
                        uint tt1 = ((a & b) | (c & (a | b))) + d + (ss1 ^ a12) + (w[j] ^ w[j + 4]);
                        uint tt2 = (g ^ (e & (f ^ g))) + h + ss1 + w[j];
                        d = c;
                        c = (b << 9) | (b >> 23);
                        b = a;
                        a = tt1;
                        h = g;
                        g = (f << 19) | (f >> 13);
                        f = e;
                        e = tt2 ^ ((tt2 << 9) | (tt2 >> 23)) ^ ((tt2 << 17) | (tt2 >> 15));
                    }

                    s0 ^= a;
                    s1 ^= b;
                    s2 ^= c;
                    s3 ^= d;
                    s4 ^= e;
                    s5 ^= f;
                    s6 ^= g;
                    s7 ^= h;
                }
            }
            _state[0] = s0;
            _state[1] = s1;
            _state[2] = s2;
            _state[3] = s3;
            _state[4] = s4;
            _state[5] = s5;
            _state[6] = s6;
            _state[7] = s7;
        }

        private static uint[] BuildT()
        {
            uint[] table = new uint[64];
            for (int j = 0; j < 64; j++)
            {
                uint value = j < 16 ? 0x79CC4519u : 0x7A879D8Au;
                table[j] = Binary.RotL(value, j);
            }
            return table;
        }
    }
}
