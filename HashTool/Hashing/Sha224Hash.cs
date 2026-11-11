namespace HashTool.Hashing
{
    public sealed class Sha224Hash : HashFunction
    {
        private static readonly uint[] K = new uint[]
        {
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        };

        private readonly byte[] _buffer = new byte[64];
        private readonly uint[] _state = new uint[8];
        private readonly uint[] _words = new uint[64];
        private readonly BlockProcessor _process;
        private int _filled;
        private ulong _length;

        public Sha224Hash()
        {
            _process = ProcessBlocks;
        }

        public override string Name { get { return "SHA-224"; } }

        public override string Group { get { return "SHA-2"; } }

        public override void Initialize()
        {
            _state[0] = 0xC1059ED8;
            _state[1] = 0x367CD507;
            _state[2] = 0x3070DD17;
            _state[3] = 0xF70E5939;
            _state[4] = 0xFFC00B31;
            _state[5] = 0x68581511;
            _state[6] = 0x64F98FA7;
            _state[7] = 0xBEFA4FA4;
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

            byte[] result = new byte[28];
            for (int i = 0; i < 7; i++)
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
            fixed (uint* w = _words)
            fixed (uint* k = K)
            {
                uint* input = (uint*)start;
                for (int block = 0; block < blocks; block++, input += 16)
                {
                    for (int i = 0; i < 16; i++)
                    {
                        w[i] = Binary.Swap(input[i]);
                    }
                    for (int i = 16; i < 64; i++)
                    {
                        uint x = w[i - 15];
                        uint y = w[i - 2];
                        uint sigma0 = ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
                        uint sigma1 = ((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10);
                        w[i] = w[i - 16] + sigma0 + w[i - 7] + sigma1;
                    }

                    uint a = s0, b = s1, c = s2, d = s3, e = s4, f = s5, g = s6, h = s7;
                    for (int i = 0; i < 64; i++)
                    {
                        uint t1 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7)))
                            + (g ^ (e & (f ^ g))) + k[i] + w[i];
                        uint t2 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10)))
                            + ((a & b) | (c & (a | b)));
                        h = g;
                        g = f;
                        f = e;
                        e = d + t1;
                        d = c;
                        c = b;
                        b = a;
                        a = t1 + t2;
                    }

                    s0 += a;
                    s1 += b;
                    s2 += c;
                    s3 += d;
                    s4 += e;
                    s5 += f;
                    s6 += g;
                    s7 += h;
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
        }    }
}
