namespace HashTool.Hashing
{
    public sealed class Sha3Hash : HashFunction
    {
        private static readonly ulong[] RoundConstants = new ulong[]
        {
            0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
            0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
            0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
            0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
        };

        private readonly int _bits;
        private readonly int _rate;
        private readonly ulong[] _state = new ulong[25];
        private readonly byte[] _buffer;
        private readonly BlockProcessor _process;
        private int _filled;

        public Sha3Hash(int bits)
        {
            _bits = bits;
            _rate = (1600 - 2 * bits) / 8;
            _buffer = new byte[_rate];
            _process = AbsorbBlocks;
        }

        public override string Name { get { return "SHA3-" + _bits; } }

        public override string Group { get { return "SHA-3"; } }

        public override void Initialize()
        {
            for (int i = 0; i < _state.Length; i++)
            {
                _state[i] = 0;
            }
            _filled = 0;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            Absorb(_buffer, ref _filled, _rate, data, offset, count, _process);
        }

        public override byte[] FinalizeHash()
        {
            for (int i = _filled; i < _rate; i++)
            {
                _buffer[i] = 0;
            }
            _buffer[_filled] = 0x06;
            _buffer[_rate - 1] |= 0x80;
            AbsorbBlocks(_buffer, 0, 1);

            byte[] result = new byte[_bits / 8];
            int produced = 0;
            while (produced < result.Length)
            {
                int take = _rate < result.Length - produced ? _rate : result.Length - produced;
                for (int i = 0; i < take; i++)
                {
                    result[produced + i] = (byte)(_state[i / 8] >> (8 * (i % 8)));
                }
                produced += take;
                if (produced < result.Length)
                {
                    KeccakF(_state);
                }
            }
            return result;
        }

        private unsafe void AbsorbBlocks(byte[] data, int offset, int blocks)
        {
            int lanes = _rate / 8;
            fixed (byte* start = &data[offset])
            fixed (ulong* state = _state)
            {
                ulong* input = (ulong*)start;
                for (int block = 0; block < blocks; block++, input += lanes)
                {
                    for (int i = 0; i < lanes; i++)
                    {
                        state[i] ^= input[i];
                    }
                    KeccakF(_state);
                }
            }
        }

        private static void KeccakF(ulong[] state)
        {
            ulong a0 = state[0], a1 = state[1], a2 = state[2], a3 = state[3], a4 = state[4];
            ulong a5 = state[5], a6 = state[6], a7 = state[7], a8 = state[8], a9 = state[9];
            ulong a10 = state[10], a11 = state[11], a12 = state[12], a13 = state[13], a14 = state[14];
            ulong a15 = state[15], a16 = state[16], a17 = state[17], a18 = state[18], a19 = state[19];
            ulong a20 = state[20], a21 = state[21], a22 = state[22], a23 = state[23], a24 = state[24];

            for (int round = 0; round < 24; round++)
            {
                ulong c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
                ulong c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
                ulong c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
                ulong c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;
                ulong c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;
                ulong d0 = c4 ^ ((c1 << 1) | (c1 >> 63));
                ulong d1 = c0 ^ ((c2 << 1) | (c2 >> 63));
                ulong d2 = c1 ^ ((c3 << 1) | (c3 >> 63));
                ulong d3 = c2 ^ ((c4 << 1) | (c4 >> 63));
                ulong d4 = c3 ^ ((c0 << 1) | (c0 >> 63));
                a0 ^= d0; a5 ^= d0; a10 ^= d0; a15 ^= d0; a20 ^= d0;
                a1 ^= d1; a6 ^= d1; a11 ^= d1; a16 ^= d1; a21 ^= d1;
                a2 ^= d2; a7 ^= d2; a12 ^= d2; a17 ^= d2; a22 ^= d2;
                a3 ^= d3; a8 ^= d3; a13 ^= d3; a18 ^= d3; a23 ^= d3;
                a4 ^= d4; a9 ^= d4; a14 ^= d4; a19 ^= d4; a24 ^= d4;

                ulong b0 = a0;
                ulong b1 = (a6 << 44) | (a6 >> 20);
                ulong b2 = (a12 << 43) | (a12 >> 21);
                ulong b3 = (a18 << 21) | (a18 >> 43);
                ulong b4 = (a24 << 14) | (a24 >> 50);
                ulong b5 = (a3 << 28) | (a3 >> 36);
                ulong b6 = (a9 << 20) | (a9 >> 44);
                ulong b7 = (a10 << 3) | (a10 >> 61);
                ulong b8 = (a16 << 45) | (a16 >> 19);
                ulong b9 = (a22 << 61) | (a22 >> 3);
                ulong b10 = (a1 << 1) | (a1 >> 63);
                ulong b11 = (a7 << 6) | (a7 >> 58);
                ulong b12 = (a13 << 25) | (a13 >> 39);
                ulong b13 = (a19 << 8) | (a19 >> 56);
                ulong b14 = (a20 << 18) | (a20 >> 46);
                ulong b15 = (a4 << 27) | (a4 >> 37);
                ulong b16 = (a5 << 36) | (a5 >> 28);
                ulong b17 = (a11 << 10) | (a11 >> 54);
                ulong b18 = (a17 << 15) | (a17 >> 49);
                ulong b19 = (a23 << 56) | (a23 >> 8);
                ulong b20 = (a2 << 62) | (a2 >> 2);
                ulong b21 = (a8 << 55) | (a8 >> 9);
                ulong b22 = (a14 << 39) | (a14 >> 25);
                ulong b23 = (a15 << 41) | (a15 >> 23);
                ulong b24 = (a21 << 2) | (a21 >> 62);

                a0 = b0 ^ ((~b1) & b2);
                a1 = b1 ^ ((~b2) & b3);
                a2 = b2 ^ ((~b3) & b4);
                a3 = b3 ^ ((~b4) & b0);
                a4 = b4 ^ ((~b0) & b1);
                a5 = b5 ^ ((~b6) & b7);
                a6 = b6 ^ ((~b7) & b8);
                a7 = b7 ^ ((~b8) & b9);
                a8 = b8 ^ ((~b9) & b5);
                a9 = b9 ^ ((~b5) & b6);
                a10 = b10 ^ ((~b11) & b12);
                a11 = b11 ^ ((~b12) & b13);
                a12 = b12 ^ ((~b13) & b14);
                a13 = b13 ^ ((~b14) & b10);
                a14 = b14 ^ ((~b10) & b11);
                a15 = b15 ^ ((~b16) & b17);
                a16 = b16 ^ ((~b17) & b18);
                a17 = b17 ^ ((~b18) & b19);
                a18 = b18 ^ ((~b19) & b15);
                a19 = b19 ^ ((~b15) & b16);
                a20 = b20 ^ ((~b21) & b22);
                a21 = b21 ^ ((~b22) & b23);
                a22 = b22 ^ ((~b23) & b24);
                a23 = b23 ^ ((~b24) & b20);
                a24 = b24 ^ ((~b20) & b21);
                a0 ^= RoundConstants[round];
            }

            state[0] = a0; state[1] = a1; state[2] = a2; state[3] = a3; state[4] = a4;
            state[5] = a5; state[6] = a6; state[7] = a7; state[8] = a8; state[9] = a9;
            state[10] = a10; state[11] = a11; state[12] = a12; state[13] = a13; state[14] = a14;
            state[15] = a15; state[16] = a16; state[17] = a17; state[18] = a18; state[19] = a19;
            state[20] = a20; state[21] = a21; state[22] = a22; state[23] = a23; state[24] = a24;
        }
    }
}
