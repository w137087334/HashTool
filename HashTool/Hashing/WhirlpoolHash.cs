namespace HashTool.Hashing
{
    public sealed class WhirlpoolHash : HashFunction
    {
        private static readonly byte[] SBox = Binary.HexToBytes(
            "1823C6E887B8014F36A6D2F5796F9152" +
            "60BC9B8EA30C7B351DE0D7C22E4BFE57" +
            "157737E59FF04ADA58C9290AB1A06B85" +
            "BD5D10F4CB3E0567E427418BA77D95D8" +
            "FBEE7C66DD17479ECA2DBF07AD5A8333" +
            "6302AA71C81949D9F2E35B889A2632B0" +
            "E90FD580BECD3448FF7A905F20681AAE" +
            "B454932264F173124008C3ECDBA18D3D" +
            "9700CF2B7682D61BB5AF6A5045F330EF" +
            "3F55A2EA65BA2FC0DE1CFD4D9275068A" +
            "B2E60E1F62D4A896F9C525598472394C" +
            "5E78388CD1A5E261B3219C1E43C7FC04" +
            "51996D0DFADF7E243BABCE118F4EB7EB" +
            "3C8194F7B9132CD3E76EC40356447FA9" +
            "2ABBC153DC0B9D6C3174F646AC8914E1" +
            "163A690970B6D0EDCC4298A4285CF886");

        private static readonly int[] Mix = new int[] { 1, 1, 4, 1, 8, 5, 2, 9 };
        private static readonly byte[][] Mul = BuildMul();
        private static readonly ulong[] RoundWords = BuildRoundWords();
        private static readonly ulong[] RoundConstants = BuildRoundConstants();

        private readonly byte[] _buffer = new byte[64];
        private readonly ulong[] _hash = new ulong[8];
        private readonly ulong[] _scratch = new ulong[16];
        private readonly BlockProcessor _process;
        private int _filled;
        private ulong _lengthHigh;
        private ulong _lengthLow;

        public WhirlpoolHash()
        {
            _process = ProcessBlocks;
        }

        public override string Name { get { return "Whirlpool"; } }

        public override string Group { get { return "其他"; } }

        public override void Initialize()
        {
            for (int i = 0; i < 8; i++)
            {
                _hash[i] = 0;
            }
            _filled = 0;
            _lengthHigh = 0;
            _lengthLow = 0;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            Absorb(_buffer, ref _filled, 64, data, offset, count, _process);
            AddLength((ulong)count);
        }

        public override byte[] FinalizeHash()
        {
            byte[] length = new byte[32];
            Binary.WriteUInt64BE(length, 16, _lengthHigh);
            Binary.WriteUInt64BE(length, 24, _lengthLow);
            int filled = _filled;
            int pad = filled < 32 ? 64 - filled : 128 - filled;
            byte[] tail = new byte[pad];
            tail[0] = 0x80;
            System.Buffer.BlockCopy(length, 0, tail, tail.Length - 32, 32);
            Absorb(_buffer, ref _filled, 64, tail, 0, tail.Length, _process);

            byte[] result = new byte[64];
            for (int i = 0; i < 8; i++)
            {
                ulong lane = _hash[i];
                int at = i << 3;
                result[at] = (byte)lane;
                result[at + 1] = (byte)(lane >> 8);
                result[at + 2] = (byte)(lane >> 16);
                result[at + 3] = (byte)(lane >> 24);
                result[at + 4] = (byte)(lane >> 32);
                result[at + 5] = (byte)(lane >> 40);
                result[at + 6] = (byte)(lane >> 48);
                result[at + 7] = (byte)(lane >> 56);
            }
            return result;
        }

        private void AddLength(ulong bytes)
        {
            ulong bitsLow = bytes << 3;
            ulong bitsHigh = bytes >> 61;
            _lengthLow += bitsLow;
            if (_lengthLow < bitsLow)
            {
                bitsHigh++;
            }
            _lengthHigh += bitsHigh;
        }

        private unsafe void ProcessBlocks(byte[] data, int offset, int blocks)
        {
            fixed (byte* start = &data[offset])
            fixed (ulong* hash = _hash, scratch = _scratch, table = RoundWords, constants = RoundConstants)
            {
                ulong* key = scratch;
                ulong* state = scratch + 8;
                ulong* message = (ulong*)start;
                for (int block = 0; block < blocks; block++, message += 8)
                {
                    for (int i = 0; i < 8; i++)
                    {
                        key[i] = hash[i];
                        state[i] = message[i] ^ hash[i];
                    }

                    for (int round = 0; round < 10; round++)
                    {
                        Round(key, table);
                        key[0] ^= constants[round];
                        Round(state, table);
                        for (int i = 0; i < 8; i++)
                        {
                            state[i] ^= key[i];
                        }
                    }

                    for (int i = 0; i < 8; i++)
                    {
                        hash[i] ^= state[i] ^ message[i];
                    }
                }
            }
        }

        private static unsafe void Round(ulong* block, ulong* t)
        {
            ulong b0 = block[0], b1 = block[1], b2 = block[2], b3 = block[3];
            ulong b4 = block[4], b5 = block[5], b6 = block[6], b7 = block[7];
            block[0] = t[(byte)b0] ^ t[256 + (byte)(b7 >> 8)] ^ t[512 + (byte)(b6 >> 16)] ^ t[768 + (byte)(b5 >> 24)]
                ^ t[1024 + (byte)(b4 >> 32)] ^ t[1280 + (byte)(b3 >> 40)] ^ t[1536 + (byte)(b2 >> 48)] ^ t[1792 + (byte)(b1 >> 56)];
            block[1] = t[(byte)b1] ^ t[256 + (byte)(b0 >> 8)] ^ t[512 + (byte)(b7 >> 16)] ^ t[768 + (byte)(b6 >> 24)]
                ^ t[1024 + (byte)(b5 >> 32)] ^ t[1280 + (byte)(b4 >> 40)] ^ t[1536 + (byte)(b3 >> 48)] ^ t[1792 + (byte)(b2 >> 56)];
            block[2] = t[(byte)b2] ^ t[256 + (byte)(b1 >> 8)] ^ t[512 + (byte)(b0 >> 16)] ^ t[768 + (byte)(b7 >> 24)]
                ^ t[1024 + (byte)(b6 >> 32)] ^ t[1280 + (byte)(b5 >> 40)] ^ t[1536 + (byte)(b4 >> 48)] ^ t[1792 + (byte)(b3 >> 56)];
            block[3] = t[(byte)b3] ^ t[256 + (byte)(b2 >> 8)] ^ t[512 + (byte)(b1 >> 16)] ^ t[768 + (byte)(b0 >> 24)]
                ^ t[1024 + (byte)(b7 >> 32)] ^ t[1280 + (byte)(b6 >> 40)] ^ t[1536 + (byte)(b5 >> 48)] ^ t[1792 + (byte)(b4 >> 56)];
            block[4] = t[(byte)b4] ^ t[256 + (byte)(b3 >> 8)] ^ t[512 + (byte)(b2 >> 16)] ^ t[768 + (byte)(b1 >> 24)]
                ^ t[1024 + (byte)(b0 >> 32)] ^ t[1280 + (byte)(b7 >> 40)] ^ t[1536 + (byte)(b6 >> 48)] ^ t[1792 + (byte)(b5 >> 56)];
            block[5] = t[(byte)b5] ^ t[256 + (byte)(b4 >> 8)] ^ t[512 + (byte)(b3 >> 16)] ^ t[768 + (byte)(b2 >> 24)]
                ^ t[1024 + (byte)(b1 >> 32)] ^ t[1280 + (byte)(b0 >> 40)] ^ t[1536 + (byte)(b7 >> 48)] ^ t[1792 + (byte)(b6 >> 56)];
            block[6] = t[(byte)b6] ^ t[256 + (byte)(b5 >> 8)] ^ t[512 + (byte)(b4 >> 16)] ^ t[768 + (byte)(b3 >> 24)]
                ^ t[1024 + (byte)(b2 >> 32)] ^ t[1280 + (byte)(b1 >> 40)] ^ t[1536 + (byte)(b0 >> 48)] ^ t[1792 + (byte)(b7 >> 56)];
            block[7] = t[(byte)b7] ^ t[256 + (byte)(b6 >> 8)] ^ t[512 + (byte)(b5 >> 16)] ^ t[768 + (byte)(b4 >> 24)]
                ^ t[1024 + (byte)(b3 >> 32)] ^ t[1280 + (byte)(b2 >> 40)] ^ t[1536 + (byte)(b1 >> 48)] ^ t[1792 + (byte)(b0 >> 56)];
        }

        private static ulong[] BuildRoundConstants()
        {
            ulong[] constants = new ulong[10];
            for (int round = 0; round < 10; round++)
            {
                ulong lane = 0;
                for (int column = 0; column < 8; column++)
                {
                    lane |= (ulong)SBox[8 * round + column] << (8 * column);
                }
                constants[round] = lane;
            }
            return constants;
        }

        private static byte[][] BuildMul()
        {
            byte[][] table = new byte[10][];
            for (int i = 0; i < table.Length; i++)
            {
                table[i] = new byte[256];
            }
            int[] coefficients = new int[] { 1, 2, 4, 5, 8, 9 };
            for (int c = 0; c < coefficients.Length; c++)
            {
                int coefficient = coefficients[c];
                for (int value = 0; value < 256; value++)
                {
                    table[coefficient][value] = GfMul((byte)coefficient, (byte)value);
                }
            }
            return table;
        }

        private static ulong[] BuildRoundWords()
        {
            ulong[] table = new ulong[8 * 256];
            for (int column = 0; column < 8; column++)
            {
                for (int value = 0; value < 256; value++)
                {
                    int substituted = SBox[value];
                    ulong packed = 0;
                    for (int output = 0; output < 8; output++)
                    {
                        packed |= (ulong)Mul[Mix[(8 + output - column) & 7]][substituted] << (8 * output);
                    }
                    table[(column << 8) | value] = packed;
                }
            }
            return table;
        }

        private static byte GfMul(byte left, byte right)
        {
            int result = 0;
            int a = left;
            int b = right;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                {
                    result ^= a;
                }
                bool high = (a & 0x80) != 0;
                a = (a << 1) & 0xFF;
                if (high)
                {
                    a ^= 0x1D;
                }
                b >>= 1;
            }
            return (byte)result;
        }
    }
}
