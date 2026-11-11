namespace HashTool.Hashing
{
    public sealed class StreebogHash : HashFunction
    {
        private static readonly byte[] Pi = new byte[]
        {
            252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
            233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
            249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
            5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
            235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
            181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
            21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
            50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
            223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
            224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
            167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
            173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
            7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
            225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
            32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
            89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
        };

        private static readonly ulong[] Rows = new ulong[]
        {
            0x8e20faa72ba0b470UL, 0x47107ddd9b505a38UL, 0xad08b0e0c3282d1cUL, 0xd8045870ef14980eUL,
            0x6c022c38f90a4c07UL, 0x3601161cf205268dUL, 0x1b8e0b0e798c13c8UL, 0x83478b07b2468764UL,
            0xa011d380818e8f40UL, 0x5086e740ce47c920UL, 0x2843fd2067adea10UL, 0x14aff010bdd87508UL,
            0x0ad97808d06cb404UL, 0x05e23c0468365a02UL, 0x8c711e02341b2d01UL, 0x46b60f011a83988eUL,
            0x90dab52a387ae76fUL, 0x486dd4151c3dfdb9UL, 0x24b86a840e90f0d2UL, 0x125c354207487869UL,
            0x092e94218d243cbaUL, 0x8a174a9ec8121e5dUL, 0x4585254f64090fa0UL, 0xaccc9ca9328a8950UL,
            0x9d4df05d5f661451UL, 0xc0a878a0a1330aa6UL, 0x60543c50de970553UL, 0x302a1e286fc58ca7UL,
            0x18150f14b9ec46ddUL, 0x0c84890ad27623e0UL, 0x0642ca05693b9f70UL, 0x0321658cba93c138UL,
            0x86275df09ce8aaa8UL, 0x439da0784e745554UL, 0xafc0503c273aa42aUL, 0xd960281e9d1d5215UL,
            0xe230140fc0802984UL, 0x71180a8960409a42UL, 0xb60c05ca30204d21UL, 0x5b068c651810a89eUL,
            0x456c34887a3805b9UL, 0xac361a443d1c8cd2UL, 0x561b0d22900e4669UL, 0x2b838811480723baUL,
            0x9bcf4486248d9f5dUL, 0xc3e9224312c8c1a0UL, 0xeffa11af0964ee50UL, 0xf97d86d98a327728UL,
            0xe4fa2054a80b329cUL, 0x727d102a548b194eUL, 0x39b008152acb8227UL, 0x9258048415eb419dUL,
            0x492c024284fbaec0UL, 0xaa16012142f35760UL, 0x550b8e9e21f7a530UL, 0xa48b474f9ef5dc18UL,
            0x70a6a56e2440598eUL, 0x3853dc371220a247UL, 0x1ca76e95091051adUL, 0x0edd37c48a08a6d8UL,
            0x07e095624504536cUL, 0x8d70c431ac02a736UL, 0xc83862965601dd1bUL, 0x641c314b2b8ee083UL
        };

        private static readonly byte[][] ConstantBytes = new byte[][]
        {
            Reverse("b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507"),
            Reverse("6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7"),
            Reverse("f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2"),
            Reverse("ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e"),
            Reverse("4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbd bfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57".Replace(" ", "")),
            Reverse("ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e"),
            Reverse("f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493"),
            Reverse("9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e"),
            Reverse("378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb"),
            Reverse("abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced"),
            Reverse("7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b"),
            Reverse("378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720")
        };

        private static readonly ulong[] Constants = BuildConstants();
        private static readonly ulong[] Lane = BuildLane();

        private readonly int _bits;
        private readonly byte[] _buffer = new byte[64];
        private readonly ulong[] _h = new ulong[8];
        private readonly ulong[] _n = new ulong[8];
        private readonly ulong[] _sigma = new ulong[8];
        private readonly ulong[] _block = new ulong[8];
        private readonly ulong[] _scratch = new ulong[16];
        private readonly ulong[] _zero = new ulong[8];
        private readonly BlockProcessor _process;
        private int _filled;

        public StreebogHash(int bits)
        {
            _bits = bits;
            _process = ProcessBlocks;
        }

        public override string Name { get { return "Streebog-" + _bits; } }

        public override string Group { get { return "Streebog"; } }

        public override void Initialize()
        {
            ulong fill = _bits == 256 ? 0x0101010101010101UL : 0UL;
            for (int i = 0; i < 8; i++)
            {
                _h[i] = fill;
                _n[i] = 0;
                _sigma[i] = 0;
            }
            _filled = 0;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            Absorb(_buffer, ref _filled, 64, data, offset, count, _process);
        }

        public override unsafe byte[] FinalizeHash()
        {
            LoadPadded(_block);
            fixed (ulong* h = _h, n = _n, sigma = _sigma, block = _block, zero = _zero)
            fixed (ulong* scratch = _scratch, table = Lane, constants = Constants)
            {
                Compress(h, n, sigma, block, (ulong)_filled << 3, scratch, table, constants);
                G(h, zero, n, scratch, table, constants);
                G(h, zero, sigma, scratch, table, constants);
            }

            int size = _bits / 8;
            byte[] result = new byte[size];
            int lane = (64 - size) >> 3;
            for (int i = 0; i < size; i++)
            {
                result[i] = (byte)(_h[lane + (i >> 3)] >> (8 * (i & 7)));
            }
            return result;
        }

        private unsafe void ProcessBlocks(byte[] data, int offset, int blocks)
        {
            fixed (byte* start = &data[offset])
            fixed (ulong* h = _h, n = _n, sigma = _sigma)
            fixed (ulong* scratch = _scratch, table = Lane, constants = Constants)
            {
                ulong* block = (ulong*)start;
                for (int i = 0; i < blocks; i++, block += 8)
                {
                    Compress(h, n, sigma, block, 0x200UL, scratch, table, constants);
                }
            }
        }

        private static unsafe void Compress(ulong* h, ulong* n, ulong* sigma, ulong* block, ulong bitCount, ulong* scratch, ulong* table, ulong* constants)
        {
            G(h, n, block, scratch, table, constants);
            AddSmall(n, bitCount);
            Add(sigma, block);
        }

        private static unsafe void G(ulong* h, ulong* n, ulong* m, ulong* scratch, ulong* table, ulong* constants)
        {
            ulong* k = scratch;
            ulong* s = scratch + 8;
            for (int i = 0; i < 8; i++)
            {
                k[i] = h[i] ^ n[i];
            }
            Lps(k, table);
            for (int i = 0; i < 8; i++)
            {
                s[i] = k[i] ^ m[i];
            }
            for (int round = 0; round < 12; round++)
            {
                Lps(s, table);
                ulong* c = constants + (round << 3);
                for (int i = 0; i < 8; i++)
                {
                    k[i] ^= c[i];
                }
                Lps(k, table);
                for (int i = 0; i < 8; i++)
                {
                    s[i] ^= k[i];
                }
            }
            for (int i = 0; i < 8; i++)
            {
                h[i] ^= s[i] ^ m[i];
            }
        }

        private static unsafe void Lps(ulong* state, ulong* t)
        {
            ulong s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3];
            ulong s4 = state[4], s5 = state[5], s6 = state[6], s7 = state[7];
            for (int i = 0; i < 8; i++)
            {
                int shift = i << 3;
                state[i] = t[(byte)(s0 >> shift)]
                    ^ t[256 + (byte)(s1 >> shift)]
                    ^ t[512 + (byte)(s2 >> shift)]
                    ^ t[768 + (byte)(s3 >> shift)]
                    ^ t[1024 + (byte)(s4 >> shift)]
                    ^ t[1280 + (byte)(s5 >> shift)]
                    ^ t[1536 + (byte)(s6 >> shift)]
                    ^ t[1792 + (byte)(s7 >> shift)];
            }
        }

        private void LoadPadded(ulong[] lanes)
        {
            for (int i = 0; i < 8; i++)
            {
                lanes[i] = 0;
            }
            for (int i = 0; i < _filled; i++)
            {
                lanes[i >> 3] |= (ulong)_buffer[i] << (8 * (i & 7));
            }
            int pad = _filled;
            lanes[pad >> 3] |= 1UL << (8 * (pad & 7));
        }

        private static unsafe void AddSmall(ulong* value, ulong amount)
        {
            ulong sum = value[0] + amount;
            ulong carry = sum < value[0] ? 1UL : 0UL;
            value[0] = sum;
            for (int i = 1; i < 8 && carry != 0; i++)
            {
                sum = value[i] + carry;
                carry = sum < value[i] ? 1UL : 0UL;
                value[i] = sum;
            }
        }

        private static unsafe void Add(ulong* left, ulong* right)
        {
            ulong carry = 0;
            for (int i = 0; i < 8; i++)
            {
                ulong sum = left[i] + right[i];
                ulong next = sum < left[i] ? 1UL : 0UL;
                ulong total = sum + carry;
                next += total < sum ? 1UL : 0UL;
                left[i] = total;
                carry = next;
            }
        }

        private static ulong[] BuildConstants()
        {
            ulong[] lanes = new ulong[12 * 8];
            for (int round = 0; round < 12; round++)
            {
                byte[] constant = ConstantBytes[round];
                for (int lane = 0; lane < 8; lane++)
                {
                    lanes[(round << 3) + lane] = Binary.ReadUInt64LE(constant, lane << 3);
                }
            }
            return lanes;
        }

        private static ulong[] BuildLane()
        {
            ulong[] lane = new ulong[8 * 256];
            for (int row = 0; row < 8; row++)
            {
                for (int value = 0; value < 256; value++)
                {
                    ulong mixed = 0;
                    int substituted = Pi[value];
                    for (int bit = 0; bit < 8; bit++)
                    {
                        if ((substituted & (1 << bit)) != 0)
                        {
                            mixed ^= Rows[63 - (row * 8 + bit)];
                        }
                    }
                    lane[(row << 8) | value] = mixed;
                }
            }
            return lane;
        }

        private static byte[] Reverse(string hex)
        {
            byte[] forward = Binary.HexToBytes(hex);
            byte[] result = new byte[forward.Length];
            for (int i = 0; i < forward.Length; i++)
            {
                result[i] = forward[forward.Length - 1 - i];
            }
            return result;
        }
    }
}
