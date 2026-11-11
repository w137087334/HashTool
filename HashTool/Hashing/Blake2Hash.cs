using System.Threading.Tasks;

namespace HashTool.Hashing
{
    public sealed class Blake2sHash : HashFunction
    {
        private static readonly uint[] Iv = new uint[]
        {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        };

        private static readonly byte[] Sigma = new byte[]
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
            11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
            7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
            9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
            2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
            12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
            13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
            6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
            10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
        };

        private readonly int _digestLength;
        private readonly byte _fanout;
        private readonly byte _depth;
        private readonly uint _nodeOffset;
        private readonly byte _nodeDepth;
        private readonly byte _innerLength;
        private readonly bool _lastNode;
        private readonly int _outputLength;
        private readonly string _name;
        private readonly string _group;
        private readonly uint[] _h = new uint[8];
        private readonly byte[] _buffer = new byte[64];
        private readonly BlockProcessor _process;
        private uint _t0;
        private uint _t1;
        private int _filled;

        public Blake2sHash(int digestBytes)
            : this(digestBytes, digestBytes, 1, 1, 0, 0, 0, false, "Blake2s-" + (digestBytes * 8), "BLAKE2s")
        {
        }

        private Blake2sHash(
            int parameterDigest,
            int outputLength,
            byte fanout,
            byte depth,
            uint nodeOffset,
            byte nodeDepth,
            byte innerLength,
            bool lastNode,
            string name,
            string group)
        {
            _digestLength = parameterDigest;
            _outputLength = outputLength;
            _fanout = fanout;
            _depth = depth;
            _nodeOffset = nodeOffset;
            _nodeDepth = nodeDepth;
            _innerLength = innerLength;
            _lastNode = lastNode;
            _name = name;
            _group = group;
            _process = ProcessBlocks;
        }

        public override string Name { get { return _name; } }

        public override string Group { get { return _group; } }

        public override void Initialize()
        {
            byte[] p = new byte[32];
            p[0] = (byte)_digestLength;
            p[2] = _fanout;
            p[3] = _depth;
            Binary.WriteUInt32LE(p, 8, _nodeOffset);
            p[14] = _nodeDepth;
            p[15] = _innerLength;
            for (int i = 0; i < 8; i++)
            {
                _h[i] = Iv[i] ^ Binary.ReadUInt32LE(p, i * 4);
            }
            _t0 = 0;
            _t1 = 0;
            _filled = 0;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            AbsorbLazy(_buffer, ref _filled, 64, data, offset, count, _process);
        }

        internal void UpdateStrided(byte[] data, int offset, int blocks, int stride)
        {
            if (blocks <= 0)
            {
                return;
            }
            if (_filled != 0 && _filled != 64)
            {
                for (int i = 0; i < blocks; i++)
                {
                    Update(data, offset + i * stride, 64);
                }
                return;
            }
            if (_filled == 64)
            {
                ProcessBlocks(_buffer, 0, 1);
            }
            for (int i = 0; i < blocks - 1; i++)
            {
                ProcessBlocks(data, offset + i * stride, 1);
            }
            System.Buffer.BlockCopy(data, offset + (blocks - 1) * stride, _buffer, 0, 64);
            _filled = 64;
        }

        public override byte[] FinalizeHash()
        {
            Increment((uint)_filled);
            for (int i = _filled; i < 64; i++)
            {
                _buffer[i] = 0;
            }
            Compress(_buffer, 0, true);
            byte[] result = new byte[_outputLength];
            for (int i = 0; i < _outputLength; i++)
            {
                result[i] = (byte)(_h[i / 4] >> (8 * (i % 4)));
            }
            return result;
        }

        private void ProcessBlocks(byte[] data, int offset, int blocks)
        {
            for (int i = 0; i < blocks; i++)
            {
                Increment(64);
                Compress(data, offset + i * 64, false);
            }
        }

        private void Increment(uint count)
        {
            uint low = _t0 + count;
            if (low < _t0)
            {
                _t1++;
            }
            _t0 = low;
        }

        private unsafe void Compress(byte[] block, int offset, bool last)
        {
            fixed (byte* start = &block[offset])
            fixed (uint* h = _h)
            fixed (byte* sigmaTable = Sigma)
            {
                uint* m = (uint*)start;
                uint v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3];
                uint v4 = h[4], v5 = h[5], v6 = h[6], v7 = h[7];
                uint v8 = 0x6A09E667, v9 = 0xBB67AE85, v10 = 0x3C6EF372, v11 = 0xA54FF53A;
                uint v12 = 0x510E527F ^ _t0, v13 = 0x9B05688C ^ _t1, v14 = 0x1F83D9AB, v15 = 0x5BE0CD19;
                if (last)
                {
                    v14 = ~v14;
                    if (_lastNode)
                    {
                        v15 = ~v15;
                    }
                }

                for (int round = 0; round < 10; round++)
                {
                    byte* s = sigmaTable + (round << 4);
                    uint t;

                    v0 += v4 + m[s[0]]; t = v12 ^ v0; v12 = (t >> 16) | (t << 16); v8 += v12; t = v4 ^ v8; v4 = (t >> 12) | (t << 20);
                    v0 += v4 + m[s[1]]; t = v12 ^ v0; v12 = (t >> 8) | (t << 24); v8 += v12; t = v4 ^ v8; v4 = (t >> 7) | (t << 25);
                    v1 += v5 + m[s[2]]; t = v13 ^ v1; v13 = (t >> 16) | (t << 16); v9 += v13; t = v5 ^ v9; v5 = (t >> 12) | (t << 20);
                    v1 += v5 + m[s[3]]; t = v13 ^ v1; v13 = (t >> 8) | (t << 24); v9 += v13; t = v5 ^ v9; v5 = (t >> 7) | (t << 25);
                    v2 += v6 + m[s[4]]; t = v14 ^ v2; v14 = (t >> 16) | (t << 16); v10 += v14; t = v6 ^ v10; v6 = (t >> 12) | (t << 20);
                    v2 += v6 + m[s[5]]; t = v14 ^ v2; v14 = (t >> 8) | (t << 24); v10 += v14; t = v6 ^ v10; v6 = (t >> 7) | (t << 25);
                    v3 += v7 + m[s[6]]; t = v15 ^ v3; v15 = (t >> 16) | (t << 16); v11 += v15; t = v7 ^ v11; v7 = (t >> 12) | (t << 20);
                    v3 += v7 + m[s[7]]; t = v15 ^ v3; v15 = (t >> 8) | (t << 24); v11 += v15; t = v7 ^ v11; v7 = (t >> 7) | (t << 25);

                    v0 += v5 + m[s[8]]; t = v15 ^ v0; v15 = (t >> 16) | (t << 16); v10 += v15; t = v5 ^ v10; v5 = (t >> 12) | (t << 20);
                    v0 += v5 + m[s[9]]; t = v15 ^ v0; v15 = (t >> 8) | (t << 24); v10 += v15; t = v5 ^ v10; v5 = (t >> 7) | (t << 25);
                    v1 += v6 + m[s[10]]; t = v12 ^ v1; v12 = (t >> 16) | (t << 16); v11 += v12; t = v6 ^ v11; v6 = (t >> 12) | (t << 20);
                    v1 += v6 + m[s[11]]; t = v12 ^ v1; v12 = (t >> 8) | (t << 24); v11 += v12; t = v6 ^ v11; v6 = (t >> 7) | (t << 25);
                    v2 += v7 + m[s[12]]; t = v13 ^ v2; v13 = (t >> 16) | (t << 16); v8 += v13; t = v7 ^ v8; v7 = (t >> 12) | (t << 20);
                    v2 += v7 + m[s[13]]; t = v13 ^ v2; v13 = (t >> 8) | (t << 24); v8 += v13; t = v7 ^ v8; v7 = (t >> 7) | (t << 25);
                    v3 += v4 + m[s[14]]; t = v14 ^ v3; v14 = (t >> 16) | (t << 16); v9 += v14; t = v4 ^ v9; v4 = (t >> 12) | (t << 20);
                    v3 += v4 + m[s[15]]; t = v14 ^ v3; v14 = (t >> 8) | (t << 24); v9 += v14; t = v4 ^ v9; v4 = (t >> 7) | (t << 25);
                }

                h[0] ^= v0 ^ v8;
                h[1] ^= v1 ^ v9;
                h[2] ^= v2 ^ v10;
                h[3] ^= v3 ^ v11;
                h[4] ^= v4 ^ v12;
                h[5] ^= v5 ^ v13;
                h[6] ^= v6 ^ v14;
                h[7] ^= v7 ^ v15;
            }
        }

        internal static Blake2sHash Leaf(int digestBytes, uint node)
        {
            return new Blake2sHash(digestBytes, 32, 8, 2, node, 0, 32, node == 7, "leaf", "BLAKE2sp");
        }

        internal static Blake2sHash Root(int digestBytes)
        {
            return new Blake2sHash(digestBytes, digestBytes, 8, 2, 0, 1, 32, true, "root", "BLAKE2sp");
        }
    }

    public sealed class Blake2bHash : HashFunction
    {
        private static readonly ulong[] Iv = new ulong[]
        {
            0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
            0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
        };

        private static readonly byte[] Sigma = new byte[]
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
            11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
            7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
            9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
            2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
            12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
            13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
            6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
            10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
        };

        private readonly int _digestLength;
        private readonly byte _fanout;
        private readonly byte _depth;
        private readonly uint _nodeOffset;
        private readonly byte _nodeDepth;
        private readonly byte _innerLength;
        private readonly bool _lastNode;
        private readonly int _outputLength;
        private readonly string _name;
        private readonly string _group;
        private readonly ulong[] _h = new ulong[8];
        private readonly byte[] _buffer = new byte[128];
        private readonly BlockProcessor _process;
        private ulong _t0;
        private ulong _t1;
        private int _filled;

        public Blake2bHash(int digestBytes)
            : this(digestBytes, digestBytes, 1, 1, 0, 0, 0, false, "Blake2b-" + (digestBytes * 8), "BLAKE2b")
        {
        }

        private Blake2bHash(
            int parameterDigest,
            int outputLength,
            byte fanout,
            byte depth,
            uint nodeOffset,
            byte nodeDepth,
            byte innerLength,
            bool lastNode,
            string name,
            string group)
        {
            _digestLength = parameterDigest;
            _outputLength = outputLength;
            _fanout = fanout;
            _depth = depth;
            _nodeOffset = nodeOffset;
            _nodeDepth = nodeDepth;
            _innerLength = innerLength;
            _lastNode = lastNode;
            _name = name;
            _group = group;
            _process = ProcessBlocks;
        }

        public override string Name { get { return _name; } }

        public override string Group { get { return _group; } }

        public override void Initialize()
        {
            byte[] p = new byte[64];
            p[0] = (byte)_digestLength;
            p[2] = _fanout;
            p[3] = _depth;
            Binary.WriteUInt32LE(p, 8, _nodeOffset);
            p[16] = _nodeDepth;
            p[17] = _innerLength;
            for (int i = 0; i < 8; i++)
            {
                _h[i] = Iv[i] ^ Binary.ReadUInt64LE(p, i * 8);
            }
            _t0 = 0;
            _t1 = 0;
            _filled = 0;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            AbsorbLazy(_buffer, ref _filled, 128, data, offset, count, _process);
        }

        internal void UpdateStrided(byte[] data, int offset, int blocks, int stride)
        {
            if (blocks <= 0)
            {
                return;
            }
            if (_filled != 0 && _filled != 128)
            {
                for (int i = 0; i < blocks; i++)
                {
                    Update(data, offset + i * stride, 128);
                }
                return;
            }
            if (_filled == 128)
            {
                ProcessBlocks(_buffer, 0, 1);
            }
            for (int i = 0; i < blocks - 1; i++)
            {
                ProcessBlocks(data, offset + i * stride, 1);
            }
            System.Buffer.BlockCopy(data, offset + (blocks - 1) * stride, _buffer, 0, 128);
            _filled = 128;
        }

        public override byte[] FinalizeHash()
        {
            Increment((ulong)_filled);
            for (int i = _filled; i < 128; i++)
            {
                _buffer[i] = 0;
            }
            Compress(_buffer, 0, true);
            byte[] result = new byte[_outputLength];
            for (int i = 0; i < _outputLength; i++)
            {
                result[i] = (byte)(_h[i / 8] >> (8 * (i % 8)));
            }
            return result;
        }

        private void ProcessBlocks(byte[] data, int offset, int blocks)
        {
            for (int i = 0; i < blocks; i++)
            {
                Increment(128);
                Compress(data, offset + i * 128, false);
            }
        }

        private void Increment(ulong count)
        {
            ulong low = _t0 + count;
            if (low < _t0)
            {
                _t1++;
            }
            _t0 = low;
        }

        private unsafe void Compress(byte[] block, int offset, bool last)
        {
            fixed (byte* start = &block[offset])
            fixed (ulong* h = _h)
            fixed (byte* sigmaTable = Sigma)
            {
                ulong* m = (ulong*)start;
                ulong v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3];
                ulong v4 = h[4], v5 = h[5], v6 = h[6], v7 = h[7];
                ulong v8 = 0x6A09E667F3BCC908UL, v9 = 0xBB67AE8584CAA73BUL, v10 = 0x3C6EF372FE94F82BUL, v11 = 0xA54FF53A5F1D36F1UL;
                ulong v12 = 0x510E527FADE682D1UL ^ _t0, v13 = 0x9B05688C2B3E6C1FUL ^ _t1;
                ulong v14 = 0x1F83D9ABFB41BD6BUL, v15 = 0x5BE0CD19137E2179UL;
                if (last)
                {
                    v14 = ~v14;
                    if (_lastNode)
                    {
                        v15 = ~v15;
                    }
                }

                for (int round = 0; round < 12; round++)
                {
                    byte* s = sigmaTable + (round << 4);
                    ulong t;

                    v0 += v4 + m[s[0]]; t = v12 ^ v0; v12 = (t >> 32) | (t << 32); v8 += v12; t = v4 ^ v8; v4 = (t >> 24) | (t << 40);
                    v0 += v4 + m[s[1]]; t = v12 ^ v0; v12 = (t >> 16) | (t << 48); v8 += v12; t = v4 ^ v8; v4 = (t >> 63) | (t << 1);
                    v1 += v5 + m[s[2]]; t = v13 ^ v1; v13 = (t >> 32) | (t << 32); v9 += v13; t = v5 ^ v9; v5 = (t >> 24) | (t << 40);
                    v1 += v5 + m[s[3]]; t = v13 ^ v1; v13 = (t >> 16) | (t << 48); v9 += v13; t = v5 ^ v9; v5 = (t >> 63) | (t << 1);
                    v2 += v6 + m[s[4]]; t = v14 ^ v2; v14 = (t >> 32) | (t << 32); v10 += v14; t = v6 ^ v10; v6 = (t >> 24) | (t << 40);
                    v2 += v6 + m[s[5]]; t = v14 ^ v2; v14 = (t >> 16) | (t << 48); v10 += v14; t = v6 ^ v10; v6 = (t >> 63) | (t << 1);
                    v3 += v7 + m[s[6]]; t = v15 ^ v3; v15 = (t >> 32) | (t << 32); v11 += v15; t = v7 ^ v11; v7 = (t >> 24) | (t << 40);
                    v3 += v7 + m[s[7]]; t = v15 ^ v3; v15 = (t >> 16) | (t << 48); v11 += v15; t = v7 ^ v11; v7 = (t >> 63) | (t << 1);

                    v0 += v5 + m[s[8]]; t = v15 ^ v0; v15 = (t >> 32) | (t << 32); v10 += v15; t = v5 ^ v10; v5 = (t >> 24) | (t << 40);
                    v0 += v5 + m[s[9]]; t = v15 ^ v0; v15 = (t >> 16) | (t << 48); v10 += v15; t = v5 ^ v10; v5 = (t >> 63) | (t << 1);
                    v1 += v6 + m[s[10]]; t = v12 ^ v1; v12 = (t >> 32) | (t << 32); v11 += v12; t = v6 ^ v11; v6 = (t >> 24) | (t << 40);
                    v1 += v6 + m[s[11]]; t = v12 ^ v1; v12 = (t >> 16) | (t << 48); v11 += v12; t = v6 ^ v11; v6 = (t >> 63) | (t << 1);
                    v2 += v7 + m[s[12]]; t = v13 ^ v2; v13 = (t >> 32) | (t << 32); v8 += v13; t = v7 ^ v8; v7 = (t >> 24) | (t << 40);
                    v2 += v7 + m[s[13]]; t = v13 ^ v2; v13 = (t >> 16) | (t << 48); v8 += v13; t = v7 ^ v8; v7 = (t >> 63) | (t << 1);
                    v3 += v4 + m[s[14]]; t = v14 ^ v3; v14 = (t >> 32) | (t << 32); v9 += v14; t = v4 ^ v9; v4 = (t >> 24) | (t << 40);
                    v3 += v4 + m[s[15]]; t = v14 ^ v3; v14 = (t >> 16) | (t << 48); v9 += v14; t = v4 ^ v9; v4 = (t >> 63) | (t << 1);
                }

                h[0] ^= v0 ^ v8;
                h[1] ^= v1 ^ v9;
                h[2] ^= v2 ^ v10;
                h[3] ^= v3 ^ v11;
                h[4] ^= v4 ^ v12;
                h[5] ^= v5 ^ v13;
                h[6] ^= v6 ^ v14;
                h[7] ^= v7 ^ v15;
            }
        }

        internal static Blake2bHash Leaf(int digestBytes, uint node)
        {
            return new Blake2bHash(digestBytes, 64, 4, 2, node, 0, 64, node == 3, "leaf", "BLAKE2bp");
        }

        internal static Blake2bHash Root(int digestBytes)
        {
            return new Blake2bHash(digestBytes, digestBytes, 4, 2, 0, 1, 64, true, "root", "BLAKE2bp");
        }
    }

    public sealed class Blake2spHash : HashFunction
    {
        private const int ParallelThreshold = 64;

        private readonly int _digestBytes;
        private readonly Blake2sHash[] _leaves = new Blake2sHash[8];
        private readonly byte[] _buffer = new byte[512];
        private readonly BlockProcessor _process;
        private int _filled;

        public Blake2spHash(int digestBytes)
        {
            _digestBytes = digestBytes;
            _process = ProcessBlocks;
        }

        public override string Name { get { return "Blake2sp-" + (_digestBytes * 8); } }

        public override string Group { get { return "BLAKE2sp"; } }

        public override void Initialize()
        {
            for (int i = 0; i < 8; i++)
            {
                _leaves[i] = Blake2sHash.Leaf(_digestBytes, (uint)i);
                _leaves[i].Initialize();
            }
            _filled = 0;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            Absorb(_buffer, ref _filled, 512, data, offset, count, _process);
        }

        private void ProcessBlocks(byte[] data, int offset, int blocks)
        {
            if (blocks >= ParallelThreshold)
            {
                Parallel.For(0, 8, delegate(int i)
                {
                    _leaves[i].UpdateStrided(data, offset + i * 64, blocks, 512);
                });
                return;
            }
            for (int i = 0; i < 8; i++)
            {
                _leaves[i].UpdateStrided(data, offset + i * 64, blocks, 512);
            }
        }

        public override byte[] FinalizeHash()
        {
            for (int i = 0; i < 8; i++)
            {
                if (_filled > i * 64)
                {
                    int left = _filled - i * 64;
                    if (left > 64)
                    {
                        left = 64;
                    }
                    _leaves[i].Update(_buffer, i * 64, left);
                }
            }

            Blake2sHash root = Blake2sHash.Root(_digestBytes);
            root.Initialize();
            for (int i = 0; i < 8; i++)
            {
                byte[] leaf = _leaves[i].FinalizeHash();
                root.Update(leaf, 0, leaf.Length);
            }
            return root.FinalizeHash();
        }
    }

    public sealed class Blake2bpHash : HashFunction
    {
        private const int ParallelThreshold = 64;

        private readonly int _digestBytes;
        private readonly Blake2bHash[] _leaves = new Blake2bHash[4];
        private readonly byte[] _buffer = new byte[512];
        private readonly BlockProcessor _process;
        private int _filled;

        public Blake2bpHash(int digestBytes)
        {
            _digestBytes = digestBytes;
            _process = ProcessBlocks;
        }

        public override string Name { get { return "Blake2bp-" + (_digestBytes * 8); } }

        public override string Group { get { return "BLAKE2bp"; } }

        public override void Initialize()
        {
            for (int i = 0; i < 4; i++)
            {
                _leaves[i] = Blake2bHash.Leaf(_digestBytes, (uint)i);
                _leaves[i].Initialize();
            }
            _filled = 0;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            Absorb(_buffer, ref _filled, 512, data, offset, count, _process);
        }

        private void ProcessBlocks(byte[] data, int offset, int blocks)
        {
            if (blocks >= ParallelThreshold)
            {
                Parallel.For(0, 4, delegate(int i)
                {
                    _leaves[i].UpdateStrided(data, offset + i * 128, blocks, 512);
                });
                return;
            }
            for (int i = 0; i < 4; i++)
            {
                _leaves[i].UpdateStrided(data, offset + i * 128, blocks, 512);
            }
        }

        public override byte[] FinalizeHash()
        {
            for (int i = 0; i < 4; i++)
            {
                if (_filled > i * 128)
                {
                    int left = _filled - i * 128;
                    if (left > 128)
                    {
                        left = 128;
                    }
                    _leaves[i].Update(_buffer, i * 128, left);
                }
            }

            Blake2bHash root = Blake2bHash.Root(_digestBytes);
            root.Initialize();
            for (int i = 0; i < 4; i++)
            {
                byte[] leaf = _leaves[i].FinalizeHash();
                root.Update(leaf, 0, leaf.Length);
            }
            return root.FinalizeHash();
        }
    }
}
