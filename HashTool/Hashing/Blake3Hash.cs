using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace HashTool.Hashing
{
    public sealed class Blake3Hash : HashFunction
    {
        private const int ChunkLength = 1024;
        private const int BlockLength = 64;
        private const uint ChunkStart = 1;
        private const uint ChunkEnd = 2;
        private const uint Parent = 4;
        private const uint Root = 8;
        private const int ParallelChunks = 16;

        private const uint Iv0 = 0x6A09E667, Iv1 = 0xBB67AE85, Iv2 = 0x3C6EF372, Iv3 = 0xA54FF53A;
        private const uint Iv4 = 0x510E527F, Iv5 = 0x9B05688C, Iv6 = 0x1F83D9AB, Iv7 = 0x5BE0CD19;

        private static readonly int[] MessagePermutation = new int[]
        {
            2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
        };

        private static readonly byte[] Schedule = BuildSchedule();

        private readonly int _digestBytes;
        private readonly uint[] _cv = new uint[8];
        private readonly byte[] _block = new byte[BlockLength];
        private readonly uint[] _stack = new uint[54 * 8];
        private uint[] _chunkCvs = new uint[0];
        private int _stackLength;
        private int _blockLength;
        private int _blocksCompressed;
        private ulong _chunkCounter;

        public Blake3Hash(int digestBytes)
        {
            _digestBytes = digestBytes;
        }

        public override string Name { get { return "Blake3-" + (_digestBytes * 8); } }

        public override string Group { get { return "BLAKE3"; } }

        public override void Initialize()
        {
            ResetChunk();
            _chunkCounter = 0;
            _stackLength = 0;
        }

        public override unsafe void Update(byte[] data, int offset, int count)
        {
            CheckRange(data, offset, count);
            while (count > 0)
            {
                if (_blocksCompressed * BlockLength + _blockLength == ChunkLength)
                {
                    fixed (uint* cv = _cv)
                    fixed (byte* block = _block)
                    {
                        uint flags = ChunkEnd | (_blocksCompressed == 0 ? ChunkStart : 0);
                        CompressInPlace(cv, (uint*)block, _chunkCounter, BlockLength, flags);
                        PushCv(cv, _chunkCounter + 1);
                    }
                    _chunkCounter++;
                    ResetChunk();
                }

                if (_blocksCompressed == 0 && _blockLength == 0 && count > ChunkLength)
                {
                    int chunks = (count - 1) / ChunkLength;
                    HashChunks(data, offset, chunks);
                    offset += chunks * ChunkLength;
                    count -= chunks * ChunkLength;
                    continue;
                }

                if (_blockLength == BlockLength)
                {
                    fixed (uint* cv = _cv)
                    fixed (byte* block = _block)
                    {
                        uint flags = _blocksCompressed == 0 ? ChunkStart : 0;
                        CompressInPlace(cv, (uint*)block, _chunkCounter, BlockLength, flags);
                    }
                    _blocksCompressed++;
                    _blockLength = 0;
                }

                int want = BlockLength - _blockLength;
                int take = count < want ? count : want;
                System.Buffer.BlockCopy(data, offset, _block, _blockLength, take);
                _blockLength += take;
                offset += take;
                count -= take;
            }
        }

        public override unsafe byte[] FinalizeHash()
        {
            for (int i = _blockLength; i < BlockLength; i++)
            {
                _block[i] = 0;
            }

            uint* key = stackalloc uint[8];
            uint* message = stackalloc uint[16];
            uint* temp = stackalloc uint[8];
            uint* words = stackalloc uint[16];
            byte[] result = new byte[_digestBytes];
            fixed (uint* cv = _cv, stack = _stack)
            fixed (byte* block = _block)
            {
                for (int i = 0; i < 8; i++)
                {
                    key[i] = cv[i];
                }
                for (int i = 0; i < 16; i++)
                {
                    message[i] = ((uint*)block)[i];
                }
                ulong counter = _chunkCounter;
                uint blockLength = (uint)_blockLength;
                uint flags = ChunkEnd | (_blocksCompressed == 0 ? ChunkStart : 0);

                for (int level = _stackLength - 1; level >= 0; level--)
                {
                    for (int i = 0; i < 8; i++)
                    {
                        temp[i] = key[i];
                    }
                    CompressInPlace(temp, message, counter, blockLength, flags);
                    uint* left = stack + level * 8;
                    for (int i = 0; i < 8; i++)
                    {
                        message[i] = left[i];
                        message[i + 8] = temp[i];
                    }
                    SetIv(key);
                    counter = 0;
                    blockLength = BlockLength;
                    flags = Parent;
                }

                int produced = 0;
                ulong outputBlock = 0;
                while (produced < result.Length)
                {
                    Rounds(key, message, outputBlock, blockLength, flags | Root, words);
                    for (int i = 0; i < 8; i++)
                    {
                        words[i + 8] ^= key[i];
                    }
                    int take = 64 < result.Length - produced ? 64 : result.Length - produced;
                    for (int i = 0; i < take; i++)
                    {
                        result[produced + i] = (byte)(words[i >> 2] >> (8 * (i & 3)));
                    }
                    produced += take;
                    outputBlock++;
                }
            }
            return result;
        }

        private void ResetChunk()
        {
            _cv[0] = Iv0; _cv[1] = Iv1; _cv[2] = Iv2; _cv[3] = Iv3;
            _cv[4] = Iv4; _cv[5] = Iv5; _cv[6] = Iv6; _cv[7] = Iv7;
            _blockLength = 0;
            _blocksCompressed = 0;
        }

        private unsafe void HashChunks(byte[] data, int offset, int chunks)
        {
            if (_chunkCvs.Length < chunks * 8)
            {
                _chunkCvs = new uint[chunks * 8];
            }
            uint[] cvs = _chunkCvs;
            ulong firstCounter = _chunkCounter;

            if (chunks >= ParallelChunks)
            {
                Parallel.ForEach(Partitioner.Create(0, chunks, ParallelChunks), delegate(System.Tuple<int, int> range)
                {
                    HashChunkRange(data, offset, firstCounter, cvs, range.Item1, range.Item2);
                });
            }
            else
            {
                HashChunkRange(data, offset, firstCounter, cvs, 0, chunks);
            }

            fixed (uint* cv = cvs)
            {
                for (int i = 0; i < chunks; i++)
                {
                    PushCv(cv + i * 8, firstCounter + (ulong)i + 1);
                }
            }
            _chunkCounter += (ulong)chunks;
        }

        private static unsafe void HashChunkRange(byte[] data, int offset, ulong firstCounter, uint[] cvs, int from, int to)
        {
            fixed (byte* start = &data[offset])
            fixed (uint* output = cvs)
            {
                for (int chunk = from; chunk < to; chunk++)
                {
                    uint* cv = output + chunk * 8;
                    SetIv(cv);
                    byte* input = start + chunk * ChunkLength;
                    ulong counter = firstCounter + (ulong)chunk;
                    for (int block = 0; block < 16; block++)
                    {
                        uint flags = (block == 0 ? ChunkStart : 0) | (block == 15 ? ChunkEnd : 0);
                        CompressInPlace(cv, (uint*)(input + block * BlockLength), counter, BlockLength, flags);
                    }
                }
            }
        }

        private unsafe void PushCv(uint* cv, ulong chunkCount)
        {
            uint* current = stackalloc uint[8];
            for (int i = 0; i < 8; i++)
            {
                current[i] = cv[i];
            }
            fixed (uint* stack = _stack)
            {
                while ((chunkCount & 1) == 0)
                {
                    _stackLength--;
                    ParentCv(stack + _stackLength * 8, current, current);
                    chunkCount >>= 1;
                }
                uint* top = stack + _stackLength * 8;
                for (int i = 0; i < 8; i++)
                {
                    top[i] = current[i];
                }
            }
            _stackLength++;
        }

        private static unsafe void ParentCv(uint* left, uint* right, uint* destination)
        {
            uint* message = stackalloc uint[16];
            for (int i = 0; i < 8; i++)
            {
                message[i] = left[i];
                message[i + 8] = right[i];
            }
            SetIv(destination);
            CompressInPlace(destination, message, 0, BlockLength, Parent);
        }

        private static unsafe void SetIv(uint* cv)
        {
            cv[0] = Iv0; cv[1] = Iv1; cv[2] = Iv2; cv[3] = Iv3;
            cv[4] = Iv4; cv[5] = Iv5; cv[6] = Iv6; cv[7] = Iv7;
        }

        private static unsafe void CompressInPlace(uint* cv, uint* m, ulong counter, uint blockLength, uint flags)
        {
            uint* v = stackalloc uint[16];
            Rounds(cv, m, counter, blockLength, flags, v);
            for (int i = 0; i < 8; i++)
            {
                cv[i] = v[i];
            }
        }

        private static unsafe void Rounds(uint* cv, uint* m, ulong counter, uint blockLength, uint flags, uint* output)
        {
            uint v0 = cv[0], v1 = cv[1], v2 = cv[2], v3 = cv[3];
            uint v4 = cv[4], v5 = cv[5], v6 = cv[6], v7 = cv[7];
            uint v8 = Iv0, v9 = Iv1, v10 = Iv2, v11 = Iv3;
            uint v12 = (uint)counter, v13 = (uint)(counter >> 32), v14 = blockLength, v15 = flags;

            fixed (byte* schedule = Schedule)
            {
                for (int round = 0; round < 7; round++)
                {
                    byte* s = schedule + (round << 4);
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
            }

            output[0] = v0 ^ v8; output[1] = v1 ^ v9; output[2] = v2 ^ v10; output[3] = v3 ^ v11;
            output[4] = v4 ^ v12; output[5] = v5 ^ v13; output[6] = v6 ^ v14; output[7] = v7 ^ v15;
            output[8] = v8; output[9] = v9; output[10] = v10; output[11] = v11;
            output[12] = v12; output[13] = v13; output[14] = v14; output[15] = v15;
        }

        private static byte[] BuildSchedule()
        {
            byte[] schedule = new byte[7 * 16];
            for (int i = 0; i < 16; i++)
            {
                schedule[i] = (byte)i;
            }
            for (int round = 1; round < 7; round++)
            {
                for (int i = 0; i < 16; i++)
                {
                    schedule[round * 16 + i] = schedule[(round - 1) * 16 + MessagePermutation[i]];
                }
            }
            return schedule;
        }
    }
}
