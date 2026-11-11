namespace HashTool.Hashing
{
    public sealed class Xxh32Hash : HashFunction
    {
        private const uint Prime1 = 0x9E3779B1;
        private const uint Prime2 = 0x85EBCA77;
        private const uint Prime3 = 0xC2B2AE3D;
        private const uint Prime4 = 0x27D4EB2F;
        private const uint Prime5 = 0x165667B1;

        private readonly byte[] _buffer = new byte[16];
        private uint _v1;
        private uint _v2;
        private uint _v3;
        private uint _v4;
        private int _filled;
        private uint _total;
        private bool _large;

        public override string Name { get { return "XXH32"; } }

        public override string Group { get { return "xxHash"; } }

        public override void Initialize()
        {
            _v1 = unchecked(Prime1 + Prime2);
            _v2 = Prime2;
            _v3 = 0;
            _v4 = unchecked(0 - Prime1);
            _filled = 0;
            _total = 0;
            _large = false;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            _total += (uint)count;
            if (_filled > 0)
            {
                int need = 16 - _filled;
                if (count < need)
                {
                    System.Buffer.BlockCopy(data, offset, _buffer, _filled, count);
                    _filled += count;
                    return;
                }
                System.Buffer.BlockCopy(data, offset, _buffer, _filled, need);
                ConsumeStripes(_buffer, 0, 1);
                offset += need;
                count -= need;
                _filled = 0;
                _large = true;
            }

            int stripes = count / 16;
            if (stripes > 0)
            {
                ConsumeStripes(data, offset, stripes);
                offset += stripes * 16;
                count -= stripes * 16;
                _large = true;
            }

            if (count > 0)
            {
                System.Buffer.BlockCopy(data, offset, _buffer, 0, count);
                _filled = count;
            }
        }

        public override byte[] FinalizeHash()
        {
            uint hash = _large
                ? Binary.RotL(_v1, 1) + Binary.RotL(_v2, 7) + Binary.RotL(_v3, 12) + Binary.RotL(_v4, 18)
                : Prime5;
            hash += _total;
            int offset = 0;
            int length = _filled;
            while (length >= 4)
            {
                hash = Binary.RotL(hash + Binary.ReadUInt32LE(_buffer, offset) * Prime3, 17) * Prime4;
                offset += 4;
                length -= 4;
            }
            while (length > 0)
            {
                hash = Binary.RotL(hash + _buffer[offset] * Prime5, 11) * Prime1;
                offset++;
                length--;
            }
            hash ^= hash >> 15;
            hash *= Prime2;
            hash ^= hash >> 13;
            hash *= Prime3;
            hash ^= hash >> 16;
            byte[] result = new byte[4];
            Binary.WriteUInt32BE(result, 0, hash);
            return result;
        }

        private unsafe void ConsumeStripes(byte[] data, int offset, int stripes)
        {
            uint v1 = _v1, v2 = _v2, v3 = _v3, v4 = _v4;
            fixed (byte* start = &data[offset])
            {
                uint* p = (uint*)start;
                uint* end = p + stripes * 4;
                for (; p < end; p += 4)
                {
                    v1 = Round(v1, p[0]);
                    v2 = Round(v2, p[1]);
                    v3 = Round(v3, p[2]);
                    v4 = Round(v4, p[3]);
                }
            }
            _v1 = v1;
            _v2 = v2;
            _v3 = v3;
            _v4 = v4;
        }

        private static uint Round(uint acc, uint input)
        {
            return Binary.RotL(acc + input * Prime2, 13) * Prime1;
        }
    }

    public sealed class Xxh64Hash : HashFunction
    {
        private const ulong Prime1 = 0x9E3779B185EBCA87UL;
        private const ulong Prime2 = 0xC2B2AE3D27D4EB4FUL;
        private const ulong Prime3 = 0x165667B19E3779F9UL;
        private const ulong Prime4 = 0x85EBCA77C2B2AE63UL;
        private const ulong Prime5 = 0x27D4EB2F165667C5UL;

        private readonly byte[] _buffer = new byte[32];
        private ulong _v1;
        private ulong _v2;
        private ulong _v3;
        private ulong _v4;
        private int _filled;
        private ulong _total;
        private bool _large;

        public override string Name { get { return "XXH64"; } }

        public override string Group { get { return "xxHash"; } }

        public override void Initialize()
        {
            _v1 = unchecked(Prime1 + Prime2);
            _v2 = Prime2;
            _v3 = 0;
            _v4 = unchecked(0 - Prime1);
            _filled = 0;
            _total = 0;
            _large = false;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            _total += (ulong)count;
            if (_filled > 0)
            {
                int need = 32 - _filled;
                if (count < need)
                {
                    System.Buffer.BlockCopy(data, offset, _buffer, _filled, count);
                    _filled += count;
                    return;
                }
                System.Buffer.BlockCopy(data, offset, _buffer, _filled, need);
                ConsumeStripes(_buffer, 0, 1);
                offset += need;
                count -= need;
                _filled = 0;
                _large = true;
            }

            int stripes = count / 32;
            if (stripes > 0)
            {
                ConsumeStripes(data, offset, stripes);
                offset += stripes * 32;
                count -= stripes * 32;
                _large = true;
            }

            if (count > 0)
            {
                System.Buffer.BlockCopy(data, offset, _buffer, 0, count);
                _filled = count;
            }
        }

        public override byte[] FinalizeHash()
        {
            ulong hash;
            if (_large)
            {
                hash = Binary.RotL(_v1, 1) + Binary.RotL(_v2, 7) + Binary.RotL(_v3, 12) + Binary.RotL(_v4, 18);
                hash = Merge(hash, _v1);
                hash = Merge(hash, _v2);
                hash = Merge(hash, _v3);
                hash = Merge(hash, _v4);
            }
            else
            {
                hash = Prime5;
            }

            hash += _total;
            int offset = 0;
            int length = _filled;
            while (length >= 8)
            {
                ulong k1 = Round(0, Binary.ReadUInt64LE(_buffer, offset));
                hash ^= k1;
                hash = Binary.RotL(hash, 27) * Prime1 + Prime4;
                offset += 8;
                length -= 8;
            }
            if (length >= 4)
            {
                hash ^= Binary.ReadUInt32LE(_buffer, offset) * Prime1;
                hash = Binary.RotL(hash, 23) * Prime2 + Prime3;
                offset += 4;
                length -= 4;
            }
            while (length > 0)
            {
                hash ^= _buffer[offset] * Prime5;
                hash = Binary.RotL(hash, 11) * Prime1;
                offset++;
                length--;
            }
            hash ^= hash >> 33;
            hash *= Prime2;
            hash ^= hash >> 29;
            hash *= Prime3;
            hash ^= hash >> 32;
            byte[] result = new byte[8];
            Binary.WriteUInt64BE(result, 0, hash);
            return result;
        }

        private unsafe void ConsumeStripes(byte[] data, int offset, int stripes)
        {
            ulong v1 = _v1, v2 = _v2, v3 = _v3, v4 = _v4;
            fixed (byte* start = &data[offset])
            {
                ulong* p = (ulong*)start;
                ulong* end = p + stripes * 4;
                for (; p < end; p += 4)
                {
                    v1 = Round(v1, p[0]);
                    v2 = Round(v2, p[1]);
                    v3 = Round(v3, p[2]);
                    v4 = Round(v4, p[3]);
                }
            }
            _v1 = v1;
            _v2 = v2;
            _v3 = v3;
            _v4 = v4;
        }

        private static ulong Round(ulong acc, ulong input)
        {
            acc += input * Prime2;
            return Binary.RotL(acc, 31) * Prime1;
        }

        private static ulong Merge(ulong acc, ulong value)
        {
            acc ^= Round(0, value);
            return acc * Prime1 + Prime4;
        }
    }

    public sealed class Xxh3Hash : HashFunction
    {
        private const int SecretSize = 192;
        private const int StripeLength = 64;
        private const int StripesPerBlock = (SecretSize - StripeLength) / 8;
        private const ulong Prime64_1 = 0x9E3779B185EBCA87UL;
        private const ulong Prime64_2 = 0xC2B2AE3D27D4EB4FUL;
        private const ulong Prime64_3 = 0x165667B19E3779F9UL;
        private const ulong Prime64_4 = 0x85EBCA77C2B2AE63UL;
        private const ulong Prime64_5 = 0x27D4EB2F165667C5UL;
        private const ulong Prime32_1 = 0x9E3779B1UL;
        private const ulong Prime32_2 = 0x85EBCA77UL;
        private const ulong Prime32_3 = 0xC2B2AE3DUL;
        private const ulong PrimeMx1 = 0x165667919E3779F9UL;
        private const ulong PrimeMx2 = 0x9FB21C651E98DF25UL;

        private static readonly byte[] Secret = new byte[]
        {
            0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
            0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
            0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
            0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
            0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
            0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
            0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
            0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
            0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
            0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
            0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
            0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e
        };

        private readonly bool _wide;
        private readonly ulong[] _acc = new ulong[8];
        private byte[] _window = new byte[1024];
        private int _start;
        private int _length;
        private long _base;
        private long _total;
        private long _stripes;
        private bool _long;

        public Xxh3Hash(bool wide)
        {
            _wide = wide;
        }

        public override string Name { get { return _wide ? "XXH3-128" : "XXH3-64"; } }

        public override string Group { get { return "xxHash"; } }

        public override void Initialize()
        {
            _start = 0;
            _length = 0;
            _base = 0;
            _total = 0;
            _stripes = 0;
            _long = false;
            _acc[0] = Prime32_3;
            _acc[1] = Prime64_1;
            _acc[2] = Prime64_2;
            _acc[3] = Prime64_3;
            _acc[4] = Prime64_4;
            _acc[5] = Prime32_2;
            _acc[6] = Prime64_5;
            _acc[7] = Prime32_1;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            while (count > 0)
            {
                Ensure(1);
                int room = _window.Length - (_start + _length);
                if (room == 0)
                {
                    Compact();
                    room = _window.Length - (_start + _length);
                }
                int take = count < room ? count : room;
                System.Buffer.BlockCopy(data, offset, _window, _start + _length, take);
                _length += take;
                _total += take;
                offset += take;
                count -= take;
                if (!_long && _total > 240)
                {
                    _long = true;
                }
                if (_long)
                {
                    ConsumeReadyStripes();
                }
            }
        }

        public override byte[] FinalizeHash()
        {
            byte[] all = Snapshot();
            if (_total <= 240)
            {
                return _wide ? Short128(all, (int)_total) : Short64(all, (int)_total);
            }

            ConsumeReadyStripes();
            int local = (int)((_total - StripeLength) - _base);
            Accumulate(_window, _start + local, Secret, SecretSize - StripeLength - 7);
            return _wide ? Merge128() : Merge64();
        }

        private unsafe void ConsumeReadyStripes()
        {
            long ready = (_total - 1) / StripeLength;
            if (_stripes >= ready)
            {
                return;
            }

            fixed (byte* window = _window, secret = Secret)
            fixed (ulong* acc = _acc)
            {
                while (_stripes < ready)
                {
                    int local = (int)(_stripes * StripeLength - _base);
                    int secretOffset = (int)((_stripes % StripesPerBlock) * 8);
                    AccumulateStripe(acc, (ulong*)(window + _start + local), (ulong*)(secret + secretOffset));
                    _stripes++;
                    if (_stripes % StripesPerBlock == 0)
                    {
                        ScrambleAcc(acc, (ulong*)(secret + SecretSize - StripeLength));
                    }
                }
            }

            long dropTo = _stripes * StripeLength;
            if (dropTo > _total - StripeLength)
            {
                dropTo = _total - StripeLength;
            }
            int drop = (int)(dropTo - _base);
            if (drop > 0)
            {
                _start += drop;
                _length -= drop;
                _base += drop;
            }
        }

        private static unsafe void AccumulateStripe(ulong* acc, ulong* input, ulong* secret)
        {
            for (int lane = 0; lane < 8; lane++)
            {
                ulong data = input[lane];
                ulong mixed = data ^ secret[lane];
                acc[lane ^ 1] += data;
                acc[lane] += (ulong)(uint)mixed * (mixed >> 32);
            }
        }

        private static unsafe void ScrambleAcc(ulong* acc, ulong* secret)
        {
            for (int lane = 0; lane < 8; lane++)
            {
                ulong value = acc[lane];
                value ^= value >> 47;
                value ^= secret[lane];
                acc[lane] = value * Prime32_1;
            }
        }

        private byte[] Snapshot()
        {
            byte[] data = new byte[_length];
            System.Buffer.BlockCopy(_window, _start, data, 0, _length);
            return data;
        }

        private void Ensure(int extra)
        {
            if (_start + _length + extra <= _window.Length)
            {
                return;
            }
            if (_length + extra <= _window.Length)
            {
                Compact();
                return;
            }
            byte[] grown = new byte[System.Math.Max(_window.Length * 2, _length + extra)];
            System.Buffer.BlockCopy(_window, _start, grown, 0, _length);
            _window = grown;
            _start = 0;
        }

        private void Compact()
        {
            if (_start == 0)
            {
                return;
            }
            System.Buffer.BlockCopy(_window, _start, _window, 0, _length);
            _start = 0;
        }

        private byte[] Short64(byte[] input, int len)
        {
            ulong hash;
            if (len > 16)
            {
                hash = len <= 128 ? Mix17To128(input, len) : Mix129To240(input, len);
            }
            else if (len > 8)
            {
                hash = Mix9To16(input, len);
            }
            else if (len >= 4)
            {
                hash = Mix4To8(input, len);
            }
            else if (len > 0)
            {
                hash = Mix1To3(input, len);
            }
            else
            {
                hash = Avalanche64(Read64(Secret, 56) ^ Read64(Secret, 64));
            }
            return Be64(hash);
        }

        private byte[] Short128(byte[] input, int len)
        {
            ulong low;
            ulong high;
            if (len > 16)
            {
                if (len <= 128)
                {
                    Mix17To128_128(input, len, out low, out high);
                }
                else
                {
                    Mix129To240_128(input, len, out low, out high);
                }
            }
            else if (len > 8)
            {
                Mix9To16_128(input, len, out low, out high);
            }
            else if (len >= 4)
            {
                Mix4To8_128(input, len, out low, out high);
            }
            else if (len > 0)
            {
                Mix1To3_128(input, len, out low, out high);
            }
            else
            {
                low = Avalanche64(Read64(Secret, 64) ^ Read64(Secret, 72));
                high = Avalanche64(Read64(Secret, 80) ^ Read64(Secret, 88));
            }
            return Be128(low, high);
        }

        private ulong Mix1To3(byte[] input, int len)
        {
            uint combined = ((uint)input[0] << 16)
                | ((uint)input[len >> 1] << 24)
                | input[len - 1]
                | ((uint)len << 8);
            ulong bitflip = (ulong)(Read32(Secret, 0) ^ Read32(Secret, 4));
            return Avalanche64(combined ^ bitflip);
        }

        private ulong Mix4To8(byte[] input, int len)
        {
            uint input1 = Read32(input, 0);
            uint input2 = Read32(input, len - 4);
            ulong bitflip = Read64(Secret, 8) ^ Read64(Secret, 16);
            ulong input64 = input2 + ((ulong)input1 << 32);
            return Rrmxmx(input64 ^ bitflip, (ulong)len);
        }

        private ulong Mix9To16(byte[] input, int len)
        {
            ulong bitflip1 = Read64(Secret, 24) ^ Read64(Secret, 32);
            ulong bitflip2 = Read64(Secret, 40) ^ Read64(Secret, 48);
            ulong lo = Read64(input, 0) ^ bitflip1;
            ulong hi = Read64(input, len - 8) ^ bitflip2;
            ulong acc = (ulong)len + Swap64(lo) + hi + Binary.MulFold(lo, hi);
            return Avalanche3(acc);
        }

        private ulong Mix17To128(byte[] input, int len)
        {
            ulong acc = (ulong)len * Prime64_1;
            if (len > 32)
            {
                if (len > 64)
                {
                    if (len > 96)
                    {
                        acc += Mix16(input, 48, Secret, 96);
                        acc += Mix16(input, len - 64, Secret, 112);
                    }
                    acc += Mix16(input, 32, Secret, 64);
                    acc += Mix16(input, len - 48, Secret, 80);
                }
                acc += Mix16(input, 16, Secret, 32);
                acc += Mix16(input, len - 32, Secret, 48);
            }
            acc += Mix16(input, 0, Secret, 0);
            acc += Mix16(input, len - 16, Secret, 16);
            return Avalanche3(acc);
        }

        private ulong Mix129To240(byte[] input, int len)
        {
            ulong acc = (ulong)len * Prime64_1;
            int rounds = len / 16;
            for (int i = 0; i < 8; i++)
            {
                acc += Mix16(input, 16 * i, Secret, 16 * i);
            }
            ulong accEnd = Mix16(input, len - 16, Secret, 136 - 17);
            acc = Avalanche3(acc);
            for (int i = 8; i < rounds; i++)
            {
                accEnd += Mix16(input, 16 * i, Secret, 16 * (i - 8) + 3);
            }
            return Avalanche3(acc + accEnd);
        }

        private void Mix1To3_128(byte[] input, int len, out ulong low, out ulong high)
        {
            uint combined = ((uint)input[0] << 16)
                | ((uint)input[len >> 1] << 24)
                | input[len - 1]
                | ((uint)len << 8);
            uint combinedHigh = Binary.RotL(Swap32(combined), 13);
            ulong bitLow = (ulong)(Read32(Secret, 0) ^ Read32(Secret, 4));
            ulong bitHigh = (ulong)(Read32(Secret, 8) ^ Read32(Secret, 12));
            low = Avalanche64(combined ^ bitLow);
            high = Avalanche64(combinedHigh ^ bitHigh);
        }

        private void Mix4To8_128(byte[] input, int len, out ulong low, out ulong high)
        {
            uint lo = Read32(input, 0);
            uint hi = Read32(input, len - 4);
            ulong input64 = lo + ((ulong)hi << 32);
            ulong bitflip = (Read64(Secret, 16) ^ Read64(Secret, 24));
            ulong keyed = input64 ^ bitflip;
            ulong productLow;
            ulong productHigh;
            Binary.Mul64(keyed, Prime64_1 + ((ulong)len << 2), out productHigh, out productLow);
            productHigh += productLow << 1;
            productLow ^= productHigh >> 3;
            productLow ^= productLow >> 35;
            productLow *= PrimeMx2;
            productLow ^= productLow >> 28;
            low = productLow;
            high = Avalanche3(productHigh);
        }

        private void Mix9To16_128(byte[] input, int len, out ulong low, out ulong high)
        {
            ulong bitLow = (Read64(Secret, 32) ^ Read64(Secret, 40));
            ulong bitHigh = (Read64(Secret, 48) ^ Read64(Secret, 56));
            ulong inputLow = Read64(input, 0);
            ulong inputHigh = Read64(input, len - 8);
            ulong productLow;
            ulong productHigh;
            Binary.Mul64(inputLow ^ inputHigh ^ bitLow, Prime64_1, out productHigh, out productLow);
            productLow += (ulong)(len - 1) << 54;
            inputHigh ^= bitHigh;
            productHigh += inputHigh + (ulong)(uint)inputHigh * (Prime32_2 - 1);
            productLow ^= Swap64(productHigh);
            ulong hashLow;
            ulong hashHigh;
            Binary.Mul64(productLow, Prime64_2, out hashHigh, out hashLow);
            hashHigh += productHigh * Prime64_2;
            low = Avalanche3(hashLow);
            high = Avalanche3(hashHigh);
        }

        private void Mix17To128_128(byte[] input, int len, out ulong low, out ulong high)
        {
            ulong accLow = (ulong)len * Prime64_1;
            ulong accHigh = 0;
            if (len > 32)
            {
                if (len > 64)
                {
                    if (len > 96)
                    {
                        Mix32(ref accLow, ref accHigh, input, 48, len - 64, 96);
                    }
                    Mix32(ref accLow, ref accHigh, input, 32, len - 48, 64);
                }
                Mix32(ref accLow, ref accHigh, input, 16, len - 32, 32);
            }
            Mix32(ref accLow, ref accHigh, input, 0, len - 16, 0);
            Finish128(accLow, accHigh, len, out low, out high);
        }

        private void Mix129To240_128(byte[] input, int len, out ulong low, out ulong high)
        {
            ulong accLow = (ulong)len * Prime64_1;
            ulong accHigh = 0;
            for (int i = 32; i < 160; i += 32)
            {
                Mix32(ref accLow, ref accHigh, input, i - 32, i - 16, i - 32);
            }
            accLow = Avalanche3(accLow);
            accHigh = Avalanche3(accHigh);
            for (int i = 160; i <= len; i += 32)
            {
                Mix32(ref accLow, ref accHigh, input, i - 32, i - 16, 3 + i - 160);
            }
            Mix32NegSeed(ref accLow, ref accHigh, input, len - 16, len - 32, 136 - 17 - 16);
            Finish128(accLow, accHigh, len, out low, out high);
        }

        private void Finish128(ulong accLow, ulong accHigh, int len, out ulong low, out ulong high)
        {
            low = Avalanche3(accLow + accHigh);
            high = 0 - Avalanche3(accLow * Prime64_1 + accHigh * Prime64_4 + (ulong)len * Prime64_2);
        }

        private void Mix32(ref ulong accLow, ref ulong accHigh, byte[] input, int first, int second, int secret)
        {
            accLow += Mix16(input, first, Secret, secret);
            accLow ^= Read64(input, second) + Read64(input, second + 8);
            accHigh += Mix16(input, second, Secret, secret + 16);
            accHigh ^= Read64(input, first) + Read64(input, first + 8);
        }

        private void Mix32NegSeed(ref ulong accLow, ref ulong accHigh, byte[] input, int first, int second, int secret)
        {
            accLow += Mix16(input, first, Secret, secret);
            accLow ^= Read64(input, second) + Read64(input, second + 8);
            accHigh += Mix16(input, second, Secret, secret + 16);
            accHigh ^= Read64(input, first) + Read64(input, first + 8);
        }

        private byte[] Merge64()
        {
            return Be64(MergeAccs(Secret, 11, (ulong)_total * Prime64_1));
        }

        private byte[] Merge128()
        {
            ulong low = MergeAccs(Secret, 11, (ulong)_total * Prime64_1);
            ulong high = MergeAccs(Secret, SecretSize - 64 - 11, ~((ulong)_total * Prime64_2));
            return Be128(low, high);
        }

        private ulong MergeAccs(byte[] secret, int secretOffset, ulong start)
        {
            ulong result = start;
            for (int i = 0; i < 4; i++)
            {
                result += Binary.MulFold(
                    _acc[i * 2] ^ Read64(secret, secretOffset + 16 * i),
                    _acc[i * 2 + 1] ^ Read64(secret, secretOffset + 16 * i + 8));
            }
            return Avalanche3(result);
        }

        private void Accumulate(byte[] input, int inputOffset, byte[] secret, int secretOffset)
        {
            for (int lane = 0; lane < 8; lane++)
            {
                ulong data = Read64(input, inputOffset + lane * 8);
                ulong mixed = data ^ Read64(secret, secretOffset + lane * 8);
                _acc[lane ^ 1] += data;
                _acc[lane] += (ulong)(uint)mixed * (mixed >> 32);
            }
        }

        private static ulong Mix16(byte[] input, int inputOffset, byte[] secret, int secretOffset)
        {
            return Binary.MulFold(
                Read64(input, inputOffset) ^ Read64(secret, secretOffset),
                Read64(input, inputOffset + 8) ^ Read64(secret, secretOffset + 8));
        }

        private static ulong Avalanche64(ulong hash)
        {
            hash ^= hash >> 33;
            hash *= Prime64_2;
            hash ^= hash >> 29;
            hash *= Prime64_3;
            hash ^= hash >> 32;
            return hash;
        }

        private static ulong Avalanche3(ulong hash)
        {
            hash ^= hash >> 37;
            hash *= PrimeMx1;
            hash ^= hash >> 32;
            return hash;
        }

        private static ulong Rrmxmx(ulong hash, ulong len)
        {
            hash ^= Binary.RotL(hash, 49) ^ Binary.RotL(hash, 24);
            hash *= PrimeMx2;
            hash ^= (hash >> 35) + len;
            hash *= PrimeMx2;
            hash ^= hash >> 28;
            return hash;
        }

        private static uint Read32(byte[] data, int offset)
        {
            return Binary.ReadUInt32LE(data, offset);
        }

        private static ulong Read64(byte[] data, int offset)
        {
            return Binary.ReadUInt64LE(data, offset);
        }

        private static uint Swap32(uint value)
        {
            return (value << 24) | ((value << 8) & 0x00FF0000) | ((value >> 8) & 0x0000FF00) | (value >> 24);
        }

        private static ulong Swap64(ulong value)
        {
            uint lo = Swap32((uint)value);
            uint hi = Swap32((uint)(value >> 32));
            return ((ulong)lo << 32) | hi;
        }

        private static byte[] Be64(ulong value)
        {
            byte[] result = new byte[8];
            Binary.WriteUInt64BE(result, 0, value);
            return result;
        }

        private static byte[] Be128(ulong low, ulong high)
        {
            byte[] result = new byte[16];
            Binary.WriteUInt64BE(result, 0, high);
            Binary.WriteUInt64BE(result, 8, low);
            return result;
        }
    }
}
