namespace HashTool.Hashing
{
    public sealed class Crc32Hash : HashFunction
    {
        private static readonly uint[] Table = BuildTable();
        private uint _crc;

        public override string Name { get { return "CRC32"; } }

        public override string Group { get { return "CRC"; } }

        public override void Initialize()
        {
            _crc = 0;
        }

        public override unsafe void Update(byte[] data, int offset, int count)
        {
            CheckRange(data, offset, count);
            if (count == 0)
            {
                return;
            }

            uint crc = ~_crc;
            fixed (byte* start = &data[offset])
            fixed (uint* t = Table)
            {
                byte* p = start;
                byte* end = start + count;
                for (; p + 8 <= end; p += 8)
                {
                    uint lo = crc ^ *(uint*)p;
                    uint hi = *(uint*)(p + 4);
                    crc = t[1792 + (lo & 0xFF)] ^ t[1536 + ((lo >> 8) & 0xFF)]
                        ^ t[1280 + ((lo >> 16) & 0xFF)] ^ t[1024 + (lo >> 24)]
                        ^ t[768 + (hi & 0xFF)] ^ t[512 + ((hi >> 8) & 0xFF)]
                        ^ t[256 + ((hi >> 16) & 0xFF)] ^ t[hi >> 24];
                }
                for (; p < end; p++)
                {
                    crc = t[(crc ^ *p) & 0xFF] ^ (crc >> 8);
                }
            }
            _crc = ~crc;
        }

        public override byte[] FinalizeHash()
        {
            byte[] result = new byte[4];
            Binary.WriteUInt32BE(result, 0, _crc);
            return result;
        }

        private static uint[] BuildTable()
        {
            uint[] table = new uint[8 * 256];
            for (uint i = 0; i < 256; i++)
            {
                uint crc = i;
                for (int bit = 0; bit < 8; bit++)
                {
                    crc = (crc & 1) != 0 ? 0xEDB88320u ^ (crc >> 1) : crc >> 1;
                }
                table[i] = crc;
            }
            for (int slice = 1; slice < 8; slice++)
            {
                for (int i = 0; i < 256; i++)
                {
                    uint previous = table[(slice - 1) * 256 + i];
                    table[slice * 256 + i] = table[previous & 0xFF] ^ (previous >> 8);
                }
            }
            return table;
        }
    }

    public sealed class Crc64Hash : HashFunction
    {
        private static readonly ulong[] Table = BuildTable();
        private ulong _crc;

        public override string Name { get { return "CRC64"; } }

        public override string Group { get { return "CRC"; } }

        public override void Initialize()
        {
            _crc = 0;
        }

        public override unsafe void Update(byte[] data, int offset, int count)
        {
            CheckRange(data, offset, count);
            if (count == 0)
            {
                return;
            }

            ulong crc = ~_crc;
            fixed (byte* start = &data[offset])
            fixed (ulong* t = Table)
            {
                byte* p = start;
                byte* end = start + count;
                for (; p + 8 <= end; p += 8)
                {
                    ulong v = crc ^ *(ulong*)p;
                    crc = t[1792 + (int)(v & 0xFF)] ^ t[1536 + (int)((v >> 8) & 0xFF)]
                        ^ t[1280 + (int)((v >> 16) & 0xFF)] ^ t[1024 + (int)((v >> 24) & 0xFF)]
                        ^ t[768 + (int)((v >> 32) & 0xFF)] ^ t[512 + (int)((v >> 40) & 0xFF)]
                        ^ t[256 + (int)((v >> 48) & 0xFF)] ^ t[(int)(v >> 56)];
                }
                for (; p < end; p++)
                {
                    crc = t[(int)((crc ^ *p) & 0xFF)] ^ (crc >> 8);
                }
            }
            _crc = ~crc;
        }

        public override byte[] FinalizeHash()
        {
            byte[] result = new byte[8];
            Binary.WriteUInt64BE(result, 0, _crc);
            return result;
        }

        private static ulong[] BuildTable()
        {
            const ulong polynomial = 0xC96C5795D7870F42UL;
            ulong[] table = new ulong[8 * 256];
            for (ulong i = 0; i < 256; i++)
            {
                ulong crc = i;
                for (int bit = 0; bit < 8; bit++)
                {
                    crc = (crc & 1) != 0 ? polynomial ^ (crc >> 1) : crc >> 1;
                }
                table[i] = crc;
            }
            for (int slice = 1; slice < 8; slice++)
            {
                for (int i = 0; i < 256; i++)
                {
                    ulong previous = table[(slice - 1) * 256 + i];
                    table[slice * 256 + i] = table[(int)(previous & 0xFF)] ^ (previous >> 8);
                }
            }
            return table;
        }
    }
}
