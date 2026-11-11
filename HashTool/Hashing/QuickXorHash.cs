using System;

namespace HashTool.Hashing
{
    public sealed class QuickXorHash : HashFunction
    {
        private const int WidthInBits = 160;
        private const int Shift = 11;
        private const int BitsInLastCell = 32;

        private ulong[] _data;
        private long _length;
        private int _shift;

        public override string Name { get { return "QuickXor"; } }

        public override string Group { get { return "其他"; } }

        public override void Initialize()
        {
            _data = new ulong[(WidthInBits - 1) / 64 + 1];
            _length = 0;
            _shift = 0;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            int vectorIndex = _shift / 64;
            int vectorOffset = _shift % 64;
            int iterations = Math.Min(count, WidthInBits);
            for (int i = 0; i < iterations; i++)
            {
                bool lastCell = vectorIndex == _data.Length - 1;
                int bitsInCell = lastCell ? BitsInLastCell : 64;
                if (vectorOffset <= bitsInCell - 8)
                {
                    for (int j = offset + i; j < offset + count; j += WidthInBits)
                    {
                        _data[vectorIndex] ^= (ulong)data[j] << vectorOffset;
                    }
                }
                else
                {
                    int index2 = lastCell ? 0 : vectorIndex + 1;
                    int lowBits = bitsInCell - vectorOffset;
                    for (int j = offset + i; j < offset + count; j += WidthInBits)
                    {
                        _data[vectorIndex] ^= (ulong)data[j] << vectorOffset;
                        _data[index2] ^= (ulong)data[j] >> lowBits;
                    }
                }

                vectorOffset += Shift;
                while (vectorOffset >= bitsInCell)
                {
                    vectorIndex = lastCell ? 0 : vectorIndex + 1;
                    vectorOffset -= bitsInCell;
                    lastCell = vectorIndex == _data.Length - 1;
                    bitsInCell = lastCell ? BitsInLastCell : 64;
                }
            }

            _shift = (_shift + Shift * (count % WidthInBits)) % WidthInBits;
            _length += count;
        }

        public override byte[] FinalizeHash()
        {
            byte[] result = new byte[WidthInBits / 8];
            for (int i = 0; i < _data.Length - 1; i++)
            {
                Binary.WriteUInt32LE(result, i * 8, (uint)_data[i]);
                Binary.WriteUInt32LE(result, i * 8 + 4, (uint)(_data[i] >> 32));
            }

            int last = (_data.Length - 1) * 8;
            uint tail = (uint)_data[_data.Length - 1];
            int remaining = result.Length - last;
            for (int i = 0; i < remaining; i++)
            {
                result[last + i] = (byte)(tail >> (8 * i));
            }

            for (int i = 0; i < 8; i++)
            {
                result[result.Length - 8 + i] ^= (byte)(_length >> (8 * i));
            }
            return result;
        }
    }
}
