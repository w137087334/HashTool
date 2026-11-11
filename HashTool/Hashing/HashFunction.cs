using System;

namespace HashTool.Hashing
{
    public delegate void BlockProcessor(byte[] data, int offset, int blocks);

    public abstract class HashFunction
    {
        public abstract string Name { get; }

        public abstract string Group { get; }

        public abstract void Initialize();

        public abstract void Update(byte[] data, int offset, int count);

        public abstract byte[] FinalizeHash();

        public byte[] Compute(byte[] data)
        {
            Initialize();
            if (data != null && data.Length > 0)
            {
                Update(data, 0, data.Length);
            }
            return FinalizeHash();
        }

        protected static void CheckRange(byte[] data, int offset, int count)
        {
            if (count < 0 || offset < 0 || data == null || offset > data.Length - count)
            {
                throw new ArgumentException("Invalid input range.");
            }
        }

        protected static void Absorb(
            byte[] buffer,
            ref int filled,
            int blockSize,
            byte[] data,
            int offset,
            int count,
            BlockProcessor process)
        {
            CheckRange(data, offset, count);

            if (filled > 0)
            {
                int need = blockSize - filled;
                if (count < need)
                {
                    Buffer.BlockCopy(data, offset, buffer, filled, count);
                    filled += count;
                    return;
                }

                Buffer.BlockCopy(data, offset, buffer, filled, need);
                process(buffer, 0, 1);
                offset += need;
                count -= need;
                filled = 0;
            }

            int blocks = count / blockSize;
            if (blocks > 0)
            {
                process(data, offset, blocks);
                offset += blocks * blockSize;
                count -= blocks * blockSize;
            }

            if (count > 0)
            {
                Buffer.BlockCopy(data, offset, buffer, 0, count);
                filled = count;
            }
        }

        protected static void AbsorbLazy(
            byte[] buffer,
            ref int filled,
            int blockSize,
            byte[] data,
            int offset,
            int count,
            BlockProcessor process)
        {
            CheckRange(data, offset, count);

            if (filled > 0)
            {
                int need = blockSize - filled;
                if (count <= need)
                {
                    Buffer.BlockCopy(data, offset, buffer, filled, count);
                    filled += count;
                    return;
                }

                Buffer.BlockCopy(data, offset, buffer, filled, need);
                process(buffer, 0, 1);
                offset += need;
                count -= need;
                filled = 0;
            }

            int blocks = (count - 1) / blockSize;
            if (blocks > 0)
            {
                process(data, offset, blocks);
                offset += blocks * blockSize;
                count -= blocks * blockSize;
            }

            if (count > 0)
            {
                Buffer.BlockCopy(data, offset, buffer, 0, count);
                filled = count;
            }
        }
    }
}
