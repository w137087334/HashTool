namespace HashTool.Hashing
{
    public sealed class Ed2kHash : HashFunction
    {
        public const int ChunkSize = 9728000;

        private Md4Hash _inner;
        private Md4Hash _outer;
        private int _innerLength;
        private bool _hasFullChunk;

        public override string Name { get { return "eD2k"; } }

        public override string Group { get { return "MD"; } }

        public override void Initialize()
        {
            _inner = new Md4Hash();
            _outer = new Md4Hash();
            _inner.Initialize();
            _outer.Initialize();
            _innerLength = 0;
            _hasFullChunk = false;
        }

        public override void Update(byte[] data, int offset, int count)
        {
            while (count > 0)
            {
                int space = ChunkSize - _innerLength;
                int take = count < space ? count : space;
                _inner.Update(data, offset, take);
                _innerLength += take;
                offset += take;
                count -= take;
                if (_innerLength == ChunkSize)
                {
                    byte[] chunkHash = _inner.FinalizeHash();
                    _outer.Update(chunkHash, 0, chunkHash.Length);
                    _inner.Initialize();
                    _innerLength = 0;
                    _hasFullChunk = true;
                }
            }
        }

        public override byte[] FinalizeHash()
        {
            if (!_hasFullChunk)
            {
                return _inner.FinalizeHash();
            }

            byte[] tailHash = _inner.FinalizeHash();
            _outer.Update(tailHash, 0, tailHash.Length);
            return _outer.FinalizeHash();
        }
    }
}
