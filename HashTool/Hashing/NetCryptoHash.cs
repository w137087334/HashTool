using System.Security.Cryptography;

namespace HashTool.Hashing
{
    public sealed class NetCryptoHash : HashFunction
    {
        private readonly string _name;
        private readonly string _group;
        private readonly FuncFactory _factory;
        private HashAlgorithm _algorithm;
        private static readonly byte[] Empty = new byte[0];

        public delegate HashAlgorithm FuncFactory();

        public NetCryptoHash(string name, string group, FuncFactory factory)
        {
            _name = name;
            _group = group;
            _factory = factory;
        }

        public override string Name { get { return _name; } }

        public override string Group { get { return _group; } }

        public override void Initialize()
        {
            if (_algorithm != null)
            {
                _algorithm.Dispose();
            }
            _algorithm = _factory();
        }

        public override void Update(byte[] data, int offset, int count)
        {
            if (count > 0)
            {
                _algorithm.TransformBlock(data, offset, count, null, 0);
            }
        }

        public override byte[] FinalizeHash()
        {
            _algorithm.TransformFinalBlock(Empty, 0, 0);
            byte[] hash = _algorithm.Hash;
            _algorithm.Dispose();
            _algorithm = null;
            return hash;
        }
    }
}
