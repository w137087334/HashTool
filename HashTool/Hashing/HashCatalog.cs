using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace HashTool.Hashing
{
    public sealed class HashDefinition
    {
        public HashDefinition(string name, string group, bool selectedByDefault, Func<HashFunction> create)
        {
            Name = name;
            Group = group;
            SelectedByDefault = selectedByDefault;
            Create = create;
        }

        public string Name { get; private set; }

        public string Group { get; private set; }

        public bool SelectedByDefault { get; private set; }

        public Func<HashFunction> Create { get; private set; }
    }

    public static class HashCatalog
    {
        private static readonly HashDefinition[] Definitions = CreateDefinitions();

        public static IList<HashDefinition> All
        {
            get { return Definitions; }
        }

        private static HashDefinition[] CreateDefinitions()
        {
            List<HashDefinition> list = new List<HashDefinition>();
            Add(list, "MD4", "MD", false, delegate { return new Md4Hash(); });
            Add(list, "MD5", "MD", true, delegate { return new NetCryptoHash("MD5", "MD", delegate { return new MD5CryptoServiceProvider(); }); });
            Add(list, "RIPEMD-160", "MD", false, delegate { return new NetCryptoHash("RIPEMD-160", "MD", delegate { return new RIPEMD160Managed(); }); });
            Add(list, "HAS-160", "MD", false, delegate { return new Has160Hash(); });
            Add(list, "eD2k", "MD", false, delegate { return new Ed2kHash(); });

            Add(list, "CRC32", "CRC", true, delegate { return new Crc32Hash(); });
            Add(list, "CRC64", "CRC", false, delegate { return new Crc64Hash(); });

            Add(list, "SHA-1", "SHA-1", true, delegate { return new NetCryptoHash("SHA-1", "SHA-1", delegate { return new SHA1Managed(); }); });
            Add(list, "SHA-224", "SHA-2", false, delegate { return new Sha224Hash(); });
            Add(list, "SHA-256", "SHA-2", true, delegate { return new NetCryptoHash("SHA-256", "SHA-2", delegate { return new SHA256Managed(); }); });
            Add(list, "SHA-384", "SHA-2", false, delegate { return new NetCryptoHash("SHA-384", "SHA-2", delegate { return new SHA384Managed(); }); });
            Add(list, "SHA-512", "SHA-2", false, delegate { return new NetCryptoHash("SHA-512", "SHA-2", delegate { return new SHA512Managed(); }); });

            AddSize(list, "SHA3", "SHA-3", new int[] { 224, 256, 384, 512 }, delegate(int bits) { return new Sha3Hash(bits); });
            Add(list, "SM3", "SM3", false, delegate { return new Sm3Hash(); });

            AddSize(list, "Blake2s", "BLAKE2s", new int[] { 128, 160, 224, 256 }, delegate(int bits) { return new Blake2sHash(bits / 8); });
            AddSize(list, "Blake2sp", "BLAKE2sp", new int[] { 128, 160, 224, 256 }, delegate(int bits) { return new Blake2spHash(bits / 8); });
            AddSize(list, "Blake2b", "BLAKE2b", new int[] { 128, 160, 224, 256, 384, 512 }, delegate(int bits) { return new Blake2bHash(bits / 8); });
            AddSize(list, "Blake2bp", "BLAKE2bp", new int[] { 128, 160, 224, 256, 384, 512 }, delegate(int bits) { return new Blake2bpHash(bits / 8); });
            AddSize(list, "Blake3", "BLAKE3", new int[] { 128, 160, 224, 256, 384, 512 }, delegate(int bits) { return new Blake3Hash(bits / 8); });

            Add(list, "XXH32", "xxHash", false, delegate { return new Xxh32Hash(); });
            Add(list, "XXH64", "xxHash", false, delegate { return new Xxh64Hash(); });
            Add(list, "XXH3-64", "xxHash", false, delegate { return new Xxh3Hash(false); });
            Add(list, "XXH3-128", "xxHash", false, delegate { return new Xxh3Hash(true); });

            Add(list, "QuickXor", "其他", false, delegate { return new QuickXorHash(); });
            Add(list, "Whirlpool", "其他", false, delegate { return new WhirlpoolHash(); });
            Add(list, "Streebog-256", "Streebog", false, delegate { return new StreebogHash(256); });
            Add(list, "Streebog-512", "Streebog", false, delegate { return new StreebogHash(512); });
            return list.ToArray();
        }

        private static void Add(List<HashDefinition> list, string name, string group, bool selected, Func<HashFunction> create)
        {
            list.Add(new HashDefinition(name, group, selected, create));
        }

        private static void AddSize(List<HashDefinition> list, string prefix, string group, int[] bits, Func<int, HashFunction> create)
        {
            for (int i = 0; i < bits.Length; i++)
            {
                int size = bits[i];
                Add(list, prefix + "-" + size, group, false, delegate { return create(size); });
            }
        }
    }
}
