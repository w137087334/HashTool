using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using HashTool.Hashing;

namespace HashTool.Tests
{
    internal static class Program
    {
        private static int _failures;

        private static void Main()
        {
            CheckKnown();
            CheckEd2k();
            CheckStreaming();
            CheckLargeStreaming();
            CheckHex();
            CheckLanguage();
            CheckVectors();
            if (_failures == 0)
            {
                Console.WriteLine("OK");
            }
            else
            {
                Console.WriteLine("FAILURES " + _failures);
                Environment.ExitCode = 1;
            }
        }

        private static void CheckKnown()
        {
            byte[] empty = new byte[0];
            byte[] abc = Encoding.ASCII.GetBytes("abc");
            byte[] digits = Encoding.ASCII.GetBytes("123456789");
            Expect("MD5", empty, "d41d8cd98f00b204e9800998ecf8427e");
            Expect("SHA-1", empty, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
            Expect("SHA-224", empty, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
            Expect("SHA-256", abc, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            Expect("SHA3-256", empty, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
            Expect("SHA3-512", empty, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
            Expect("SM3", abc, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
            Expect("MD4", empty, "31d6cfe0d16ae931b73c59d7e0c089c0");
            Expect("MD4", abc, "a448017aaf21d8525fc10ae87aa6729d");
            Expect("CRC32", digits, "cbf43926");
            Expect("CRC64", digits, "995dc9bbdf1939fa");
            Expect("RIPEMD-160", empty, "9c1185a5c5e9fc54612808977ee8f548b2258d31");
            Expect("Blake2s-256", empty, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
            Expect("Blake2b-512", empty, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
            Expect("Blake3-256", empty, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
            Expect("XXH32", empty, "02cc5d05");
            Expect("XXH64", empty, "ef46db3751d8e999");
            Expect("Streebog-512", empty, "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a");
            Expect("Streebog-256", empty, "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb");
            Expect("Whirlpool", empty, "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
            Expect("Whirlpool", abc, "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5");
            Expect("Whirlpool", Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog"), "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35");
            Expect("Whirlpool", Pattern(100), "b752b6eeb497a8bebfc1be1649ca41d57fd1973bffc2261ca196b5474e0f353762f354c1d743581f61c51f4d86921360bc2e8ad35e830578b68b12e884a50894");
            Expect("HAS-160", abc, "975e810488cf2a3d49838478124afce4b1c78804");
            Expect("QuickXor", Encoding.ASCII.GetBytes("hello world"), "6828031bd8f00610dce10d726b03190000000000");
        }

        private static void CheckEd2k()
        {
            byte[] small = Pattern(1000);
            if (Hex(new Ed2kHash().Compute(small)) != Hex(new Md4Hash().Compute(small)))
            {
                Fail("eD2k 短消息应等于 MD4");
            }

            int chunk = Ed2kHash.ChunkSize;
            byte[] exact = new byte[chunk];
            exact[0] = 0x61;
            exact[chunk - 1] = 0x62;
            byte[] chunkHash = new Md4Hash().Compute(exact);
            byte[] emptyHash = new Md4Hash().Compute(new byte[0]);
            byte[] joined = new byte[32];
            Buffer.BlockCopy(chunkHash, 0, joined, 0, 16);
            Buffer.BlockCopy(emptyHash, 0, joined, 16, 16);
            string expect = Hex(new Md4Hash().Compute(joined));
            string actual = Hex(new Ed2kHash().Compute(exact));
            if (expect != actual)
            {
                Fail("eD2k 整块期望 " + expect + " 实际 " + actual);
            }

            byte[] extra = new byte[chunk + 3];
            extra[0] = 0x61;
            extra[chunk] = 1;
            extra[chunk + 1] = 2;
            extra[chunk + 2] = 3;
            byte[] first = new byte[chunk];
            Buffer.BlockCopy(extra, 0, first, 0, chunk);
            byte[] rest = new byte[] { 1, 2, 3 };
            byte[] head = new Md4Hash().Compute(first);
            byte[] tail = new Md4Hash().Compute(rest);
            Buffer.BlockCopy(head, 0, joined, 0, 16);
            Buffer.BlockCopy(tail, 0, joined, 16, 16);
            expect = Hex(new Md4Hash().Compute(joined));
            actual = Hex(new Ed2kHash().Compute(extra));
            if (expect != actual)
            {
                Fail("eD2k 余数期望 " + expect + " 实际 " + actual);
            }
        }

        private static void CheckStreaming()
        {
            byte[][] messages = new byte[][]
            {
                new byte[0],
                Encoding.ASCII.GetBytes("abc"),
                Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog"),
                Pattern(63),
                Pattern(64),
                Pattern(65),
                Pattern(200),
                Pattern(240),
                Pattern(241),
                Pattern(1023),
                Pattern(1024),
                Pattern(1025),
                Pattern(2048)
            };
            int[] chunks = new int[] { 1, 3, 7, 63, 64, 127, 128, 1024 };

            foreach (HashDefinition definition in HashCatalog.All)
            {
                foreach (byte[] message in messages)
                {
                    string once = Hex(definition.Create().Compute(message));
                    foreach (int chunk in chunks)
                    {
                        string split = Hex(ComputeChunked(definition.Create(), message, chunk));
                        if (once != split)
                        {
                            Fail(definition.Name + " 分段 " + chunk + " 与整段不一致，长度 " + message.Length);
                            break;
                        }
                    }
                }
            }
        }

        private static void CheckLargeStreaming()
        {
            byte[] message = XorShift(300001);
            int[] chunks = new int[] { 1000, 65537, 100003 };
            foreach (HashDefinition definition in HashCatalog.All)
            {
                string once = Hex(definition.Create().Compute(message));
                foreach (int chunk in chunks)
                {
                    string split = Hex(ComputeChunked(definition.Create(), message, chunk));
                    if (once != split)
                    {
                        Fail(definition.Name + " 大消息分段 " + chunk + " 与整段不一致");
                        break;
                    }
                }
            }
        }

        private static void CheckHex()
        {
            ExpectHex("", "");
            ExpectHex("00ff10", "00ff10");
            ExpectHex("0xAB, 0xcd ; 0x01", "abcd01");
            ExpectHex("de-ad_be:ef\r\n", "deadbeef");
            ExpectHexError("abc");
            ExpectHexError("zz");
        }

        private static void ExpectHex(string text, string expected)
        {
            string actual = Hex(HexCodec.Parse(text));
            if (actual != expected)
            {
                Fail("十六进制解析 “" + text + "” 期望 " + expected + " 实际 " + actual);
            }
        }

        private static void ExpectHexError(string text)
        {
            try
            {
                HexCodec.Parse(text);
                Fail("十六进制解析 “" + text + "” 应当报错");
            }
            catch (FormatException)
            {
            }
        }

        private static void CheckLanguage()
        {
            if (Locale.Get("WindowTitle") != "Hash Calculator")
            {
                Fail("默认语言应为英文");
            }
            if (Locale.Select("zh-CN", false))
            {
                Fail("没有语言包时不能切换到中文");
            }

            string directory = Path.Combine(Path.GetTempPath(), "hashtool-lang-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string pack = Path.Combine(directory, "zh-CN.txt");
            File.WriteAllText(pack, "name=中文\r\nWindowTitle=哈希计算\r\nHex.Empty=十六进制内容为空。\r\n", new UTF8Encoding(true));
            try
            {
                if (!Locale.LoadPack(pack) || !Locale.Select("zh-CN", false))
                {
                    Fail("中文语言包应能加载并切换");
                }
                if (Locale.Get("WindowTitle") != "哈希计算")
                {
                    Fail("切换后应使用语言包文案");
                }
                if (Locale.Get("Compute") != "Compute")
                {
                    Fail("语言包缺少的条目应回退英文");
                }
                try
                {
                    HexCodec.Parse(null);
                    Fail("空十六进制应当报错");
                }
                catch (FormatException ex)
                {
                    if (ex.Message != "十六进制内容为空。")
                    {
                        Fail("中文语言包下的十六进制错误应为：" + ex.Message);
                    }
                }
            }
            finally
            {
                Locale.Select(Locale.EnglishId, false);
                Directory.Delete(directory, true);
            }

            if (Locale.Get("WindowTitle") != "Hash Calculator")
            {
                Fail("切回英文失败");
            }
        }

        private static void CheckVectors()
        {
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Vectors.txt");
            Dictionary<int, List<string[]>> byLength = new Dictionary<int, List<string[]>>();
            List<int> order = new List<int>();
            foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
            {
                if (line.Length == 0 || line[0] == '#')
                {
                    continue;
                }
                string[] parts = line.Split(' ');
                int length = int.Parse(parts[0]);
                List<string[]> entries;
                if (!byLength.TryGetValue(length, out entries))
                {
                    entries = new List<string[]>();
                    byLength.Add(length, entries);
                    order.Add(length);
                }
                entries.Add(new string[] { parts[1], parts[2] });
            }

            HashSet<string> covered = new HashSet<string>();
            int count = 0;
            foreach (int length in order)
            {
                byte[] data = XorShift(length);
                foreach (string[] entry in byLength[length])
                {
                    covered.Add(entry[0]);
                    count++;
                    string actual = Hex(ComputeChunked(Find(entry[0]).Create(), data, 1024 * 1024));
                    if (actual != entry[1])
                    {
                        Fail(entry[0] + " 测试向量长度 " + length + " 期望 " + entry[1] + " 实际 " + actual);
                    }
                }
            }

            foreach (HashDefinition definition in HashCatalog.All)
            {
                if (!covered.Contains(definition.Name))
                {
                    Fail(definition.Name + " 没有测试向量");
                }
            }
            Console.WriteLine("测试向量 " + count + " 条，覆盖 " + covered.Count + " 种算法");
        }

        private static byte[] XorShift(int length)
        {
            byte[] data = new byte[length];
            uint state = 0x9E3779B9;
            for (int i = 0; i < length; i++)
            {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                data[i] = (byte)state;
            }
            return data;
        }

        private static byte[] Pattern(int length)
        {
            byte[] data = new byte[length];
            for (int i = 0; i < length; i++)
            {
                data[i] = (byte)i;
            }
            return data;
        }

        private static byte[] ComputeChunked(HashFunction function, byte[] data, int chunk)
        {
            function.Initialize();
            int offset = 0;
            while (offset < data.Length)
            {
                int count = data.Length - offset;
                if (count > chunk)
                {
                    count = chunk;
                }
                function.Update(data, offset, count);
                offset += count;
            }
            return function.FinalizeHash();
        }

        private static void Expect(string name, byte[] data, string expected)
        {
            HashFunction function = Find(name).Create();
            string actual = Hex(function.Compute(data));
            if (actual != expected)
            {
                Fail(name + " 期望 " + expected + " 实际 " + actual);
            }
        }

        private static HashDefinition Find(string name)
        {
            foreach (HashDefinition definition in HashCatalog.All)
            {
                if (definition.Name == name)
                {
                    return definition;
                }
            }
            throw new InvalidOperationException(name);
        }

        private static string Hex(byte[] data)
        {
            return HexCodec.ToHex(data, false);
        }

        private static void Fail(string message)
        {
            Console.WriteLine(message);
            _failures++;
        }
    }
}
