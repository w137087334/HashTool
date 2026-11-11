using System;

namespace HashTool.Hashing
{
    public static class HexCodec
    {
        public static string ToHex(byte[] data, bool upper)
        {
            if (data == null || data.Length == 0)
            {
                return string.Empty;
            }

            char[] chars = new char[data.Length * 2];
            string alphabet = upper ? "0123456789ABCDEF" : "0123456789abcdef";
            for (int i = 0; i < data.Length; i++)
            {
                chars[i * 2] = alphabet[data[i] >> 4];
                chars[i * 2 + 1] = alphabet[data[i] & 0x0F];
            }
            return new string(chars);
        }

        public static byte[] Parse(string text)
        {
            if (text == null)
            {
                throw new FormatException(Locale.Get("Hex.Empty"));
            }

            byte[] data = new byte[text.Length / 2];
            int digits = 0;
            int high = 0;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (IsSeparator(c))
                {
                    continue;
                }

                if ((c == '0') && i + 1 < text.Length && (text[i + 1] == 'x' || text[i + 1] == 'X'))
                {
                    i++;
                    continue;
                }

                int value = HexValue(c);
                if (value < 0)
                {
                    throw new FormatException(Locale.Format("Hex.BadChar", c));
                }

                if ((digits & 1) == 0)
                {
                    high = value;
                }
                else
                {
                    data[digits >> 1] = (byte)((high << 4) | value);
                }
                digits++;
            }

            if ((digits & 1) != 0)
            {
                throw new FormatException(Locale.Get("Hex.Odd"));
            }

            if (digits / 2 == data.Length)
            {
                return data;
            }
            byte[] trimmed = new byte[digits / 2];
            Buffer.BlockCopy(data, 0, trimmed, 0, trimmed.Length);
            return trimmed;
        }

        private static int HexValue(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F')
            {
                return c - 'A' + 10;
            }
            return -1;
        }

        private static bool IsSeparator(char c)
        {
            return char.IsWhiteSpace(c) || c == ',' || c == ';' || c == ':' || c == '-' || c == '_';
        }
    }
}
