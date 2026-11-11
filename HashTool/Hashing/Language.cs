using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace HashTool.Hashing
{
    public sealed class LanguageInfo
    {
        public LanguageInfo(string id, string name)
        {
            Id = id;
            Name = name;
        }

        public string Id { get; private set; }

        public string Name { get; private set; }
    }

    public static class Locale
    {
        public const string EnglishId = "en";

        private static readonly Dictionary<string, string> English = CreateEnglish();
        private static readonly List<LanguageInfo> AvailableList = new List<LanguageInfo>();
        private static readonly Dictionary<string, Dictionary<string, string>> Packs = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

        private static volatile Dictionary<string, string> _overlay;
        private static string _currentId = EnglishId;
        private static bool _initialized;

        static Locale()
        {
            AvailableList.Add(new LanguageInfo(EnglishId, "English"));
        }

        public static IList<LanguageInfo> Available
        {
            get { return AvailableList.AsReadOnly(); }
        }

        public static string CurrentId
        {
            get { return _currentId; }
        }

        public static bool HasPack
        {
            get { return Packs.Count > 0; }
        }

        public static void Initialize()
        {
            if (_initialized)
            {
                return;
            }
            _initialized = true;

            string directory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Lang");
            if (Directory.Exists(directory))
            {
                string[] files = Directory.GetFiles(directory, "*.txt");
                Array.Sort(files, StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < files.Length; i++)
                {
                    LoadPack(files[i]);
                }
            }

            string saved = ReadSaved();
            if (!string.IsNullOrEmpty(saved))
            {
                Select(saved, false);
            }
        }

        public static bool LoadPack(string path)
        {
            Dictionary<string, string> map;
            try
            {
                map = Parse(path);
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }

            if (map == null || map.Count == 0)
            {
                return false;
            }

            string id = Path.GetFileNameWithoutExtension(path);
            if (string.IsNullOrEmpty(id) || id.Equals(EnglishId, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string name = id;
            string declared;
            if (map.TryGetValue("name", out declared) && declared.Length > 0)
            {
                name = declared;
            }
            map.Remove("name");
            map.Remove("id");
            Packs[id] = map;

            for (int i = 0; i < AvailableList.Count; i++)
            {
                if (string.Equals(AvailableList[i].Id, id, StringComparison.OrdinalIgnoreCase))
                {
                    AvailableList[i] = new LanguageInfo(id, name);
                    return true;
                }
            }
            AvailableList.Add(new LanguageInfo(id, name));
            return true;
        }

        public static bool Select(string id, bool persist)
        {
            if (string.IsNullOrEmpty(id) || id.Equals(EnglishId, StringComparison.OrdinalIgnoreCase))
            {
                _currentId = EnglishId;
                _overlay = null;
                if (persist)
                {
                    Save(EnglishId);
                }
                return true;
            }

            Dictionary<string, string> pack;
            if (!Packs.TryGetValue(id, out pack))
            {
                return false;
            }

            _currentId = id;
            _overlay = pack;
            if (persist)
            {
                Save(id);
            }
            return true;
        }

        public static string Get(string key)
        {
            string value;
            Dictionary<string, string> overlay = _overlay;
            if (overlay != null && overlay.TryGetValue(key, out value) && value.Length > 0)
            {
                return value;
            }
            if (English.TryGetValue(key, out value))
            {
                return value;
            }
            return key;
        }

        public static string Format(string key, params object[] args)
        {
            string text = Get(key);
            if (args == null || args.Length == 0)
            {
                return text;
            }
            return string.Format(text, args);
        }

        private static Dictionary<string, string> Parse(string path)
        {
            Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.Ordinal);
            using (StreamReader reader = new StreamReader(path, Encoding.UTF8, true))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Length == 0 || line[0] == '#' || line[0] == ';')
                    {
                        continue;
                    }
                    int split = line.IndexOf('=');
                    if (split <= 0)
                    {
                        continue;
                    }
                    string key = line.Substring(0, split).Trim();
                    string value = line.Substring(split + 1);
                    if (key.Length > 0)
                    {
                        map[key] = value;
                    }
                }
            }
            return map;
        }

        private static string SettingsPath()
        {
            string directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "HashTool");
            return Path.Combine(directory, "language.txt");
        }

        private static string ReadSaved()
        {
            try
            {
                string path = SettingsPath();
                if (!File.Exists(path))
                {
                    return null;
                }
                string text = File.ReadAllText(path, Encoding.UTF8).Trim();
                return text.Length == 0 ? null : text;
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
        }

        private static void Save(string id)
        {
            try
            {
                string path = SettingsPath();
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                File.WriteAllText(path, id, Encoding.UTF8);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static Dictionary<string, string> CreateEnglish()
        {
            Dictionary<string, string> text = new Dictionary<string, string>();
            text.Add("WindowTitle", "Hash Calculator");
            text.Add("HexInput", "Hex text");
            text.Add("HexInputTip", "Parse the editor as hexadecimal. Spaces, commas, and a 0x prefix are allowed.");
            text.Add("Uppercase", "Uppercase");
            text.Add("Compute", "Compute");
            text.Add("Cancel", "Cancel");
            text.Add("Copy", "Copy result");
            text.Add("ClearText", "Clear text");
            text.Add("File", "File");
            text.Add("Clear", "Clear");
            text.Add("Browse", "Browse…");
            text.Add("Hint", "A file path takes priority over the editor. Text is read as UTF-8; hexadecimal allows spaces and a 0x prefix. Drop a file onto the editor. Double-click an algorithm to select only that one. Ctrl+Enter computes, Esc cancels.");
            text.Add("Algorithms", "Algorithms");
            text.Add("SelectAll", "Select all");
            text.Add("SelectNone", "Select none");
            text.Add("Selected", "Selected {0} / {1}");
            text.Add("LanguageTip", "Language");
            text.Add("Ready", "Ready");
            text.Add("ClearedText", "Text cleared.");
            text.Add("ClearedFile", "File cleared.");
            text.Add("AllFiles", "All files|*.*");
            text.Add("BrowseTitle", "Choose a file to hash");
            text.Add("FileChosen", "File selected. It is used when computing.");
            text.Add("DropNeedFile", "Drop a file.");
            text.Add("DroppedOne", "File dropped. It is used when computing.");
            text.Add("DroppedMany", "Dropped {0} items. Using the first file.");
            text.Add("NothingToCopy", "Nothing to copy.");
            text.Add("Copied", "Copied to the clipboard.");
            text.Add("ClipboardBusy", "The clipboard is in use by another program. Copy failed; try again.");
            text.Add("NeedAlgorithm", "Select at least one hash algorithm.");
            text.Add("FileMissing", "File not found: {0}");
            text.Add("Computing", "Computing…");
            text.Add("Cancelling", "Cancelling…");
            text.Add("Done", "Finished in {0}.");
            text.Add("Cancelled", "Cancelled.");
            text.Add("HexInvalid", "Invalid hexadecimal text.");
            text.Add("HexTitle", "Hexadecimal");
            text.Add("Failed", "Failed.");
            text.Add("FailedDetail", "Failed: {0}");
            text.Add("Progress", "Computing… {0}%  {1} / {2} bytes");
            text.Add("Report.SourceFile", "Source    File");
            text.Add("Report.SourceText", "Source    Text");
            text.Add("Report.Path", "Path      {0}");
            text.Add("Report.Encoding", "Encoding  {0}");
            text.Add("Report.Hex", "Hexadecimal");
            text.Add("Report.Size", "Size      {0} bytes");
            text.Add("Report.Time", "Time      {0}");
            text.Add("Report.Count", "Algorithms {0}");
            text.Add("Report.Empty", "(empty text)");
            text.Add("Elapsed.Ms", "{0} ms");
            text.Add("Elapsed.Sec", "{0} s");
            text.Add("Group.Other", "Other");
            text.Add("AlgorithmTip", "{0}. Double-click to select only this one.");
            text.Add("Hex.Empty", "Hexadecimal text is empty.");
            text.Add("Hex.BadChar", "Unrecognized character in hexadecimal text: \"{0}\".");
            text.Add("Hex.Odd", "Hexadecimal text must contain an even number of digits.");
            return text;
        }
    }
}
