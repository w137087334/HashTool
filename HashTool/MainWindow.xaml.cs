using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using HashTool.Hashing;
using Microsoft.Win32;

namespace HashTool
{
    public partial class MainWindow : Window
    {
        private const int BufferSize = 4 * 1024 * 1024;
        private const int ProgressIntervalMs = 100;

        private readonly List<AlgorithmGroup> _groups = new List<AlgorithmGroup>();
        private string _sourceText;
        private bool _suppressTextChanged;
        private bool _updatingChecks;
        private bool _running;
        private bool _suppressLanguage;
        private CancellationTokenSource _cancel;
        private string _statusKey = "Ready";
        private object[] _statusArgs = new object[0];

        public MainWindow()
        {
            Locale.Initialize();
            InitializeComponent();
            BuildAlgorithms();
            BindLanguageBox();
            ApplyLanguage();
        }

        private void BuildAlgorithms()
        {
            List<AlgorithmGroup>[] columns = new List<AlgorithmGroup>[]
            {
                new List<AlgorithmGroup>(),
                new List<AlgorithmGroup>(),
                new List<AlgorithmGroup>()
            };
            AlgorithmGroup group = null;
            foreach (HashDefinition definition in HashCatalog.All)
            {
                if (group == null || group.Name != definition.Group)
                {
                    group = new AlgorithmGroup(definition.Group);
                    _groups.Add(group);
                    columns[ColumnOf(definition.Group)].Add(group);
                }
                group.Children.Add(CreateAlgorithmBox(definition, group));
            }

            int rowCount = 0;
            foreach (List<AlgorithmGroup> column in columns)
            {
                if (column.Count > rowCount)
                {
                    rowCount = column.Count;
                }
            }

            for (int row = 0; row < rowCount; row++)
            {
                AlgorithmBoard.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                for (int column = 0; column < columns.Length; column++)
                {
                    bool showLine = row < rowCount - 1;
                    UIElement cell = row < columns[column].Count
                        ? CreateGroupCell(columns[column][row], showLine)
                        : BlankCell(showLine);
                    Put(cell, column, row, 1);
                }
            }

            for (int column = 1; column < columns.Length; column++)
            {
                Border divider = BlankCell(false);
                divider.BorderThickness = new Thickness(1, 0, 0, 0);
                divider.HorizontalAlignment = HorizontalAlignment.Left;
                divider.Width = 1;
                Put(divider, column, 0, rowCount);
            }

            foreach (AlgorithmGroup item in _groups)
            {
                RefreshGroup(item);
            }
        }

        private static int ColumnOf(string group)
        {
            switch (group)
            {
                case "MD":
                case "CRC":
                case "SHA-1":
                case "SHA-2":
                case "SM3":
                    return 0;
                case "SHA-3":
                case "xxHash":
                case "Streebog":
                case "其他":
                    return 1;
                default:
                    return 2;
            }
        }

        private CheckBox CreateAlgorithmBox(HashDefinition definition, AlgorithmGroup group)
        {
            CheckBox box = new CheckBox
            {
                Content = ShortLabel(definition),
                IsChecked = definition.SelectedByDefault,
                Margin = new Thickness(0, 0, 6, 0),
                Padding = new Thickness(2, 0, 0, 0),
                ToolTip = Locale.Format("AlgorithmTip", definition.Name),
                Tag = definition
            };
            RoutedEventHandler changed = delegate { OnAlgorithmChanged(group); };
            box.Checked += changed;
            box.Unchecked += changed;
            box.MouseDoubleClick += delegate { SelectOnly(box); };
            return box;
        }

        private static string ShortLabel(HashDefinition definition)
        {
            int dash = definition.Name.LastIndexOf('-');
            int number;
            if (dash <= 0 || !int.TryParse(definition.Name.Substring(dash + 1), out number))
            {
                return definition.Name;
            }

            string prefix = definition.Name.Substring(0, dash + 1);
            int matches = 0;
            foreach (HashDefinition other in HashCatalog.All)
            {
                if (other.Group != definition.Group)
                {
                    continue;
                }
                if (!other.Name.StartsWith(prefix) || !int.TryParse(other.Name.Substring(prefix.Length), out number))
                {
                    return definition.Name;
                }
                matches++;
            }
            return matches >= 2 ? definition.Name.Substring(dash + 1) : definition.Name;
        }

        private UIElement CreateGroupCell(AlgorithmGroup group, bool showBottomBorder)
        {
            CheckBox header = new CheckBox
            {
                Content = DisplayGroup(group.Name),
                FontWeight = FontWeights.SemiBold,
                IsThreeState = true,
                VerticalAlignment = VerticalAlignment.Center
            };
            header.Click += delegate { OnGroupClick(group); };
            group.Header = header;

            WrapPanel options = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
            foreach (CheckBox box in group.Children)
            {
                options.Children.Add(box);
            }

            Grid grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(96) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.Children.Add(new Border
            {
                BorderBrush = LineBrush,
                BorderThickness = new Thickness(0, 0, 1, 0),
                Background = (Brush)FindResource("WindowBrush"),
                Padding = new Thickness(8, 4, 6, 4),
                Child = header
            });
            Border optionCell = new Border { Padding = new Thickness(8, 3, 6, 3), Child = options };
            Grid.SetColumn(optionCell, 1);
            grid.Children.Add(optionCell);

            Border shell = BlankCell(showBottomBorder);
            shell.Child = grid;
            return shell;
        }

        private Border BlankCell(bool showBottomBorder)
        {
            return new Border
            {
                BorderBrush = LineBrush,
                BorderThickness = new Thickness(0, 0, 0, showBottomBorder ? 1 : 0)
            };
        }

        private Brush LineBrush
        {
            get { return (Brush)FindResource("LineBrush"); }
        }

        private void Put(UIElement element, int column, int row, int rowSpan)
        {
            Grid.SetColumn(element, column);
            Grid.SetRow(element, row);
            if (rowSpan > 1)
            {
                Grid.SetRowSpan(element, rowSpan);
            }
            AlgorithmBoard.Children.Add(element);
        }

        private void OnAlgorithmChanged(AlgorithmGroup group)
        {
            if (_updatingChecks)
            {
                return;
            }
            RefreshGroup(group);
            UpdateSelectionText();
        }

        private void OnGroupClick(AlgorithmGroup group)
        {
            if (_updatingChecks)
            {
                return;
            }

            bool check = false;
            foreach (CheckBox child in group.Children)
            {
                if (child.IsChecked != true)
                {
                    check = true;
                    break;
                }
            }

            SetChecks(group.Children, check);
            RefreshGroup(group);
            UpdateSelectionText();
        }

        private void RefreshGroup(AlgorithmGroup group)
        {
            bool all = true;
            bool any = false;
            foreach (CheckBox child in group.Children)
            {
                if (child.IsChecked == true)
                {
                    any = true;
                }
                else
                {
                    all = false;
                }
            }

            _updatingChecks = true;
            group.Header.IsChecked = all ? true : any ? (bool?)null : false;
            _updatingChecks = false;
        }

        private void SelectOnly(CheckBox target)
        {
            _updatingChecks = true;
            foreach (AlgorithmGroup group in _groups)
            {
                foreach (CheckBox box in group.Children)
                {
                    box.IsChecked = box == target;
                }
            }
            _updatingChecks = false;
            foreach (AlgorithmGroup group in _groups)
            {
                RefreshGroup(group);
            }
            UpdateSelectionText();
        }

        private void SelectAllButton_Click(object sender, RoutedEventArgs e)
        {
            SetAll(true);
        }

        private void SelectNoneButton_Click(object sender, RoutedEventArgs e)
        {
            SetAll(false);
        }

        private void SetAll(bool selected)
        {
            foreach (AlgorithmGroup group in _groups)
            {
                SetChecks(group.Children, selected);
                RefreshGroup(group);
            }
            UpdateSelectionText();
        }

        private void SetChecks(IList<CheckBox> boxes, bool selected)
        {
            _updatingChecks = true;
            foreach (CheckBox box in boxes)
            {
                box.IsChecked = selected;
            }
            _updatingChecks = false;
        }

        private void UpdateSelectionText()
        {
            int selected = 0;
            int total = 0;
            foreach (AlgorithmGroup group in _groups)
            {
                foreach (CheckBox box in group.Children)
                {
                    total++;
                    if (box.IsChecked == true)
                    {
                        selected++;
                    }
                }
            }
            SelectionText.Text = Locale.Format("Selected", selected, total);
        }

        private void BindLanguageBox()
        {
            _suppressLanguage = true;
            LanguageBox.ItemsSource = Locale.Available;
            LanguageBox.SelectedValue = Locale.CurrentId;
            LanguageBox.Visibility = Locale.HasPack ? Visibility.Visible : Visibility.Collapsed;
            _suppressLanguage = false;
        }

        private void LanguageBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_suppressLanguage)
            {
                return;
            }

            LanguageInfo info = LanguageBox.SelectedItem as LanguageInfo;
            if (info == null || info.Id == Locale.CurrentId)
            {
                return;
            }

            if (!Locale.Select(info.Id, true))
            {
                _suppressLanguage = true;
                LanguageBox.SelectedValue = Locale.CurrentId;
                _suppressLanguage = false;
                return;
            }

            ApplyLanguage();
        }

        private void ApplyLanguage()
        {
            Title = Locale.Get("WindowTitle");
            HexBox.Content = Locale.Get("HexInput");
            HexBox.ToolTip = Locale.Get("HexInputTip");
            UpperBox.Content = Locale.Get("Uppercase");
            ComputeButton.Content = _running ? Locale.Get("Cancel") : Locale.Get("Compute");
            CopyButton.Content = Locale.Get("Copy");
            ClearTextButton.Content = Locale.Get("ClearText");
            FileLabel.Text = Locale.Get("File");
            ClearFileButton.Content = Locale.Get("Clear");
            BrowseButton.Content = Locale.Get("Browse");
            HintText.Text = Locale.Get("Hint");
            AlgorithmLabel.Text = Locale.Get("Algorithms");
            SelectAllButton.Content = Locale.Get("SelectAll");
            SelectNoneButton.Content = Locale.Get("SelectNone");
            LanguageBox.ToolTip = Locale.Get("LanguageTip");
            foreach (AlgorithmGroup group in _groups)
            {
                group.Header.Content = DisplayGroup(group.Name);
                foreach (CheckBox box in group.Children)
                {
                    HashDefinition definition = (HashDefinition)box.Tag;
                    box.ToolTip = Locale.Format("AlgorithmTip", definition.Name);
                }
            }
            UpdateSelectionText();
            ApplyStatus();
        }

        private static string DisplayGroup(string name)
        {
            return name == "其他" ? Locale.Get("Group.Other") : name;
        }

        private void SetStatus(string key, params object[] args)
        {
            _statusKey = key;
            _statusArgs = args == null || args.Length == 0 ? new object[0] : (object[])args.Clone();
            ApplyStatus();
        }

        private void ApplyStatus()
        {
            StatusText.Text = _statusArgs.Length == 0
                ? Locale.Get(_statusKey)
                : Locale.Format(_statusKey, _statusArgs);
        }

        private void ClearTextButton_Click(object sender, RoutedEventArgs e)
        {
            _sourceText = null;
            _suppressTextChanged = true;
            InputBox.Clear();
            _suppressTextChanged = false;
            SetStatus("ClearedText");
        }

        private void ClearFileButton_Click(object sender, RoutedEventArgs e)
        {
            FilePathBox.Clear();
            SetStatus("ClearedFile");
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = Locale.Get("AllFiles");
            dialog.Title = Locale.Get("BrowseTitle");
            if (dialog.ShowDialog(this) == true)
            {
                FilePathBox.Text = dialog.FileName;
                SetStatus("FileChosen");
            }
        }

        private void InputBox_PreviewDragOver(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                e.Handled = true;
            }
        }

        private void InputBox_Drop(object sender, DragEventArgs e)
        {
            if (!e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                return;
            }

            string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (files == null || files.Length == 0)
            {
                return;
            }

            string file = null;
            for (int i = 0; i < files.Length; i++)
            {
                if (File.Exists(files[i]))
                {
                    file = files[i];
                    break;
                }
            }

            if (file == null)
            {
                SetStatus("DropNeedFile");
                e.Handled = true;
                return;
            }

            FilePathBox.Text = file;
            if (files.Length == 1)
            {
                SetStatus("DroppedOne");
            }
            else
            {
                SetStatus("DroppedMany", files.Length);
            }
            e.Handled = true;
        }

        private void InputBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!_suppressTextChanged)
            {
                _sourceText = null;
            }
        }

        private void CopyButton_Click(object sender, RoutedEventArgs e)
        {
            string text = InputBox.Text;
            if (string.IsNullOrEmpty(text))
            {
                SetStatus("NothingToCopy");
                return;
            }
            try
            {
                Clipboard.SetText(text);
                SetStatus("Copied");
            }
            catch (ExternalException)
            {
                SetStatus("ClipboardBusy");
            }
        }

        private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.Control)
            {
                if (!_running)
                {
                    StartCompute();
                }
                e.Handled = true;
            }
            else if (e.Key == Key.Escape && _running)
            {
                CancelCompute();
                e.Handled = true;
            }
        }

        private void ComputeButton_Click(object sender, RoutedEventArgs e)
        {
            if (_running)
            {
                CancelCompute();
            }
            else
            {
                StartCompute();
            }
        }

        private void CancelCompute()
        {
            if (_cancel != null && !_cancel.IsCancellationRequested)
            {
                _cancel.Cancel();
                SetStatus("Cancelling");
            }
        }

        private void StartCompute()
        {
            List<HashDefinition> selected = SelectedDefinitions();
            if (selected.Count == 0)
            {
                MessageBox.Show(this, Locale.Get("NeedAlgorithm"), Locale.Get("WindowTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string path = FilePathBox.Text == null ? string.Empty : FilePathBox.Text.Trim();
            bool fromFile = path.Length > 0;
            bool hex = HexBox.IsChecked == true;
            bool upper = UpperBox.IsChecked == true;
            string text = _sourceText ?? InputBox.Text ?? string.Empty;
            if (fromFile && !File.Exists(path))
            {
                MessageBox.Show(this, Locale.Format("FileMissing", path), Locale.Get("WindowTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            CancellationTokenSource cancel = new CancellationTokenSource();
            CancellationToken token = cancel.Token;
            _cancel = cancel;
            _running = true;
            ComputeButton.Content = Locale.Get("Cancel");
            SetStatus("Computing");
            ComputeProgress.Value = 0;
            ComputeProgress.IsIndeterminate = !fromFile;
            ComputeProgress.Visibility = Visibility.Visible;

            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    Stopwatch watch = Stopwatch.StartNew();
                    List<HashFunction> functions = new List<HashFunction>();
                    for (int i = 0; i < selected.Count; i++)
                    {
                        HashFunction function = selected[i].Create();
                        function.Initialize();
                        functions.Add(function);
                    }

                    long size;
                    if (fromFile)
                    {
                        size = HashFile(path, functions, token);
                    }
                    else
                    {
                        byte[] data = hex
                            ? HexCodec.Parse(text)
                            : new UTF8Encoding(false).GetBytes(text);
                        size = data.LongLength;
                        token.ThrowIfCancellationRequested();
                        UpdateAll(functions, data, 0, data.Length);
                    }
                    token.ThrowIfCancellationRequested();

                    List<byte[]> digests = new List<byte[]>();
                    for (int i = 0; i < functions.Count; i++)
                    {
                        digests.Add(functions[i].FinalizeHash());
                    }
                    watch.Stop();
                    string report = FormatReport(fromFile, path, text, hex, size, watch.Elapsed, selected, digests, upper);

                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        _sourceText = text;
                        _suppressTextChanged = true;
                        InputBox.Text = report;
                        InputBox.CaretIndex = 0;
                        InputBox.ScrollToHome();
                        _suppressTextChanged = false;
                        FinishCompute("Done", FormatElapsed(watch.Elapsed));
                    }));
                }
                catch (OperationCanceledException)
                {
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        FinishCompute("Cancelled");
                    }));
                }
                catch (FormatException ex)
                {
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        FinishCompute("HexInvalid");
                        MessageBox.Show(this, ex.Message, Locale.Get("HexTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
                    }));
                }
                catch (Exception ex)
                {
                    Exception cause = Unwrap(ex);
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        FinishCompute("Failed");
                        MessageBox.Show(this, Locale.Format("FailedDetail", cause.Message), Locale.Get("WindowTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
                    }));
                }
            });
        }

        private static Exception Unwrap(Exception ex)
        {
            AggregateException aggregate = ex as AggregateException;
            return aggregate != null ? aggregate.Flatten().InnerExceptions[0] : ex;
        }

        private void FinishCompute(string key, params object[] args)
        {
            _running = false;
            if (_cancel != null)
            {
                _cancel.Dispose();
                _cancel = null;
            }
            ComputeButton.Content = Locale.Get("Compute");
            SetStatus(key, args);
            ComputeProgress.IsIndeterminate = false;
            ComputeProgress.Visibility = Visibility.Collapsed;
        }

        private long HashFile(string path, List<HashFunction> functions, CancellationToken token)
        {
            byte[] current = new byte[BufferSize];
            byte[] next = new byte[BufferSize];
            long[] costs = new long[functions.Count];
            long processed = 0;
            Stopwatch sinceReport = Stopwatch.StartNew();
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096,
                FileOptions.SequentialScan | FileOptions.Asynchronous))
            {
                long length = stream.Length;
                int read = stream.Read(current, 0, current.Length);
                while (read > 0)
                {
                    token.ThrowIfCancellationRequested();
                    IAsyncResult pending = stream.BeginRead(next, 0, next.Length, null, null);
                    int nextRead;
                    try
                    {
                        UpdateAll(functions, current, 0, read, costs);
                    }
                    finally
                    {
                        nextRead = stream.EndRead(pending);
                    }

                    processed += read;
                    byte[] swap = current;
                    current = next;
                    next = swap;
                    read = nextRead;

                    if (sinceReport.ElapsedMilliseconds >= ProgressIntervalMs || read == 0)
                    {
                        sinceReport.Reset();
                        sinceReport.Start();
                        long shown = processed;
                        long total = Math.Max(length, processed);
                        double percent = total > 0 ? shown * 100.0 / total : 100;
                        Dispatcher.BeginInvoke(new Action(delegate
                        {
                            if (!_running || token.IsCancellationRequested)
                            {
                                return;
                            }
                            ComputeProgress.Value = percent;
                            SetStatus("Progress", percent.ToString("0"), shown.ToString("N0"), total.ToString("N0"));
                        }));
                    }
                }
            }
            return processed;
        }

        private static void UpdateAll(List<HashFunction> functions, byte[] data, int offset, int count)
        {
            UpdateAll(functions, data, offset, count, new long[functions.Count]);
        }

        private static void UpdateAll(List<HashFunction> functions, byte[] data, int offset, int count, long[] costs)
        {
            if (count <= 0)
            {
                return;
            }
            if (functions.Count == 1)
            {
                functions[0].Update(data, offset, count);
                return;
            }

            int[] order = new int[functions.Count];
            long[] keys = new long[functions.Count];
            for (int i = 0; i < order.Length; i++)
            {
                order[i] = i;
                keys[i] = -costs[i];
            }
            Array.Sort(keys, order);

            Parallel.ForEach(Partitioner.Create(0, order.Length, 1), delegate(System.Tuple<int, int> range)
            {
                for (int index = range.Item1; index < range.Item2; index++)
                {
                    int target = order[index];
                    long start = Stopwatch.GetTimestamp();
                    functions[target].Update(data, offset, count);
                    costs[target] = Stopwatch.GetTimestamp() - start;
                }
            });
        }

        private List<HashDefinition> SelectedDefinitions()
        {
            List<HashDefinition> selected = new List<HashDefinition>();
            foreach (AlgorithmGroup group in _groups)
            {
                foreach (CheckBox box in group.Children)
                {
                    if (box.IsChecked == true)
                    {
                        selected.Add((HashDefinition)box.Tag);
                    }
                }
            }
            return selected;
        }

        private static string FormatReport(
            bool fromFile,
            string path,
            string text,
            bool hex,
            long size,
            TimeSpan elapsed,
            List<HashDefinition> selected,
            List<byte[]> digests,
            bool upper)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine(fromFile ? Locale.Get("Report.SourceFile") : Locale.Get("Report.SourceText"));
            if (fromFile)
            {
                builder.AppendLine(Locale.Format("Report.Path", path));
            }
            else
            {
                builder.AppendLine(Locale.Format("Report.Encoding", hex ? Locale.Get("Report.Hex") : "UTF-8"));
            }
            builder.AppendLine(Locale.Format("Report.Size", size.ToString("N0")));
            builder.AppendLine(Locale.Format("Report.Time", FormatElapsed(elapsed)));
            builder.AppendLine(Locale.Format("Report.Count", selected.Count));

            string group = null;
            for (int i = 0; i < selected.Count; i++)
            {
                if (group != selected[i].Group)
                {
                    group = selected[i].Group;
                    builder.AppendLine();
                    builder.AppendLine(DisplayGroup(group));
                }
                builder.AppendLine("  " + selected[i].Name);
                builder.AppendLine("    " + HexCodec.ToHex(digests[i], upper));
            }

            if (!fromFile && text != null && text.Length == 0)
            {
                builder.AppendLine();
                builder.AppendLine(Locale.Get("Report.Empty"));
            }
            return builder.ToString();
        }

        private static string FormatElapsed(TimeSpan elapsed)
        {
            if (elapsed.TotalMilliseconds < 1000)
            {
                return Locale.Format("Elapsed.Ms", Math.Max(0, (int)elapsed.TotalMilliseconds));
            }
            return Locale.Format("Elapsed.Sec", elapsed.TotalSeconds.ToString("0.00"));
        }

        private sealed class AlgorithmGroup
        {
            public AlgorithmGroup(string name)
            {
                Name = name;
                Children = new List<CheckBox>();
            }

            public string Name { get; private set; }

            public CheckBox Header { get; set; }

            public List<CheckBox> Children { get; private set; }
        }
    }
}
