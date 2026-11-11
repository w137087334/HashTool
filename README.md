# HashTool

计算文本和文件哈希的 Windows 桌面程序。一次可以选择多种算法，结果写回编辑框。

目标框架是 .NET Framework 4.0，界面用 WPF。发布为 64 位。

## 使用

1. 在编辑框输入文本，或在「文件」中指定路径。填了文件路径时优先计算文件。
2. 勾选算法。默认选中 MD5、CRC32、SHA-1、SHA-256。
3. 按 **Ctrl+Enter** 或点 **Compute**。计算过程中按钮变为 **Cancel**，**Esc** 也可以取消。
4. 点 **Copy result** 把结果复制到剪贴板。

文本按 UTF-8 读取。勾选 **Hex text** 后，编辑框按十六进制解析，可以含空格、逗号和 `0x` 前缀。文件可以直接拖进编辑框。双击一种算法会只选中它。

结果默认小写。勾选 **Uppercase** 后输出大写。

## 算法

共 51 种：

| 分组 | 算法 |
| --- | --- |
| MD | MD4、MD5、RIPEMD-160、HAS-160、eD2k |
| CRC | CRC32、CRC64 |
| SHA-1 | SHA-1 |
| SHA-2 | SHA-224、SHA-256、SHA-384、SHA-512 |
| SHA-3 | SHA3-224、SHA3-256、SHA3-384、SHA3-512 |
| SM3 | SM3 |
| BLAKE2 | BLAKE2s / BLAKE2sp（128–256）、BLAKE2b / BLAKE2bp（128–512） |
| BLAKE3 | BLAKE3-128 到 BLAKE3-512 |
| xxHash | XXH32、XXH64、XXH3-64、XXH3-128 |
| Streebog | Streebog-256、Streebog-512 |
| 其他 | QuickXor、Whirlpool |

MD5、SHA-1、SHA-256、SHA-384、SHA-512、RIPEMD-160 使用系统加密库。其余在程序内实现。

## 语言

界面内置英文。没有语言包时只有英文，也不会显示语言切换。

中文是可选语言包，源文件在 `HashTool/Lang/zh-CN.txt`，编译后复制到程序目录的 `Lang\zh-CN.txt`。文件存在时，算法栏右侧可以选择 **English** 或 **中文**。选择保存在 `%LocalAppData%\HashTool\language.txt`。语言包被移走后，即使上次选过中文，也会回到英文。

语言包是 UTF-8 文本，一行一条：

```
name=中文
WindowTitle=哈希计算
Compute=计算
```

`name` 是下拉框里的显示名。以 `#` 或 `;` 开头的行是注释。语言包里没有的条目回退到英文。

## 编译和测试

需要 .NET SDK（用于编译 `net40`）以及能运行 .NET Framework 4.x 的 Windows。

```powershell
dotnet build HashTool.sln -c Release
dotnet run --project HashTool.Tests -c Release --no-build
```

程序输出在 `HashTool\bin\Release\net40\HashTool.exe`。测试用 `HashTool.Tests\Vectors.txt` 里的向量核对全部算法，并检查流式更新、十六进制解析和语言包加载。
