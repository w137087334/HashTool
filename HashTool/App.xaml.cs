using System.Windows;
using HashTool.Hashing;

namespace HashTool
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            Locale.Initialize();
            base.OnStartup(e);
        }
    }
}
