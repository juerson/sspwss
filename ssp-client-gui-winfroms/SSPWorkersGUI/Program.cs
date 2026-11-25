using SSPWorkersGUI;

namespace SSPWorkersGUI
{
    internal static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            // 防止多开：已有一个实例在运行时，激活它的窗口并直接退出
            if (!SingleInstance.TryAcquire())
            {
                SingleInstance.ActivateExistingInstance();
                return;
            }

            // To customize application configuration such as set high DPI settings or default font,
            // see https://aka.ms/applicationconfiguration.
            ApplicationConfiguration.Initialize();
            Application.Run(new App());
        }
    }
}
