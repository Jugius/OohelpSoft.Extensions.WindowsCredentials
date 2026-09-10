using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace OohelpSoft.WindowsCredentials;

public static class WindowsCredentialPrompt
{
    public static UserCredentials? Prompt(
        IntPtr? parentWindowHandle = null,
        string? message = null,
        string? caption = null)
    {
        var uiInfo = new NativeMethods.CREDUI_INFO
        {
            cbSize =
                (uint)Marshal.SizeOf<NativeMethods.CREDUI_INFO>(),

            hwndParent =
                parentWindowHandle ?? IntPtr.Zero,

            pszMessageText = message,
            pszCaptionText = caption,

            hbmBanner = IntPtr.Zero
        };

        uint authPackage = 0;
        var save = false;

        var result =
            NativeMethods.CredUIPromptForWindowsCredentials(
                ref uiInfo,
                0,
                ref authPackage,
                IntPtr.Zero,
                0,
                out var authBuffer,
                out var authBufferSize,
                ref save,
                NativeMethods.CREDUIWIN_GENERIC);

        if (result == NativeMethods.ERROR_CANCELLED)
        {
            return null;
        }

        if (result != NativeMethods.ERROR_SUCCESS)
        {
            throw new Win32Exception(
                (int)result,
                "Не удалось открыть окно ввода учетных данных.");
        }

        try
        {
            return UnpackCredentials(
                authBuffer,
                authBufferSize);
        }
        finally
        {
            if (authBuffer != IntPtr.Zero)
            {
                UnmanagedMemory.ZeroUnmanagedMemory(authBuffer, checked((int)authBufferSize));
                NativeMethods.CoTaskMemFree(authBuffer);
            }
        }
    }

    private static UserCredentials UnpackCredentials(
    IntPtr authBuffer,
    uint authBufferSize)
    {
        var userNameSize =
            NativeMethods.CREDUI_MAX_USERNAME_LENGTH + 1;

        var domainNameSize =
            NativeMethods.CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1;

        var passwordSize =
            NativeMethods.CREDUI_MAX_PASSWORD_LENGTH + 1;

        var userName = new StringBuilder(
            checked((int)userNameSize));

        var domainName = new StringBuilder(
            checked((int)domainNameSize));

        var password = new StringBuilder(
            checked((int)passwordSize));

        var result =
            NativeMethods.CredUnPackAuthenticationBuffer(
                0,
                authBuffer,
                authBufferSize,
                userName,
                ref userNameSize,
                domainName,
                ref domainNameSize,
                password,
                ref passwordSize);

        if (!result)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Не удалось получить учетные данные.");
        }

        var fullUserName = CombineUserName(userName.ToString(), domainName.ToString());

        return new UserCredentials(
            fullUserName,
            password.ToString());
    }
    private static string CombineUserName(string userName, string domainName)
    {
        if (string.IsNullOrWhiteSpace(userName))
        {
            throw new InvalidOperationException(
                "Windows не вернула имя пользователя.");
        }

        return string.IsNullOrWhiteSpace(domainName)
            ? userName
            : $"{domainName}\\{userName}";
    }

    private static class NativeMethods
    {
        public const uint ERROR_SUCCESS = 0;
        public const uint ERROR_CANCELLED = 1223;
        public const uint CREDUIWIN_GENERIC = 0x00000001;
        public const uint CREDUI_MAX_USERNAME_LENGTH = 513;
        public const uint CREDUI_MAX_DOMAIN_TARGET_LENGTH = 337;
        public const uint CREDUI_MAX_PASSWORD_LENGTH = 1280;

        [StructLayout(
            LayoutKind.Sequential,
            CharSet = CharSet.Unicode)]
        public struct CREDUI_INFO
        {
            public uint cbSize;
            public IntPtr hwndParent;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pszMessageText;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pszCaptionText;

            public IntPtr hbmBanner;
        }

        [DllImport(
            "credui.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        public static extern uint CredUIPromptForWindowsCredentials(
            ref CREDUI_INFO uiInfo,
            uint authError,
            ref uint authPackage,
            IntPtr inAuthBuffer,
            uint inAuthBufferSize,
            out IntPtr outAuthBuffer,
            out uint outAuthBufferSize,
            ref bool save,
            uint flags);

        [DllImport(
            "credui.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredUnPackAuthenticationBuffer(
            uint flags,
            IntPtr authBuffer,
            uint authBufferSize,
            StringBuilder userName,
            ref uint userNameSize,
            StringBuilder domainName,
            ref uint domainNameSize,
            StringBuilder password,
            ref uint passwordSize);

        [DllImport("ole32.dll")]
        public static extern void CoTaskMemFree(
            IntPtr pv);
    }
}
