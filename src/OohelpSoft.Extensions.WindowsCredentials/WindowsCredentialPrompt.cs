using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OohelpSoft.WindowsCredentials;

public static class WindowsCredentialPrompt
{
    public static UserCredentials? Prompt(
        nint? parentWindowHandle = null,
        string? message = null,
        string? caption = null,
        string? initialUserName = null)
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

        nint inAuthBuffer = IntPtr.Zero;
        uint inAuthBufferSize = 0;

        if (!string.IsNullOrWhiteSpace(initialUserName))
        {
            inAuthBuffer = PackInitialCredentials(
                initialUserName,
                out inAuthBufferSize);
        }

        try
        {
            uint authPackage = 0;
            var save = false;

            var result =
                NativeMethods.CredUIPromptForWindowsCredentials(
                    ref uiInfo,
                    0,
                    ref authPackage,
                    inAuthBuffer,
                    inAuthBufferSize,
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
                    UnmanagedMemory.ZeroUnmanagedMemory(
                        authBuffer,
                        checked((int)authBufferSize));

                    NativeMethods.CoTaskMemFree(authBuffer);
                }
            }
        }
        finally
        {
            if (inAuthBuffer != IntPtr.Zero)
            {
                UnmanagedMemory.ZeroUnmanagedMemory(
                    inAuthBuffer,
                    checked((int)inAuthBufferSize));

                Marshal.FreeHGlobal(inAuthBuffer);
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

        var userName = new char[checked((int)userNameSize)];
        var domainName = new char[checked((int)domainNameSize)];
        var password = new char[checked((int)passwordSize)];

        try
        {
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

            var fullUserName = CombineUserName(
                GetNullTerminatedString(userName),
                GetNullTerminatedString(domainName));

            return new UserCredentials(
                fullUserName,
                GetNullTerminatedString(password));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                MemoryMarshal.AsBytes(userName.AsSpan()));

            CryptographicOperations.ZeroMemory(
                MemoryMarshal.AsBytes(domainName.AsSpan()));

            CryptographicOperations.ZeroMemory(
                MemoryMarshal.AsBytes(password.AsSpan()));
        }
    }
    private static string GetNullTerminatedString(
    char[] buffer)
    {
        var length = Array.IndexOf(buffer, '\0');

        return new string(
            buffer,
            0,
            length >= 0 ? length : buffer.Length);
    }
    private static string CombineUserName(string userName, string domainName)
    {
        return string.IsNullOrWhiteSpace(domainName)
            ? userName
            : $"{domainName}\\{userName}";
    }
    private static nint PackInitialCredentials(
    string userName,
    out uint bufferSize)
    {
        bufferSize = 0;

        NativeMethods.CredPackAuthenticationBuffer(
            0,
            userName,
            string.Empty,
            IntPtr.Zero,
            ref bufferSize);

        int error = Marshal.GetLastWin32Error();

        if (error != NativeMethods.ERROR_INSUFFICIENT_BUFFER)
        {
            throw new Win32Exception(
                error,
                "Не удалось определить размер буфера учетных данных.");
        }

        nint buffer = Marshal.AllocHGlobal(checked((int)bufferSize));

        if (!NativeMethods.CredPackAuthenticationBuffer(
            0,
            userName,
            string.Empty,
            buffer,
            ref bufferSize))
        {
            error = Marshal.GetLastWin32Error();

            Marshal.FreeHGlobal(buffer);

            throw new Win32Exception(
                error,
                "Не удалось подготовить буфер учетных данных.");
        }

        return buffer;
    }
    private static class NativeMethods
    {
        public const uint ERROR_SUCCESS = 0;
        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const uint ERROR_CANCELLED = 1223;
        public const uint CREDUIWIN_GENERIC = 0x00000001;
        public const uint CREDUI_MAX_USERNAME_LENGTH = 513;
        public const uint CREDUI_MAX_DOMAIN_TARGET_LENGTH = 337;
        public const uint CREDUI_MAX_PASSWORD_LENGTH = 1280;

        [StructLayout(
            LayoutKind.Sequential,
            CharSet = CharSet.Unicode)]

#pragma warning disable S101 // Types should be named in PascalCase
        public struct CREDUI_INFO
#pragma warning restore S101 // Types should be named in PascalCase
        {
            public uint cbSize;
            public IntPtr hwndParent;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pszMessageText;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pszCaptionText;

            public IntPtr hbmBanner;
        }

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
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

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredPackAuthenticationBuffer(
            uint dwFlags,
            string pszUserName,
            string pszPassword,
            IntPtr pPackedCredentials,
            ref uint pcbPackedCredentials);

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredUnPackAuthenticationBuffer(
            uint flags, 
            IntPtr authBuffer, 
            uint authBufferSize, 
            char[] userName, 
            ref uint userNameSize, 
            char[] domainName, 
            ref uint domainNameSize, 
            char[] password, 
            ref uint passwordSize);

        [DllImport("ole32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern void CoTaskMemFree(IntPtr pv);        
    }
}