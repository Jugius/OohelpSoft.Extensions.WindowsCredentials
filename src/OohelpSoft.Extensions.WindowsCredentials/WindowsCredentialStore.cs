using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace OohelpSoft.WindowsCredentials;
public sealed class WindowsCredentialStore
{
    private const uint CredentialTypeGeneric = 1;
    private const uint CredentialPersistLocalMachine = 2;
    private const int ErrorNotFound = 1168;
    private const int MaxCredentialBlobSize = 2560;
    private const int MaxGenericTargetNameLength = 32767;

    private readonly string _targetName;

    public WindowsCredentialStore(string targetName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);

        if (targetName.Length > MaxGenericTargetNameLength)
        {
            throw new ArgumentException(
                $"Target name cannot be longer than " +
                $"{MaxGenericTargetNameLength} characters.",
                nameof(targetName));
        }

        _targetName = targetName;
    }

    public void Save(UserCredentials credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        var passwordBytes =
            Encoding.Unicode.GetBytes(credentials.Password);

        if (passwordBytes.Length > MaxCredentialBlobSize)
        {
            CryptographicOperations.ZeroMemory(passwordBytes);

            throw new ArgumentException(
                $"Password is too long. " +
                $"Credential blob cannot exceed " +
                $"{MaxCredentialBlobSize} bytes.",
                nameof(credentials));
        }

        IntPtr targetNamePtr = IntPtr.Zero;
        IntPtr userNamePtr = IntPtr.Zero;
        IntPtr credentialBlobPtr = IntPtr.Zero;

        try
        {
            targetNamePtr =
                Marshal.StringToCoTaskMemUni(_targetName);

            userNamePtr =
                Marshal.StringToCoTaskMemUni(credentials.UserName);

            if (passwordBytes.Length > 0)
            {
                credentialBlobPtr =
                    Marshal.AllocHGlobal(passwordBytes.Length);

                Marshal.Copy(
                    passwordBytes,
                    0,
                    credentialBlobPtr,
                    passwordBytes.Length);
            }

            var credential = new NativeMethods.CREDENTIAL
            {
                Flags = 0,
                Type = CredentialTypeGeneric,

                TargetName = targetNamePtr,

                Comment = IntPtr.Zero,

                LastWritten = default,

                CredentialBlobSize =
                    (uint)passwordBytes.Length,

                CredentialBlob =
                    credentialBlobPtr,

                Persist =
                    CredentialPersistLocalMachine,

                AttributeCount = 0,
                Attributes = IntPtr.Zero,

                TargetAlias = IntPtr.Zero,

                UserName = userNamePtr
            };

            if (!NativeMethods.CredWrite(
                    ref credential,
                    0))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Не удалось сохранить учетные данные Windows.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);

            if (credentialBlobPtr != IntPtr.Zero)
            {
                UnmanagedMemory.ZeroUnmanagedMemory(
                    credentialBlobPtr,
                    passwordBytes.Length);

                Marshal.FreeHGlobal(credentialBlobPtr);
            }

            if (userNamePtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(userNamePtr);
            }

            if (targetNamePtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(targetNamePtr);
            }
        }
    }

    public UserCredentials? GetCredentials()
    {
        if (!NativeMethods.CredRead(
                _targetName,
                CredentialTypeGeneric,
                0,
                out var credentialPtr))
        {
            var error = Marshal.GetLastWin32Error();

            if (error == ErrorNotFound)
            {
                return null;
            }

            throw new Win32Exception(
                error,
                "Не удалось прочитать учетные данные Windows.");
        }

        try
        {
            var credential =
                Marshal.PtrToStructure<NativeMethods.CREDENTIAL>(
                    credentialPtr);

            var userName =
                Marshal.PtrToStringUni(
                    credential.UserName);

            if (string.IsNullOrWhiteSpace(userName))
            {
                throw new InvalidOperationException(
                    "Windows Credential Manager не содержит имени пользователя.");
            }

            if (credential.CredentialBlobSize >
                MaxCredentialBlobSize)
            {
                throw new InvalidOperationException(
                    "Размер сохраненного CredentialBlob превышает " +
                    "допустимый размер.");
            }

            if (credential.CredentialBlobSize == 0)
            {
                return new UserCredentials(
                    userName,
                    string.Empty);
            }

            if (credential.CredentialBlob == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    "CredentialBlob имеет нулевой указатель.");
            }

            if (credential.CredentialBlobSize % 2 != 0)
            {
                throw new InvalidOperationException(
                    "CredentialBlob содержит некорректное количество " +
                    "байт для UTF-16 строки.");
            }
            
            var passwordSize = checked((int)credential.CredentialBlobSize);
            var passwordBytes = new byte[passwordSize];            

            try
            {
                Marshal.Copy(
                    credential.CredentialBlob,
                    passwordBytes,
                    0,
                    passwordBytes.Length);

                var password =
                    Encoding.Unicode.GetString(passwordBytes);

                return new UserCredentials(
                    userName,
                    password);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    passwordBytes);
                UnmanagedMemory.ZeroUnmanagedMemory(credential.CredentialBlob, checked((int)credential.CredentialBlobSize));
            }
        }
        finally
        {
            NativeMethods.CredFree(credentialPtr);
        }
    }

    public void Delete()
    {
        if (NativeMethods.CredDelete(
                _targetName,
                CredentialTypeGeneric,
                0))
        {
            return;
        }

        var error = Marshal.GetLastWin32Error();

        if (error == ErrorNotFound)
        {
            return;
        }

        throw new Win32Exception(
            error,
            "Не удалось удалить учетные данные Windows.");
    }

    private static class NativeMethods
    {
        [StructLayout(
            LayoutKind.Sequential,
            CharSet = CharSet.Unicode)]
        public struct CREDENTIAL
        {
            public uint Flags;
            public uint Type;

            public IntPtr TargetName;
            public IntPtr Comment;

            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;

            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;

            public uint Persist;

            public uint AttributeCount;
            public IntPtr Attributes;

            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        [DllImport(
            "advapi32.dll",
            EntryPoint = "CredWriteW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredWrite(
            ref CREDENTIAL credential,
            uint flags);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "CredReadW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredRead(
            string targetName,
            uint type,
            uint flags,
            out IntPtr credential);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "CredDeleteW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredDelete(
            string targetName,
            uint type,
            uint flags);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "CredFree")]
        public static extern void CredFree(
            IntPtr credential);
    }
}
