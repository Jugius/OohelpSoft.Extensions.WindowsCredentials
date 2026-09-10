using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OohelpSoft.WindowsCredentials;

internal static class UnmanagedMemory
{
    private const int ZeroMemoryChunkSize = 4096;

    public static void ZeroUnmanagedMemory(
        IntPtr address,
        int size)
    {
        if (address == IntPtr.Zero || size <= 0)
            return;

        var zeroBytes = new byte[
            Math.Min(size, ZeroMemoryChunkSize)];

        try
        {
            var remaining = size;
            var currentAddress = address;

            while (remaining > 0)
            {
                var bytesToClear =
                    Math.Min(remaining, zeroBytes.Length);

                Marshal.Copy(
                    zeroBytes,
                    0,
                    currentAddress,
                    bytesToClear);

                currentAddress =
                    IntPtr.Add(currentAddress, bytesToClear);

                remaining -= bytesToClear;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zeroBytes);
        }
    }
}
