// Copyright (c) Arctium.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Arctium.WoW.Launcher.Patches;

static class Windows
{
    private const byte FILL = 0; // Marks a value that will be filled later
    private const byte NOOP = 0x90;

#if x64
    public static byte[] Integrity = { 0xC2, 0x00, 0x00 };
    public static byte[] CertBundle = { 0x90, 0x90 };
    public static byte[] CertCommonName = { 0xB0, 0x01 };
    public static byte[] ShortJump = { 0xEB };
    public static byte[] NoJump = { 0x00, 0x00, 0x00, 0x00 };
    public static byte[] AuthSeed =
    {
        // glorified memcpy(source: (IP+FILL), dest: rdx, length: 16)
        0x0F, 0x28, 0x05, FILL, FILL, FILL, FILL,   // movaps xmm0, [IP+FILL] (Will be filled with our SignatureModulusOffset) This instructions takes the first 16 byte of it
        0x0F, 0x11, 0x02,                           // movups [rdx], xmm0 // writes where rdx is pointing to
        0xC3                                        // ret
    };
#elif ARM64
    public static byte[] Integrity = { };
    public static byte[] Branch = { 0xB5 };
    public static byte[] CertCommonName = { 0x20 };
#endif

    // Registry entry used for -launcherlogin.
    public static byte[] LauncherLogin = Encoding.UTF8.GetBytes(@"Software\Custom Game Server Dev\Battle.net\Launch Options\");

    public static byte[] UseCustomBundleAsArgument(ulong certBundleAddr, int jmpOffset)
    {
        var replaceArgPatch = new byte[]
        {
            0x48, 0xBF, FILL, FILL, FILL, FILL, FILL, FILL, FILL, FILL, // movabs rdi, certBundleAddr
            0xE9, FILL, FILL, FILL, FILL,                               // jmp $+jmpOffset
        };
        Unsafe.WriteUnaligned(ref replaceArgPatch[2], certBundleAddr);
        Unsafe.WriteUnaligned(ref replaceArgPatch[11], jmpOffset);

        return replaceArgPatch;
    }
}
