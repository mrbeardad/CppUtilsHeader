#include "utils.hpp"

#include <cassert>
#include <sstream>
#include <type_traits>

int main()
{
    auto noop = [] {};
    static_assert(std::is_nothrow_move_constructible_v<util::detail::ScopeExit<decltype(noop)>>);

    util::SimpleSpinLock lock;
    assert(util::EncodeBase64("hello") == "aGVsbG8=");
    assert(util::DecodeBase64("aGVsbG8=") == std::optional<std::string>{"hello"});
    assert(!util::DecodeBase64("not valid!"));
    struct BinaryRecord
    {
        uint16_t first;
        uint32_t second;
    };
    static_assert(std::is_trivially_copyable_v<BinaryRecord>);
    std::ostringstream binary;
    util::write(binary, BinaryRecord{0x1234, 0x12345678});
    util::write(binary, std::string_view{"xy", 2});
    assert(binary.str().size() == sizeof(BinaryRecord) + 2);
    (void)&util::WriteFileBytes;

    const wchar_t wideText[] = L"hi";
    std::string wideBytes(reinterpret_cast<const char*>(wideText), sizeof(wideText));
    std::istringstream wideInput(wideBytes);
    assert(util::read<std::wstring>(wideInput) == L"hi");

#ifdef _WIN32
    (void)&util::ScopedComInitializer::IsInitialized;
    (void)&util::EnsureGdiplusStarted;
    (void)&util::GetShellItemIconDataUrl;
    (void)&util::GetShellItemIconBitmap;
    (void)&util::BitmapToIcoFile;
    (void)&util::BitmapToPngFile;
    (void)&util::BitmapToPngDataUrl;
#endif

    return 0;
}
