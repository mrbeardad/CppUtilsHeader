#pragma once

#ifndef MRBEARDAD_UTILS_H
#define MRBEARDAD_UTILS_H

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <ShlObj.h>
#include <TlHelp32.h>
#include <combaseapi.h>
#include <gdiplus.h>
#include <sddl.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <winternl.h>
#endif // _WIN32

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iosfwd>
#include <limits>
#include <optional>
#include <random>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

using namespace std::literals::string_literals;
using namespace std::literals::string_view_literals;
using namespace std::literals::chrono_literals;

namespace util
{

// ============================================================================
// Scope Exit
// ============================================================================

namespace detail
{

enum class ScopeExitDummy
{
};

template <typename T>
class ScopeExit
{
    T f_;

  public:
    ScopeExit(T&& codeChunk_) : f_(std::forward<T>(codeChunk_))
    {
    }

    ScopeExit(ScopeExit<T>&& other) noexcept(std::is_nothrow_move_constructible_v<T>) : f_(std::move(other.f_))
    {
    }

    ~ScopeExit()
    {
        f_();
    }
};

template <typename T>
ScopeExit<T> operator+(ScopeExitDummy, T&& functor_)
{
    return ScopeExit<T>{std::forward<T>(functor_)};
}

} // namespace detail

#define STR_CONCAT_IMPL(x, y) x##y
#define STR_CONCAT(x, y) STR_CONCAT_IMPL(x, y)
#define UNIQUE_VARIABLE_NAME(prefix) STR_CONCAT(prefix, __LINE__)
#define defer auto UNIQUE_VARIABLE_NAME(_scope_exit_) = util::detail::ScopeExitDummy{} + [&]()

// ============================================================================
// Synchronization
// ============================================================================

class SimpleSpinLock
{
    std::atomic_flag locked = ATOMIC_FLAG_INIT;

  public:
    void lock()
    {
        while (locked.test_and_set(std::memory_order_acquire))
        {
            ;
        }
    }

    void unlock()
    {
        locked.clear(std::memory_order_release);
    }
};

class SpinLock
{
    std::atomic_bool locked_ = false;

    static constexpr size_t MAX_WAIT_ITERS = 4096;
    static constexpr size_t MIN_BACKOFF_ITERS = 8;
    static constexpr size_t MAX_BACKOFF_ITERS = 1024;

  public:
    FORCEINLINE void lock()
    {
        size_t curMaxDelay = MIN_BACKOFF_ITERS;

        while (true)
        {
            // WaitUntilLockIsFree();

            if (locked_.exchange(true, std::memory_order_acquire))
                BackoffExp(curMaxDelay);
            else
                break;
        }
    }

    FORCEINLINE bool try_lock() noexcept
    {
        return !locked_.exchange(true, std::memory_order_acquire);
    }

    FORCEINLINE void unlock()
    {
        locked_.store(false, std::memory_order_release);
    }

  private:
    FORCEINLINE static void CpuRelax()
    {
#ifdef _MSC_VER
        _mm_pause();
#elif defined(__GUNC__) || defined(__clang__)
        asm("pause");
#endif
    }

    FORCEINLINE static void YieldSleep()
    {
        std::this_thread::sleep_for(500us);
    }

    FORCEINLINE static void BackoffExp(size_t& curMaxIters)
    {
        thread_local std::minstd_rand gen(std::random_device{}());
        thread_local std::uniform_int_distribution<size_t> dist;

        const size_t spinIters = dist(gen, decltype(dist)::param_type{0, curMaxIters});
        curMaxIters = std::min(2 * curMaxIters, MAX_BACKOFF_ITERS);

        for (size_t i = 0; i < spinIters; i++)
            CpuRelax();
    }

    FORCEINLINE void WaitUntilLockIsFree() const
    {
        size_t numIters = 0;

        while (locked_.load(std::memory_order_relaxed))
        {
            if (numIters < MAX_WAIT_ITERS)
            {
                numIters++;
                CpuRelax();
            }
            else
            {
                YieldSleep();
            }
        }
    }
};

// ============================================================================
// Encoding
// ============================================================================

inline int char2byte(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    return -1;
}

inline std::string hex2bin(std::string_view hex)
{
    std::string data;
    if (hex.size() % 2 != 0)
    {
        return data;
    }

    data.assign(hex.size() / 2, '\0');
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        int hi = char2byte(hex[i]);
        int lo = char2byte(hex[i + 1]);
        if (hi == -1 || lo == -1)
        {
            data.clear();
            return data;
        }
        data[i / 2] = static_cast<char>((hi << 4) | lo);
    }
    return data;
}

inline std::string bin2hex(std::string_view data, bool upperCase = false)
{
    std::string hex;
    for (char c : data)
    {
        hex += upperCase ? std::format("{:02X}", c) : std::format("{:02x}", c);
    }

    return hex;
}

inline std::string EncodeBase64(std::string_view data)
{
    static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((data.size() + 2) / 3) * 4);

    for (size_t i = 0; i < data.size(); i += 3)
    {
        uint32_t value = static_cast<uint32_t>(static_cast<unsigned char>(data[i])) << 16;
        if (i + 1 < data.size())
        {
            value |= static_cast<uint32_t>(static_cast<unsigned char>(data[i + 1])) << 8;
        }
        if (i + 2 < data.size())
        {
            value |= static_cast<uint32_t>(static_cast<unsigned char>(data[i + 2]));
        }

        output.push_back(table[(value >> 18) & 0x3F]);
        output.push_back(table[(value >> 12) & 0x3F]);
        output.push_back(i + 1 < data.size() ? table[(value >> 6) & 0x3F] : '=');
        output.push_back(i + 2 < data.size() ? table[value & 0x3F] : '=');
    }

    return output;
}

namespace detail
{

inline int Base64Value(char input)
{
    if (input >= 'A' && input <= 'Z')
        return input - 'A';
    if (input >= 'a' && input <= 'z')
        return input - 'a' + 26;
    if (input >= '0' && input <= '9')
        return input - '0' + 52;
    if (input == '+')
        return 62;
    if (input == '/')
        return 63;
    return -1;
}

} // namespace detail

inline std::optional<std::string> DecodeBase64(std::string_view encoded)
{
    if (encoded.size() % 4 != 0)
    {
        return std::nullopt;
    }

    std::string output;
    output.reserve((encoded.size() / 4) * 3);

    for (size_t i = 0; i < encoded.size(); i += 4)
    {
        const bool pad2 = encoded[i + 2] == '=';
        const bool pad3 = encoded[i + 3] == '=';
        if ((encoded[i] == '=') || (encoded[i + 1] == '=') || (pad2 && !pad3) ||
            ((pad2 || pad3) && i + 4 != encoded.size()))
        {
            return std::nullopt;
        }

        const int value0 = detail::Base64Value(encoded[i]);
        const int value1 = detail::Base64Value(encoded[i + 1]);
        const int value2 = pad2 ? 0 : detail::Base64Value(encoded[i + 2]);
        const int value3 = pad3 ? 0 : detail::Base64Value(encoded[i + 3]);
        if (value0 < 0 || value1 < 0 || value2 < 0 || value3 < 0)
        {
            return std::nullopt;
        }

        const uint32_t value = (static_cast<uint32_t>(value0) << 18) | (static_cast<uint32_t>(value1) << 12) |
                               (static_cast<uint32_t>(value2) << 6) | static_cast<uint32_t>(value3);
        output.push_back(static_cast<char>((value >> 16) & 0xFF));
        if (!pad2)
        {
            output.push_back(static_cast<char>((value >> 8) & 0xFF));
        }
        if (!pad3)
        {
            output.push_back(static_cast<char>(value & 0xFF));
        }
    }

    return output;
}

// ============================================================================
// String Case
// ============================================================================

inline int toupper(int in)
{
    if (in <= 'z' && in >= 'a')
        return in - ('z' - 'Z');
    return in;
}

inline std::string toupper(std::string_view str)
{
    std::string result;
    result.reserve(str.size());
    std::transform(str.begin(), str.end(), std::back_inserter(result), [](unsigned char c) { return toupper(c); });
    return result;
}

inline std::wstring toupper(std::wstring_view str)
{
    std::wstring result;
    result.reserve(str.size());
    std::transform(str.begin(), str.end(), std::back_inserter(result), [](wchar_t c) { return toupper(c); });
    return result;
}

inline int tolower(int in)
{
    if (in <= 'Z' && in >= 'A')
        return in - ('Z' - 'z');
    return in;
}

inline std::string tolower(std::string_view str)
{
    std::string result;
    result.reserve(str.size());
    std::transform(str.begin(), str.end(), std::back_inserter(result), [](char c) { return tolower(c); });
    return result;
}

inline std::wstring tolower(std::wstring_view str)
{
    std::wstring result;
    result.reserve(str.size());
    std::transform(str.begin(), str.end(), std::back_inserter(result), [](wchar_t c) { return tolower(c); });
    return result;
}

inline std::wstring trim(std::wstring value)
{
    size_t start = 0;
    while (start < value.size() && std::iswspace(value[start]))
    {
        ++start;
    }

    size_t end = value.size();
    while (end > start && std::iswspace(value[end - 1]))
    {
        --end;
    }
    return value.substr(start, end - start);
}

// ============================================================================
// Binary IO
// ============================================================================

/**
 * @brief Recommend to check the s.gcount since eof may occured, or use s.exceptions(std::ios_base::eofbit)
 */
template <typename T>
T read(std::istream& s)
{
    T x{};
    s.read(reinterpret_cast<char*>(&x), sizeof(T));
    return x;
}

template <>
inline std::string read(std::istream& s)
{
    std::string str;
    std::getline(s, str, '\0');
    return str;
}

template <>
inline std::wstring read(std::istream& s)
{
    std::wstring str;
    str.reserve(256);
    for (wchar_t c; (c = read<wchar_t>(s)) != L'\0';)
    {
        str += c;
    }
    return str;
}

inline std::string read(std::istream& s, std::streamsize n)
{
    if (n < 0)
    {
        return {};
    }

    std::string str(static_cast<size_t>(n), '\0');
    s.read(str.data(), n);
    return str;
}

template <typename T>
    requires std::is_trivially_copyable_v<T>
void write(std::ostream& s, const T& value)
{
    s.write(reinterpret_cast<const char*>(&value), sizeof(T));
}

inline void write(std::ostream& s, std::string_view data)
{
    s.write(data.data(), static_cast<std::streamsize>(data.size()));
}

inline bool WriteFileBytes(const std::filesystem::path& path, std::string_view data)
{
    std::ofstream file(path, std::ios::binary);
    if (!file)
    {
        return false;
    }

    write(file, data);
    return file.good();
}

/*
 * ============================================================================
 * Windows Only Utils
 * ============================================================================
 */
#ifdef _WIN32

// ============================================================================
// Windows Diagnostics
// ============================================================================

#define DLOGW(...) ::OutputDebugStringW(std::format(__VA_ARGS__).c_str())

// ============================================================================
// Windows Initialization
// ============================================================================

class ScopedComInitializer
{
    bool initialized_ = false;
    bool shouldUninitialize_ = false;

  public:
    ScopedComInitializer()
    {
        const HRESULT hr = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        initialized_ = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
        shouldUninitialize_ = SUCCEEDED(hr);
    }

    ScopedComInitializer(const ScopedComInitializer&) = delete;
    ScopedComInitializer& operator=(const ScopedComInitializer&) = delete;

    ~ScopedComInitializer()
    {
        if (shouldUninitialize_)
        {
            ::CoUninitialize();
        }
    }

    bool IsInitialized() const noexcept
    {
        return initialized_;
    }
};

namespace detail
{

class GdiplusSession
{
    ULONG_PTR token_ = 0;
    Gdiplus::Status status_ = Gdiplus::GenericError;

  public:
    GdiplusSession()
    {
        Gdiplus::GdiplusStartupInput input;
        status_ = Gdiplus::GdiplusStartup(&token_, &input, nullptr);
    }

    GdiplusSession(const GdiplusSession&) = delete;
    GdiplusSession& operator=(const GdiplusSession&) = delete;

    ~GdiplusSession()
    {
        if (status_ == Gdiplus::Ok)
        {
            Gdiplus::GdiplusShutdown(token_);
        }
    }

    bool IsStarted() const noexcept
    {
        return status_ == Gdiplus::Ok;
    }
};

} // namespace detail

inline bool EnsureGdiplusStarted()
{
    static const detail::GdiplusSession session;
    return session.IsStarted();
}

// ============================================================================
// Windows String Conversion
// ============================================================================

inline std::u16string& to_u16string(std::wstring& s)
{
    return *reinterpret_cast<std::u16string*>(&s);
}

inline const std::u16string& to_u16string(const std::wstring& s)
{
    return *reinterpret_cast<const std::u16string*>(&s);
}

inline std::u16string to_u16string(std::wstring&& s)
{
    return std::move(*reinterpret_cast<std::u16string*>(&s));
}

inline std::wstring& to_wstring(std::u16string& s)
{
    return *reinterpret_cast<std::wstring*>(&s);
}

inline const std::wstring& to_wstring(const std::u16string& s)
{
    return *reinterpret_cast<const std::wstring*>(&s);
}

inline std::wstring to_wstring(std::u16string&& s)
{
    return std::move(*reinterpret_cast<std::wstring*>(&s));
}

inline std::wstring to_wstring(const std::string_view& str)
{
    std::wstring wstrTo;
    if (str.empty())
        return wstrTo;

    if (str.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        return {};
    }

    const int inputSize = static_cast<int>(str.size());
    int size = ::MultiByteToWideChar(CP_UTF8, 0, str.data(), inputSize, NULL, 0);
    if (size <= 0)
    {
        return {};
    }

    wstrTo.resize(size);
    if (::MultiByteToWideChar(CP_UTF8, 0, str.data(), inputSize, wstrTo.data(), size) <= 0)
    {
        return {};
    }
    return wstrTo;
}

inline std::string to_string(const std::wstring_view& wstr)
{
    std::string strTo;
    if (wstr.empty())
        return strTo;

    if (wstr.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        return {};
    }

    const int inputSize = static_cast<int>(wstr.size());
    int size = ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), inputSize, NULL, 0, NULL, NULL);
    if (size <= 0)
    {
        return {};
    }

    strTo.resize(size);
    if (::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), inputSize, strTo.data(), size, NULL, NULL) <= 0)
    {
        return {};
    }
    return strTo;
}

template <typename>
inline constexpr bool dependent_false_v = false;

// ============================================================================
// Windows Handle RAII
// ============================================================================

template <typename HandleType>
auto CloseFunctionForHandle()
{
    if constexpr (std::is_same_v<HandleType, HANDLE>)
    {
        return &::CloseHandle;
    }
    else if constexpr (std::is_same_v<HandleType, HKEY>)
    {
        return &::RegCloseKey;
    }
    else if constexpr (std::is_same_v<HandleType, HBITMAP>)
    {
        return [](HBITMAP bitmap) { return ::DeleteObject(bitmap); };
    }
    else
    {
        static_assert(dependent_false_v<HandleType>,
                      "Unsupported handle type, please add the close function into CloseFunctionForHandle");
    }
}

template <typename HandleType = HANDLE>
struct AutoHandle
{
    HandleType handle = NULL;
    inline static auto close = CloseFunctionForHandle<HandleType>();

    AutoHandle() = default;

    AutoHandle(HandleType h) : handle(h)
    {
    }

    AutoHandle(const AutoHandle&) = delete;
    AutoHandle& operator=(const AutoHandle&) = delete;

    AutoHandle(AutoHandle&& other) noexcept : handle(other.handle)
    {
        other.handle = NULL;
    }

    AutoHandle& operator=(AutoHandle&& other) noexcept
    {
        if (&*this != &other)
        {
            if (handle)
            {
                close(handle);
            }
            handle = other.handle;
            other.handle = NULL;
        }
        return *this;
    }

    ~AutoHandle()
    {
        Close();
    }

    HandleType* operator&()
    {
        return &handle;
    }

    operator HandleType() const
    {
        return handle;
    }

    void Close()
    {
        if (handle)
        {
            close(handle);
            handle = NULL;
        }
    }
};

using RegType =
    std::variant<std::nullptr_t, DWORD, unsigned long long, std::vector<BYTE>, std::vector<std::wstring>, std::wstring>;

// ============================================================================
// Windows Registry
// ============================================================================

namespace detail
{

inline RegType GetRegValue(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, DWORD dwFlags,
                           DWORD dwType, DWORD cbData)
{
    RegType var;
    LPBYTE data = NULL;
    switch (dwType)
    {
    case REG_DWORD:
        var.emplace<DWORD>(0);
        data = reinterpret_cast<LPBYTE>(&std::get<DWORD>(var));
        break;

    case REG_QWORD:
        var.emplace<unsigned long long>(0);
        data = reinterpret_cast<LPBYTE>(&std::get<unsigned long long>(var));
        break;

    case REG_BINARY:
        var.emplace<std::vector<BYTE>>(cbData);
        data = reinterpret_cast<LPBYTE>(std::get<std::vector<BYTE>>(var).data());
        break;

    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        var.emplace<std::wstring>(cbData / sizeof(WCHAR) - 1, '\0');
        data = reinterpret_cast<LPBYTE>(std::get<std::wstring>(var).data());
        break;

    default:
        return var;
    }

    LSTATUS result = ::RegGetValueW(hKey, subKey.c_str(), valueName.c_str(), dwFlags, &dwType, data, &cbData);

    if (result != ERROR_SUCCESS)
    {
        var.emplace<std::nullptr_t>(nullptr);
    }
    else if (dwType == REG_SZ)
    {
        std::wstring& str = std::get<std::wstring>(var);
        str.resize((cbData / sizeof(WCHAR)) - 1);
    }
    else if (dwType == REG_EXPAND_SZ)
    {
        std::wstring& str = std::get<std::wstring>(var);
        str.resize((cbData / sizeof(WCHAR)) - 1);
        std::wstring expandedStr;
        DWORD expandedSize = ::ExpandEnvironmentStringsW(str.c_str(), NULL, 0);
        if (expandedSize > 0)
        {
            expandedStr.resize(expandedSize - 1);
            ::ExpandEnvironmentStringsW(str.c_str(), expandedStr.data(), expandedSize);
            var.emplace<std::wstring>(std::move(expandedStr));
        }
    }
    else if (dwType == REG_MULTI_SZ)
    {
        std::wstring& multiSz = std::get<std::wstring>(var);
        std::vector<std::wstring> multi;
        for (auto word : std::views::split(multiSz, std::wstring(1, L'\0')))
        {
            multi.emplace_back(std::wstring(word.begin(), word.end()));
        }
        multi.erase(--multi.end());
        var.emplace<std::vector<std::wstring>>(std::move(multi));
    }

    return var;
}

} // namespace detail

/**
 * @brief Get the value data in registry
 * @param hKey root key
 * @param subKey sub key
 * @param valueName value name
 * @param wow64 0 means no addition flag, 64 means KEY_WOW64_64KEY, 32 means KEY_WOW64_32KEY
 * @return
 */
inline RegType GetRegValue(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, int wow64 = 0)
{
    DWORD dwType = 0;
    DWORD cbData = 0;
    DWORD dwFlags = RRF_RT_ANY | (wow64 == 0 ? 0 : wow64 == 64 ? RRF_SUBKEY_WOW6464KEY : RRF_SUBKEY_WOW6432KEY);
    LSTATUS result = ::RegGetValueW(hKey, subKey.c_str(), valueName.c_str(), dwFlags, &dwType, NULL, &cbData);
    if (result != ERROR_SUCCESS)
    {
        return {};
    }
    return detail::GetRegValue(hKey, subKey, valueName, dwFlags, dwType, cbData);
}

/**
 * @brief Get all values of the key in registry
 * @param hKey root key
 * @param subKey sub key
 * @param wow64 0 means no addition flag, 64 means KEY_WOW64_64KEY, 32 means KEY_WOW64_32KEY
 * @return
 */
inline std::vector<std::pair<std::wstring, RegType>> ListRegValues(HKEY hKey, const std::wstring& subKey, int wow64 = 0)
{
    std::vector<std::pair<std::wstring, RegType>> values;

    AutoHandle<HKEY> hEnumKey;
    DWORD dwFlags = wow64 == 0 ? 0 : wow64 == 64 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
    LSTATUS result = ::RegOpenKeyExW(hKey, subKey.c_str(), 0, KEY_QUERY_VALUE | dwFlags, &hEnumKey);
    if (result != ERROR_SUCCESS)
    {
        return values;
    }

    DWORD maxValueNameLen;
    result = ::RegQueryInfoKeyW(hEnumKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &maxValueNameLen, NULL, NULL, NULL);
    if (result != ERROR_SUCCESS)
    {
        return values;
    }

    DWORD index = 0;
    DWORD dwType;

    while (true)
    {
        std::wstring name;
        DWORD nameSize = maxValueNameLen + 1;
        name.resize(maxValueNameLen);
        DWORD dataSize = 0;
        result = ::RegEnumValueW(hEnumKey, index, name.data(), &nameSize, NULL, &dwType, NULL, &dataSize);
        if (result != ERROR_SUCCESS)
        {
            break;
        }
        name.resize(nameSize);

        RegType value = detail::GetRegValue(hEnumKey, L"", name.c_str(), RRF_RT_ANY, dwType, dataSize);
        values.emplace_back(std::move(name), std::move(value));

        index++;
    }

    return values;
}

/**
 * @brief Get all subkey names of the key in registry
 * @param hKey root key
 * @param subKey sub key
 * @param wow64 0 means no addition flag, 64 means KEY_WOW64_64KEY, 32 means KEY_WOW64_32KEY
 * @return
 */
inline std::vector<std::wstring> ListRegKeys(HKEY hKey, const std::wstring& subKey, int wow64 = 0)
{
    std::vector<std::wstring> keys;

    AutoHandle<HKEY> hEnumKey;
    DWORD dwFlags = wow64 == 0 ? 0 : wow64 == 64 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
    LSTATUS result =
        ::RegOpenKeyExW(hKey, subKey.c_str(), 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | dwFlags, &hEnumKey);
    if (result != ERROR_SUCCESS)
    {
        return keys;
    }

    DWORD maxSubKeyLen;
    result = ::RegQueryInfoKeyW(hEnumKey, NULL, NULL, NULL, NULL, &maxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL);
    if (result != ERROR_SUCCESS)
    {
        return keys;
    }

    DWORD index = 0;

    while (true)
    {
        std::wstring name;
        DWORD nameSize = maxSubKeyLen + 1;
        name.resize(maxSubKeyLen);
        DWORD dataSize = 0;
        result = ::RegEnumKeyExW(hEnumKey, index, name.data(), &nameSize, NULL, NULL, NULL, NULL);
        if (result != ERROR_SUCCESS)
        {
            break;
        }
        name.resize(nameSize);

        keys.emplace_back(std::move(name));

        index++;
    }

    return keys;
}

/**
 * @brief Set the value data in registry
 * @param rootKey root key
 * @param subKey sub key
 * @param valueName value name
 * @param var value data
 * @param wow64 0 means no addition flag, 64 means KEY_WOW64_64KEY, 32 means KEY_WOW64_32KEY
 * @param expandSz is REG_EXPAND_SZ or REG_SZ if var is wstring
 * @return
 */
inline bool SetRegValue(HKEY rootKey, const std::wstring& subKey, const std::wstring& valueName, const RegType& var,
                        int wow64 = 0, bool expandSz = false)
{
    AutoHandle<HKEY> hKey = NULL;
    DWORD dwDisposition = 0;
    DWORD dwFlags = wow64 == 0 ? 0 : wow64 == 64 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
    LSTATUS result = ::RegCreateKeyExW(rootKey, subKey.c_str(), NULL, NULL, NULL, KEY_SET_VALUE | dwFlags, NULL, &hKey,
                                       &dwDisposition);
    if (result != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD type = 0;
    const BYTE* data = NULL;
    size_t cbData = 0;
    std::wstring multiSz;
    std::visit(
        [&](auto& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, std::nullptr_t>)
            {
                type = REG_NONE;
                data = nullptr;
                cbData = 0;
            }
            else if constexpr (std::is_same_v<T, DWORD>)
            {
                type = REG_DWORD;
                data = reinterpret_cast<const BYTE*>(&arg);
                cbData = sizeof(T);
            }
            else if constexpr (std::is_same_v<T, unsigned long long>)
            {
                type = REG_QWORD;
                data = reinterpret_cast<const BYTE*>(&arg);
                cbData = sizeof(T);
            }
            else if constexpr (std::is_same_v<T, std::vector<BYTE>>)
            {
                type = REG_BINARY;
                data = reinterpret_cast<const BYTE*>(arg.data());
                cbData = arg.size();
            }
            else if constexpr (std::is_same_v<T, std::vector<std::wstring>>)
            {
                for (auto& s : arg)
                {
                    multiSz += s + L'\0';
                }
                type = REG_MULTI_SZ;
                data = reinterpret_cast<const BYTE*>(multiSz.c_str());
                cbData = (multiSz.size() + 1) * sizeof(wchar_t);
            }
            else if constexpr (std::is_same_v<T, std::wstring>)
            {
                type = expandSz ? REG_EXPAND_SZ : REG_SZ;
                data = reinterpret_cast<const BYTE*>(arg.c_str());
                cbData = (arg.size() + 1) * sizeof(wchar_t);
            }
        },
        var);

    result = ::RegSetValueExW(hKey, valueName.c_str(), 0, type, data, cbData);

    return result == ERROR_SUCCESS;
}

inline bool SetRegValue(HKEY rootKey, const std::wstring& subKey, const std::wstring& valueName,
                        const std::initializer_list<BYTE>& var, int wow64 = 0)
{
    return SetRegValue(rootKey, subKey, valueName, std::vector<BYTE>{var}, wow64);
}

inline bool SetRegValue(HKEY rootKey, const std::wstring& subKey, const std::wstring& valueName,
                        const std::initializer_list<std::wstring>& var, int wow64 = 0)
{
    return SetRegValue(rootKey, subKey, valueName, std::vector<std::wstring>{var}, wow64);
}

// ============================================================================
// Windows Enumeration
// ============================================================================

inline void EnumToplevelWindows(const std::function<bool(HWND)>& callback)
{
    // non-capturing lambda can convert to function pointer required by EnumWindows
    auto enumProc = [](HWND hwnd, LPARAM lParam) -> BOOL {
        auto cb = reinterpret_cast<std::function<bool(HWND)>*>(lParam);
        return (*cb)(hwnd);
    };

    ::EnumWindows(static_cast<WNDENUMPROC>(enumProc), reinterpret_cast<LPARAM>(&callback));
}

// ============================================================================
// Windows Process
// ============================================================================

inline std::wstring GetProcessImagePath(DWORD pid)
{
    using NtQueryInformationProcess_t = decltype(&::NtQueryInformationProcess);
    const PROCESSINFOCLASS ProcessImageFileNameWin32 = static_cast<PROCESSINFOCLASS>(43);

    AutoHandle hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
        return L"";

    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        return L"";
    }

    auto NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess)
    {
        return L"";
    }

    ULONG size = 16 + MAX_PATH;
    std::vector<BYTE> buffer(size);
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, buffer.data(), size, &size);
    if (status == 0xC0000004) // STATUS_INFO_LENGTH_MISMATCH
    {
        buffer.resize(size);
        status = NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, buffer.data(), size, &size);
        if (status < 0)
            return L"";
    }
    else if (status < 0)
    {
        return L"";
    }

    auto us = (PUNICODE_STRING)buffer.data();

    return std::wstring(us->Buffer, us->Length / sizeof(wchar_t));
}

inline uint64_t FileTimeToUint64(const FILETIME& fileTime)
{
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart;
}

inline std::optional<uint64_t> GetProcessCreationTime(DWORD pid)
{
    AutoHandle hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        return std::nullopt;
    }

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (!::GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime))
    {
        return std::nullopt;
    }

    return FileTimeToUint64(creationTime);
}

template <typename Callback>
inline void EnumAllProcesses(Callback&& callback)
{
    AutoHandle snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return;
    }
    PROCESSENTRY32W entry{sizeof(PROCESSENTRY32W)};
    if (::Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (!callback(entry))
            {
                break;
            }
        } while (::Process32NextW(snapshot, &entry));
    }
}

inline DWORD GetDesktopProcessId()
{
    // "Shell_TrayWnd" is the class name for the taskbar window, owned by explorer.exe
    HWND hwnd = ::FindWindowW(L"Shell_TrayWnd", NULL);
    if (!hwnd)
    {
        // Fallback: try desktop window (class "Progman")
        hwnd = ::FindWindowW(L"Progman", NULL);
    }
    DWORD pid = 0;
    if (hwnd)
    {
        ::GetWindowThreadProcessId(hwnd, &pid);
    }
    return pid;
}

inline bool IsProcessElevated(DWORD processId)
{
    bool isElevated = false;

    AutoHandle hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess)
    {
        AutoHandle hToken;
        if (::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            TOKEN_ELEVATION elevation;
            DWORD dwSize;
            if (::GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
            {
                isElevated = elevation.TokenIsElevated != 0;
            }
        }
    }

    return isElevated;
}

inline AutoHandle<> CreateProcessAsDesktopUser(const std::wstring& path, const std::wstring& argument,
                                               const std::wstring& cwd = L"")
{
    AutoHandle hChild;

    DWORD pid = GetDesktopProcessId();
    if (pid == 0)
    {
        return hChild;
    }

    AutoHandle hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess)
    {
        AutoHandle hToken;
        if (::OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken))
        {
            AutoHandle hNewToken;
            if (::DuplicateTokenEx(hToken,
                                   TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT |
                                       TOKEN_ADJUST_SESSIONID,
                                   NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
            {
                std::wstring cmdline = L"\"" + path + L"\" " + argument;
                std::wstring dir = cwd.empty() ? std::filesystem::path(path).parent_path().wstring() : cwd;
                PROCESS_INFORMATION pi{};
                STARTUPINFOW si{sizeof(si)};
                if (::CreateProcessAsUserW(hNewToken, NULL, cmdline.data(), NULL, NULL, FALSE, NULL, NULL, dir.c_str(),
                                           &si, &pi))
                {
                    hChild = pi.hProcess;
                    ::CloseHandle(pi.hThread);
                }
            }
        }
    }

    return hChild;
}

inline AutoHandle<> CreateProcessAsAdmin(const std::wstring& path, const std::wstring& argument,
                                         const std::wstring& cwd = L"")
{
    AutoHandle hProcess;
    std::wstring dir = cwd.empty() ? std::filesystem::path(path).parent_path().wstring() : cwd;
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = path.c_str();
    sei.lpParameters = argument.c_str();
    sei.lpDirectory = dir.c_str();
    sei.nShow = SW_NORMAL;

    if (::ShellExecuteExW(&sei))
    {
        hProcess = sei.hProcess;
    }
    return hProcess;
}

inline bool KillProcessByNames(const std::vector<std::wstring>& names, bool wait = true)
{
    std::vector<AutoHandle<>> hProcesses;
    bool failed = false;

    EnumAllProcesses([&](const PROCESSENTRY32W& entry) {
        if (entry.th32ProcessID != 0 &&
            std::any_of(names.begin(), names.end(), [exe = entry.szExeFile](const std::wstring& name) {
                return ::_wcsicmp(exe, name.c_str()) == 0;
            }))
        {
            HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, entry.th32ProcessID);
            if (hProcess && ::TerminateProcess(hProcess, 0))
            {
                hProcesses.emplace_back(hProcess);
            }
            else
            {
                failed = true;
            }
        }
        return true;
    });

    if (wait && !hProcesses.empty())
    {
        DWORD res = ::WaitForMultipleObjects(hProcesses.size(), reinterpret_cast<const HANDLE*>(hProcesses.data()),
                                             TRUE, INFINITE);

        if (res < WAIT_OBJECT_0 || res >= WAIT_OBJECT_0 + hProcesses.size())
        {
            return false;
        }
    }

    return !failed;
}

inline bool KillProcessByProcessIds(const std::vector<DWORD>& processIds, bool wait = true)
{
    std::vector<AutoHandle<>> hProcesses;
    bool failed = false;

    for (DWORD pid : processIds)
    {
        HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
        if (hProcess && ::TerminateProcess(hProcess, 0))
        {
            hProcesses.emplace_back(hProcess);
        }
        else
        {
            failed = true;
        }
    }

    if (wait && !hProcesses.empty())
    {
        DWORD res = ::WaitForMultipleObjects(hProcesses.size(), &hProcesses[0], TRUE, INFINITE);

        if (res == WAIT_FAILED)
        {
            failed = true;
        }
    }

    return !failed;
}

// ============================================================================
// Windows User Account
// ============================================================================

struct UserAccount
{
    std::vector<BYTE> tokenData;

    const TOKEN_USER* TokenUser() const
    {
        return reinterpret_cast<const TOKEN_USER*>(tokenData.data());
    }

    std::wstring GetAccountUserName() const
    {
        std::wstring userName;

        DWORD userSize = 0;
        DWORD domainSize = 0;
        SID_NAME_USE sidName;
        ::LookupAccountSidW(NULL, TokenUser()->User.Sid, NULL, &userSize, NULL, &domainSize, &sidName);
        std::wstring user(userSize - 1, L'\0');
        std::wstring domain(domainSize - 1, L'\0');
        ::LookupAccountSidW(NULL, TokenUser()->User.Sid, user.data(), &userSize, domain.data(), &domainSize, &sidName);
        if (user != L"")
        {
            userName = domain + L"\\" + user;
        }
        return userName;
    }

    std::wstring GetAccountSid() const
    {
        std::wstring sid;
        LPWSTR sidString = nullptr;
        if (::ConvertSidToStringSidW(TokenUser()->User.Sid, &sidString))
        {
            sid = sidString;
            ::LocalFree(sidString);
        }
        return sid;
    }
};

inline UserAccount GetProcessUserAccount(DWORD processId)
{
    UserAccount user{};
    AutoHandle hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);

    if (hProcess)
    {
        AutoHandle hToken;

        if (::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            DWORD tokenSize = 0;
            ::GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenSize);

            if (tokenSize > 0)
            {
                user.tokenData.resize(tokenSize);
                ::GetTokenInformation(hToken, TokenUser, user.tokenData.data(), tokenSize, &tokenSize);
            }
        }
    }
    return user;
}

// ============================================================================
// Windows Shell
// ============================================================================

inline std::wstring GetKnownFolderPath(REFKNOWNFOLDERID rfid)
{
    PWSTR path;
    std::wstring result;
    if (SUCCEEDED(::SHGetKnownFolderPath(rfid, 0, NULL, &path)))
    {
        result = path;
        ::CoTaskMemFree(path);
    }
    return result;
}

inline std::wstring ResolveLnkExecutable(const std::filesystem::path& shortcutPath)
{
    ScopedComInitializer com;
    if (!com.IsInitialized())
    {
        return {};
    }

    IShellLinkW* shellLink = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                    reinterpret_cast<void**>(&shellLink));
    if (FAILED(hr))
    {
        return {};
    }
    defer
    {
        shellLink->Release();
    };

    IPersistFile* persistFile = nullptr;
    hr = shellLink->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&persistFile));
    if (FAILED(hr))
    {
        return {};
    }
    defer
    {
        persistFile->Release();
    };

    hr = persistFile->Load(shortcutPath.c_str(), STGM_READ);
    if (FAILED(hr))
    {
        return {};
    }

    std::wstring target(32768, L'\0');
    WIN32_FIND_DATAW findData{};
    hr = shellLink->GetPath(target.data(), static_cast<int>(target.size()), &findData, SLGP_UNCPRIORITY);
    if (FAILED(hr))
    {
        return {};
    }
    target.resize(wcsnlen_s(target.c_str(), target.size()));
    return target;
}

// ============================================================================
// Windows Imaging
// ============================================================================

inline std::optional<CLSID> GetImageEncoderClsid(const wchar_t* mimeType)
{
    UINT count = 0;
    UINT size = 0;
    if (!mimeType || Gdiplus::GetImageEncodersSize(&count, &size) != Gdiplus::Ok || count == 0 || size == 0)
    {
        return std::nullopt;
    }

    std::vector<BYTE> buffer(size);
    auto* encoders = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buffer.data());
    if (Gdiplus::GetImageEncoders(count, size, encoders) != Gdiplus::Ok)
    {
        return std::nullopt;
    }

    for (UINT i = 0; i < count; ++i)
    {
        if (encoders[i].MimeType && std::wcscmp(encoders[i].MimeType, mimeType) == 0)
        {
            return encoders[i].Clsid;
        }
    }

    return std::nullopt;
}

namespace detail
{

struct PngBitmapData
{
    std::string bytes;
    int width = 0;
    int height = 0;
};

#pragma pack(push, 1)

struct IcoHeader
{
    uint16_t reserved = 0;
    uint16_t type = 1;
    uint16_t count = 1;
};

struct IcoEntry
{
    uint8_t width = 0;
    uint8_t height = 0;
    uint8_t colorCount = 0;
    uint8_t reserved = 0;
    uint16_t planes = 1;
    uint16_t bitCount = 32;
    uint32_t bytesInRes = 0;
    uint32_t imageOffset = sizeof(IcoHeader) + sizeof(IcoEntry);
};

#pragma pack(pop)

static_assert(sizeof(IcoHeader) == 6);
static_assert(sizeof(IcoEntry) == 16);

inline std::optional<PngBitmapData> BitmapToPngData(HBITMAP bitmap)
{
    if (!bitmap)
    {
        return std::nullopt;
    }

    if (!EnsureGdiplusStarted())
    {
        return std::nullopt;
    }

    static const auto pngEncoderClsid = GetImageEncoderClsid(L"image/png");
    if (!pngEncoderClsid)
    {
        return std::nullopt;
    }

    IStream* stream = nullptr;
    if (FAILED(::CreateStreamOnHGlobal(nullptr, TRUE, &stream)))
    {
        return std::nullopt;
    }
    defer
    {
        stream->Release();
    };

    BITMAP bitmapInfo{};
    if (::GetObjectW(bitmap, sizeof(bitmapInfo), &bitmapInfo) == 0 || bitmapInfo.bmWidth <= 0 ||
        bitmapInfo.bmHeight == 0)
    {
        return std::nullopt;
    }

    const int width = bitmapInfo.bmWidth;
    const int height = std::abs(bitmapInfo.bmHeight);
    const int stride = width * 4;
    std::vector<BYTE> pixels(static_cast<size_t>(stride) * height);

    if (bitmapInfo.bmBits && bitmapInfo.bmBitsPixel == 32)
    {
        const auto* source = static_cast<const BYTE*>(bitmapInfo.bmBits);
        const int sourceStride = std::abs(bitmapInfo.bmWidthBytes);
        const bool topDown = bitmapInfo.bmHeight < 0;

        for (int y = 0; y < height; ++y)
        {
            const int sourceY = topDown ? y : height - 1 - y;
            std::memcpy(pixels.data() + static_cast<size_t>(y) * stride,
                        source + static_cast<size_t>(sourceY) * sourceStride, stride);
        }
    }
    else
    {
        BITMAPINFO dibInfo{};
        dibInfo.bmiHeader.biSize = sizeof(dibInfo.bmiHeader);
        dibInfo.bmiHeader.biWidth = width;
        dibInfo.bmiHeader.biHeight = -height;
        dibInfo.bmiHeader.biPlanes = 1;
        dibInfo.bmiHeader.biBitCount = 32;
        dibInfo.bmiHeader.biCompression = BI_RGB;

        HDC dc = ::GetDC(nullptr);
        if (!dc)
        {
            return std::nullopt;
        }
        defer
        {
            ::ReleaseDC(nullptr, dc);
        };

        if (::GetDIBits(dc, bitmap, 0, height, pixels.data(), &dibInfo, DIB_RGB_COLORS) == 0)
        {
            return std::nullopt;
        }
    }

    Gdiplus::Bitmap image(width, height, stride, PixelFormat32bppPARGB, pixels.data());
    if (image.GetLastStatus() != Gdiplus::Ok || image.Save(stream, &*pngEncoderClsid, nullptr) != Gdiplus::Ok)
    {
        return std::nullopt;
    }

    HGLOBAL global = nullptr;
    if (FAILED(::GetHGlobalFromStream(stream, &global)))
    {
        return std::nullopt;
    }

    SIZE_T byteCount = ::GlobalSize(global);
    if (byteCount == 0)
    {
        return std::nullopt;
    }

    auto* bytes = static_cast<const BYTE*>(::GlobalLock(global));
    if (!bytes)
    {
        return std::nullopt;
    }
    defer
    {
        ::GlobalUnlock(global);
    };

    PngBitmapData result;
    result.bytes.assign(reinterpret_cast<const char*>(bytes), byteCount);
    result.width = width;
    result.height = height;
    return result;
}

inline std::optional<std::string> BuildIcoFromPng(const PngBitmapData& png)
{
    if (png.bytes.empty() || png.width <= 0 || png.height <= 0 || png.width > 256 || png.height > 256 ||
        png.bytes.size() > std::numeric_limits<uint32_t>::max())
    {
        return std::nullopt;
    }

    IcoEntry entry;
    entry.width = static_cast<uint8_t>(png.width == 256 ? 0 : png.width);
    entry.height = static_cast<uint8_t>(png.height == 256 ? 0 : png.height);
    entry.bytesInRes = static_cast<uint32_t>(png.bytes.size());

    std::ostringstream ico(std::ios::binary);
    write(ico, IcoHeader{});
    write(ico, entry);
    write(ico, png.bytes);

    return std::move(ico).str();
}

} // namespace detail

inline AutoHandle<HBITMAP> GetShellItemIconBitmap(const std::filesystem::path& path, SIZE size = {64, 64})
{
    ScopedComInitializer com;
    if (!com.IsInitialized())
    {
        return {};
    }

    IShellItemImageFactory* factory = nullptr;
    HRESULT hr = ::SHCreateItemFromParsingName(path.c_str(), nullptr, IID_PPV_ARGS(&factory));
    if (FAILED(hr))
    {
        return {};
    }
    defer
    {
        factory->Release();
    };

    HBITMAP bitmap = nullptr;
    hr = factory->GetImage(size, static_cast<SIIGBF>(SIIGBF_ICONONLY | SIIGBF_BIGGERSIZEOK), &bitmap);
    if (FAILED(hr) || !bitmap)
    {
        return {};
    }

    return AutoHandle<HBITMAP>{bitmap};
}

inline bool BitmapToPngFile(HBITMAP bitmap, const std::filesystem::path& path)
{
    const auto png = detail::BitmapToPngData(bitmap);
    return png && WriteFileBytes(path, png->bytes);
}

inline bool BitmapToIcoFile(HBITMAP bitmap, const std::filesystem::path& path)
{
    const auto png = detail::BitmapToPngData(bitmap);
    if (!png)
    {
        return false;
    }

    const auto ico = detail::BuildIcoFromPng(*png);
    return ico && WriteFileBytes(path, *ico);
}

inline std::string BitmapToPngDataUrl(HBITMAP bitmap)
{
    const auto png = detail::BitmapToPngData(bitmap);
    if (!png)
    {
        return {};
    }

    return "data:image/png;base64," + EncodeBase64(png->bytes);
}

inline std::string GetShellItemIconDataUrl(const std::filesystem::path& path, SIZE size = {64, 64})
{
    AutoHandle<HBITMAP> bitmap = GetShellItemIconBitmap(path, size);
    return BitmapToPngDataUrl(bitmap);
}

#endif // _WIN32

} // namespace util

#endif // MRBEARDAD_UTILS_H
