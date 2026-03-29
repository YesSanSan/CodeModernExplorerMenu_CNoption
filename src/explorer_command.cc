// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include <fmt/core.h>
#include <iostream>
#include <fstream>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <filesystem>
#include <string>
#include <utility>
#include <shlwapi.h>
#include <shobjidl_core.h>
#include <userenv.h>
#include <wrl/module.h>
#include <wrl/implements.h>
#include <wrl/client.h>
#include "wil/stl.h"
#include "wil/filesystem.h"
#include "wil/win32_helpers.h"
#include <wil/cppwinrt.h>
#include <wil/resource.h>
#include <wil/com.h>

using Microsoft::WRL::ClassicCom;
using Microsoft::WRL::ComPtr;
using Microsoft::WRL::InhibitRoOriginateError;
using Microsoft::WRL::Module;
using Microsoft::WRL::ModuleType;
using Microsoft::WRL::RuntimeClass;
using Microsoft::WRL::RuntimeClassFlags;

extern "C" BOOL WINAPI DllMain(HINSTANCE instance,
                               DWORD reason,
                               LPVOID reserved) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
      break;
  }

  return true;
}

namespace {

    std::filesystem::path GetVSCodeExecutablePath() {
        // 1. 尝试在 PATH 环境变量中搜索 (适合 Scoop, PATH 注册版)
        wchar_t pathBuffer[MAX_PATH];
        // 将 EXE_NAME 转换为 path，然后调用 c_str() 获取符合 SearchPathW 要求的宽字符指针
        DWORD result = SearchPathW(NULL, std::filesystem::path(EXE_NAME).c_str(), NULL, MAX_PATH, pathBuffer, NULL);
        
        if (result > 0 && result < MAX_PATH) {
            return std::filesystem::path(pathBuffer);
        }

        // 2. 如果 PATH 没找到，尝试原有的“相对于 DLL”的逻辑
        try {
            std::filesystem::path module_path{ wil::GetModuleFileNameW<std::wstring>(wil::GetModuleInstanceHandle()) };
            // 向上退两级查找 (假设 DLL 在 bin 或某个子目录下)
            auto probe_path = module_path.parent_path().parent_path() / DIR_NAME / EXE_NAME;
            if (std::filesystem::exists(probe_path)) {
                return probe_path;
            }
        } catch (...) {}

        // 3. 最后保底：硬编码路径 (官方安装版默认位置)
        std::filesystem::path fallback_path = std::filesystem::path(L"C:\\Program Files") / DIR_NAME / EXE_NAME;
        return fallback_path;
    }

  // Extracted from
  // https://source.chromium.org/chromium/chromium/src/+/main:base/command_line.cc;l=109-159

  std::wstring QuoteForCommandLineArg(const std::wstring& arg) {
  // We follow the quoting rules of CommandLineToArgvW.
  // http://msdn.microsoft.com/en-us/library/17w5ykft.aspx
  std::wstring quotable_chars(L" \\\"");
  if (arg.find_first_of(quotable_chars) == std::wstring::npos) {
    // No quoting necessary.
    return arg;
  }

  std::wstring out;
  out.push_back('"');
  for (size_t i = 0; i < arg.size(); ++i) {
    if (arg[i] == '\\') {
      // Find the extent of this run of backslashes.
      size_t start = i, end = start + 1;
      for (; end < arg.size() && arg[end] == '\\'; ++end) {}
      size_t backslash_count = end - start;

      // Backslashes are escapes only if the run is followed by a double quote.
      // Since we also will end the string with a double quote, we escape for
      // either a double quote or the end of the string.
      if (end == arg.size() || arg[end] == '"') {
        // To quote, we need to output 2x as many backslashes.
        backslash_count *= 2;
      }
      for (size_t j = 0; j < backslash_count; ++j)
        out.push_back('\\');

      // Advance i to one before the end to balance i++ in loop.
      i = end - 1;
    } else if (arg[i] == '"') {
      out.push_back('\\');
      out.push_back('"');
    } else {
      out.push_back(arg[i]);
    }
  }
  out.push_back('"');

  return out;
}

}

class __declspec(uuid(DLL_UUID)) ExplorerCommandHandler final : public RuntimeClass<RuntimeClassFlags<ClassicCom | InhibitRoOriginateError>, IExplorerCommand> {
 public:
  // IExplorerCommand implementation:
  IFACEMETHODIMP GetTitle(IShellItemArray* items, PWSTR* name) {
    const size_t kMaxStringLength = 1024;
    wchar_t value_w[kMaxStringLength];
    wchar_t expanded_value_w[kMaxStringLength];
    DWORD value_size_w = sizeof(value_w);
    #if defined(INSIDER)
        const wchar_t kTitleRegkey[] = L"Software\\Classes\\CodeInsidersModernExplorerMenu";
    #else
        const wchar_t kTitleRegkey[] = L"Software\\Classes\\CodeModernExplorerMenu";
    #endif
    HKEY subhkey = nullptr;
    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, kTitleRegkey, 0, KEY_READ, &subhkey);
    if (result != ERROR_SUCCESS) {
      result = RegOpenKeyEx(HKEY_CURRENT_USER, kTitleRegkey, 0, KEY_READ, &subhkey);
    }

    DWORD type = REG_EXPAND_SZ;
    RegQueryValueEx(subhkey, L"Title", nullptr, &type,
                    reinterpret_cast<LPBYTE>(&value_w), &value_size_w);
    RegCloseKey(subhkey);
    value_size_w = ExpandEnvironmentStrings(value_w, expanded_value_w, kMaxStringLength);
    return (value_size_w && value_size_w < kMaxStringLength)
        ? SHStrDup(expanded_value_w, name)
        : SHStrDup(L"UnExpected Title", name);
  }

    IFACEMETHODIMP GetIcon(IShellItemArray* items, PWSTR* icon) {
        std::filesystem::path module_path = GetVSCodeExecutablePath();

        if (!std::filesystem::exists(module_path)) {
            return E_FAIL;
        }

        return SHStrDupW(module_path.c_str(), icon);
    }

  IFACEMETHODIMP GetToolTip(IShellItemArray* items, PWSTR* infoTip) {
    *infoTip = nullptr;
    return E_NOTIMPL;
  }

  IFACEMETHODIMP GetCanonicalName(GUID* guidCommandName) {
    *guidCommandName = GUID_NULL;
    return S_OK;
  }

  IFACEMETHODIMP GetState(IShellItemArray* items, BOOL okToBeSlow, EXPCMDSTATE* cmdState) {
    *cmdState = ECS_ENABLED;
    return S_OK;
  }

  IFACEMETHODIMP GetFlags(EXPCMDFLAGS* flags) {
    *flags = ECF_DEFAULT;
    return S_OK;
  }

  IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand** enumCommands) {
    *enumCommands = nullptr;
    return E_NOTIMPL;
  }

    IFACEMETHODIMP Invoke(IShellItemArray* items, IBindCtx* bindCtx) {
        if (items) {
            std::filesystem::path module_path = GetVSCodeExecutablePath();

            if (!std::filesystem::exists(module_path)) {
                return E_FAIL;
            }

            DWORD count;
            RETURN_IF_FAILED(items->GetCount(&count));
            for (DWORD i = 0; i < count; ++i) {
                ComPtr<IShellItem> item;
                auto result = items->GetItemAt(i, &item);
                if (SUCCEEDED(result)) {
                    wil::unique_cotaskmem_string path;
                    result = item->GetDisplayName(SIGDN_FILESYSPATH, &path);
                    if (SUCCEEDED(result)) {
                        // 使用寻找到的 module_path 启动程序
                        HINSTANCE ret = ShellExecuteW(nullptr, L"open", module_path.c_str(), 
                                                    QuoteForCommandLineArg(path.get()).c_str(), 
                                                    nullptr, SW_SHOW);
                        if ((INT_PTR)ret <= HINSTANCE_ERROR) {
                            RETURN_LAST_ERROR();
                        }
                    }
                }
            }
        }
        return S_OK;
    }
};

CoCreatableClass(ExplorerCommandHandler)
CoCreatableClassWrlCreatorMapInclude(ExplorerCommandHandler)

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
  if (ppv == nullptr)
    return E_POINTER;
  *ppv = nullptr;
  return Module<ModuleType::InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}

STDAPI DllCanUnloadNow(void) {
  return Module<ModuleType::InProc>::GetModule().GetObjectCount() == 0 ? S_OK : S_FALSE;
}

STDAPI DllGetActivationFactory(HSTRING activatableClassId,
                               IActivationFactory** factory) {
  return Module<ModuleType::InProc>::GetModule().GetActivationFactory(activatableClassId, factory);
}
