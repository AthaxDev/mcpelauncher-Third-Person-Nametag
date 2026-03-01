#ifdef _WIN32
#include <Windows.h>
#include <cstdint>
#include <thread>

static constexpr size_t INSTRUCTION_SIZE = 6;
static uint8_t  g_originalBytes[INSTRUCTION_SIZE] = {};
static void*    g_instructionPointer = nullptr;
static bool     g_patched = false;

constexpr uint8_t THIRD_PERSON_NAMETAG_SIG[] = {
    0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x45, 0x00, 0x49, 0x8B, 0xCD, 0x48, 0x8B, 0x80,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x84, 0xC0, 0x0F, 0x85
};

constexpr uint8_t THIRD_PERSON_NAMETAG_MASK[] = {
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

static uintptr_t FindPattern(uintptr_t base, size_t size,
                             const uint8_t* pattern, const uint8_t* mask, size_t patternLen) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(base);
    for (size_t i = 0; i < size - patternLen; ++i) {
        bool found = true;
        for (size_t j = 0; j < patternLen; ++j) {
            if (mask[j] == 0xFF && data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}

static void ApplyPatch() {
    if (!g_instructionPointer || g_patched) return;
    DWORD protect;
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &protect);
    memset(g_instructionPointer, 0x90, INSTRUCTION_SIZE);
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, protect, &protect);
    g_patched = true;
}

static void RemovePatch() {
    if (!g_instructionPointer || !g_patched) return;
    DWORD protect;
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &protect);
    memcpy(g_instructionPointer, g_originalBytes, INSTRUCTION_SIZE);
    VirtualProtect(g_instructionPointer, INSTRUCTION_SIZE, protect, &protect);
    g_patched = false;
}

static void Initialize() {
    HMODULE base = GetModuleHandleA(nullptr);
    if (!base) return;

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(base) + dosHeader->e_lfanew);
    size_t sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

    uintptr_t targetAddr = FindPattern(
        reinterpret_cast<uintptr_t>(base), sizeOfImage,
        THIRD_PERSON_NAMETAG_SIG, THIRD_PERSON_NAMETAG_MASK,
        sizeof(THIRD_PERSON_NAMETAG_SIG));

    if (targetAddr) {
        g_instructionPointer = reinterpret_cast<void*>(targetAddr);
        memcpy(g_originalBytes, g_instructionPointer, INSTRUCTION_SIZE);
        ApplyPatch();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        std::thread(Initialize).detach();
    } else if (reason == DLL_PROCESS_DETACH) {
        RemovePatch();
    }
    return TRUE;
}

#else
#if defined(__aarch64__)
#include <cstdint>
#include <cstring>
#include <sys/mman.h>

#include "pl/Gloss.h"
#include "pl/Signature.h"

static const char* NAMETAG_SIGNATURE =
        "? ? 40 F9 "
        "? ? ? EB "
        "? ? ? 54 "
        "? ? 40 F9 "
        "? 81 40 F9 "
        "E0 03 ? AA "
        "00 01 3F D6 "
        "? ? 00 37 "
        "? ? 40 F9 "
        "? ? ? A9 "
        "? ? ? CB "
        "? ? ? D3 "
        "? ? 00 51 "
        "? ? ? 8A";

static constexpr size_t PATCH_OFFSET = 8;

static const uint8_t PATCH_BYTES[4] = { 0x1F, 0x20, 0x03, 0xD5 };
static const size_t  PATCH_SIZE     = sizeof(PATCH_BYTES);

static bool PatchMemory(void* addr, const void* data, size_t size) {
    uintptr_t page_start = (uintptr_t)addr & ~(4095UL);
    size_t    page_size  = ((uintptr_t)addr + size - page_start + 4095) & ~(4095UL);

    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    memcpy(addr, data, size);
    __builtin___clear_cache((char*)addr, (char*)addr + size);
    mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);

    return true;
}

static bool PatchNametag() {
    uintptr_t addr = pl::signature::pl_resolve_signature(NAMETAG_SIGNATURE, "libminecraftpe.so");
    if (addr == 0) {
        return false;
    }

    void* patch_target = reinterpret_cast<void*>(addr + PATCH_OFFSET);
    return PatchMemory(patch_target, PATCH_BYTES, PATCH_SIZE);
}

__attribute__((constructor))
void ThirdPersonNametag_Init() {
    GlossInit(true);
    PatchNametag();
}

#elif defined(__x86_64__)
#include <dlfcn.h>
#include <link.h>
#include <span>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <libhat.hpp>
#include <libhat/scanner.hpp>

static bool patch_applied = false;

static bool PatchMemory(void* addr, const void* data, size_t size) {
    long page_size  = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~((uintptr_t)(page_size - 1));
    size_t len      = ((uintptr_t)addr + size - start + page_size - 1) & ~((size_t)(page_size - 1));

    if (mprotect((void*)start, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("[-] mprotect RWX failed");
        return false;
    }
    memcpy(addr, data, size);
    mprotect((void*)start, len, PROT_READ | PROT_EXEC);
    return true;
}

extern "C" [[gnu::visibility("default")]] void mod_preinit() {}

extern "C" [[gnu::visibility("default")]] void mod_init() {
    using namespace hat::literals::signature_literals;

    void* mcLib = dlopen("libminecraftpe.so", 0);
    if (!mcLib) {
        printf("[-] patch: failed to open libminecraftpe.so\n");
        return;
    }

    std::span<std::byte> range1;
    auto callback = [&](const dl_phdr_info& info) {
        auto h = dlopen(info.dlpi_name, RTLD_NOLOAD);
        dlclose(h);
        if (h != mcLib) return 0;
        range1 = {
            reinterpret_cast<std::byte*>(info.dlpi_addr + info.dlpi_phdr[1].p_vaddr),
            info.dlpi_phdr[1].p_memsz
        };
        return 1;
    };
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void* data) {
        return (*static_cast<decltype(callback)*>(data))(*info);
    }, &callback);

    if (range1.empty()) {
        printf("[-] patch: failed to get libminecraftpe.so range\n");
        return;
    }

    printf("[+] patch: scanning range %p size 0x%zx\n", range1.data(), range1.size());

    auto match = hat::find_pattern(range1,
        "4C 8B 23 "
        "4C 3B 64 24 28 "
        "0F 84 ?? ?? ?? ?? "
        "49 89 ED "
        "49 8B 04 24 "
        "4C 89 E7 "
        "FF 90 00 01 00 00 "
        "84 C0 "
        "4C 89 ED "
        "0F 85 ?? ?? ?? ?? "
        "49 8B 7C 24 10 "
        "48 8B 47 38 "
        "48 8B 4F 40 "
        "48 29 C1 "
        "48 C1 E9 03 "
        "FF C9 "
        "81 E1 A9 81 D9 97 "
        "48 8B 04 C8 "
        "48 83 F8 FF"_sig,
        hat::scan_alignment::X1
    ).get();

    if (!match) {
        printf("[-] patch: signature not found\n");
        return;
    }

    printf("[+] patch: signature found at %p\n", match);

    void* jz_addr = reinterpret_cast<uint8_t*>(match) + 8;
    printf("[+] patch: patching jz at %p\n", jz_addr);

    static const uint8_t NOP6[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

    if (PatchMemory(jz_addr, NOP6, sizeof(NOP6))) {
        printf("[+] patch: jz NOPed successfully\n");
        patch_applied = true;
    } else {
        printf("[-] patch: patch failed\n");
    }
}

#endif
#endif
