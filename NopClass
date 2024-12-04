class NopDetour
{
public:
    bool enabled = false;
    uint8_t bytes;
    uintptr_t target;
    uintptr_t memory;
    uint8_t* savedBytes;

    NopDetour(uintptr_t targetAddress, uint8_t bytesToNop) noexcept {
        bytes = bytesToNop;
        target = targetAddress;

        savedBytes = new uint8_t[bytes];
        for (uint8_t i = 0; i < bytes; i++) {
            savedBytes[i] = *reinterpret_cast<uint8_t*>(targetAddress + i);
        }
    }

    void startNop() noexcept {
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(target), bytes, PAGE_EXECUTE_READWRITE, &oldProtect);
        enabled = true;
        for (uint8_t i = 0; i < bytes; i++) {
            *reinterpret_cast<uint8_t*>(target + i) = 0x90;
        }
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(target), bytes);
        VirtualProtect(reinterpret_cast<void*>(target), bytes, oldProtect, &oldProtect);
        return;
    }

    void endNop() noexcept {
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(target), bytes, PAGE_EXECUTE_READWRITE, &oldProtect);
        enabled = false;
        for (uint8_t i = 0; i < bytes; i++) {
            *reinterpret_cast<uint8_t*>(target + i) = savedBytes[i];
        }
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(target), bytes);
        VirtualProtect(reinterpret_cast<void*>(target), bytes, oldProtect, &oldProtect);
        return;
    }

    void toggleNop() noexcept {
        if (enabled)
            endNop();
        else
            startNop();
        return;
    }

    ~NopDetour() noexcept {
        endNop();
        delete[] savedBytes;
    }
};
