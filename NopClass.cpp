/*
 USAGE
 We want to make a infinite ammo cheat for assault cube
 whe we shoot the assembly X86 code will execute [dec [eax]] that will decrease by 1 at address stored in EAX register
 we want to make [dec [eax]] to NOP instruction that mean No OPeration

 unsigned int mean max address location FFFFFFFF for X86 architecture (if process is X86 he can allocate 4GB of ram because unsigned int is 2^32 = 4294967296[4GB])(X64 got 64 bits FFFFFFFF FFFFFFFF)

 /variables/
 unsigned int targetAddress = address of our target (ASM code X86: [dec [eax]])
 uint8_t distanceInBytes = 2 (ASM code X86: [dec [eax]] is 2 bytes long operation [FF 08])

 NopDetour ammunitionNOP(targetAddress, distanceInBytes);

 when we use startNOP
 [dec [eax]] will become to [NOP NOP] that means there will be no code to decrease our ammo

 when we use endNOP
 it will restore to original
*/

class NopDetour
{
public:
    bool enabled = false;
    uint8_t bytes;
    uintptr_t target;
    uintptr_t memory;
    BYTE* savedBytes;

    NopDetour(uintptr_t targetAddress, uint8_t bytesToNop) noexcept {
        bytes = bytesToNop;
        target = targetAddress;

        savedBytes = new BYTE[bytes];
        for (uint8_t i = 0; i < bytes; i++) {
            savedBytes[i] = *reinterpret_cast<BYTE*>(targetAddress + i);
        }
    }

    void startNop() noexcept {
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(target), bytes, PAGE_EXECUTE_READWRITE, &oldProtect);
        enabled = true;
        for (uint8_t i = 0; i < bytes; i++) {
            *reinterpret_cast<BYTE*>(target + i) = 0x90;
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
            *reinterpret_cast<BYTE*>(target + i) = savedBytes[i];
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
