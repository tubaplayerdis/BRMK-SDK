#include <chrono>
#include "Basic.hpp"
#include "BrickRigs_classes.hpp"
#include "Engine_classes.hpp"
#include "../Include/Hooking/Hook.hpp"

using namespace UC;
uintptr_t O_GObjects = 0;
uintptr_t O_AppendString = 0;
uintptr_t O_GNames = 0;
uintptr_t O_GWorld = 0;
uintptr_t O_ProcessEvent = 0;

//Editor Sigs
#define EDITOR_PROCESS_EVENT_MODULE "BrickRigsModKitSteam-CoreUObject.dll"
#define EDITOR_PROCESS_EVENT_SYB "?ProcessEvent@UObject@@UEAAXPEAVUFunction@@PEAX@Z"

#define EDITOR_GOBJECTS_MODULE "BrickRigsModKitSteam-CoreUObject.dll"
#define EDITOR_GOBJECTS_SYB "?GUObjectArray@@3VFUObjectArray@@A"

#define EDITOR_APPEND_STRING_MODULE "BrickRigsModKitSteam-Core.dll"
#define EDITOR_APPEND_STRING_SYB "?AppendString@FName@@QEBAXAEAVFString@@@Z"

#define EDITOR_GNAMES_MODULE "BrickRigsModKitSteam-Core.dll"
#define EDITOR_GNAMES_SYB "" //Currently not exported

#define EDITOR_GWORLD_MODULE "BrickRigsModKitSteam-Engine.dll"
#define EDITOR_GWORLD_SYB "?GWorld@@3VUWorldProxy@@A"

namespace
{
    uintptr_t GetSymbolAddress(const char* Module, const char* Symbol)
    {
        HMODULE hModuleKit = GetModuleHandleA(Module); // or whatever the module's actually called
        return (uintptr_t)GetProcAddress(hModuleKit, Symbol);
    }
}

//Offset from the object array pointer where GObjects is
#define GOBJECTS_OFFSET 0x10

uintptr_t SDK::Offsets::OGObjects()
{
    if (O_GObjects == 0)
    {
        O_GObjects = GetSymbolAddress(EDITOR_GOBJECTS_MODULE, EDITOR_GOBJECTS_SYB) + GOBJECTS_OFFSET;
    }

    if (O_GObjects == 0)
        std::cerr << "GObjects offset NOT FOUND\n";

    return O_GObjects;
}

uintptr_t SDK::Offsets::OAppendString()
{
    if (O_AppendString == 0)
    {
        O_AppendString = GetSymbolAddress(EDITOR_APPEND_STRING_MODULE, EDITOR_APPEND_STRING_SYB);
    }
    if (O_AppendString == 0) std::cerr << "AppendString offset NOT FOUND" << std::endl;
    return O_AppendString;
}

uintptr_t SDK::Offsets::OGNames()
{
    if (O_GNames == 0)
    {
        O_GNames = 0;//GetSymbolAddress(EDITOR_GNAMES_MODULE, EDITOR_GNAMES_SYB);
    }
    if (O_GNames == 0) std::cerr << "GNames offset NOT FOUND" << std::endl;
    return O_GNames;
}

uintptr_t SDK::Offsets::OGWorld()
{
    if (O_GWorld != 0) return O_GWorld;

    O_GWorld = GetSymbolAddress(EDITOR_GWORLD_MODULE, EDITOR_GWORLD_SYB);
    if (O_ProcessEvent == 0) std::cerr << "GWorld Offset NOT FOUND" << std::endl;
    return O_GWorld;
}

uintptr_t SDK::Offsets::OProcessEvent()
{
    if (O_ProcessEvent == 0)
    {
        O_ProcessEvent = GetSymbolAddress(EDITOR_PROCESS_EVENT_MODULE, EDITOR_PROCESS_EVENT_SYB);
    }
    if (O_ProcessEvent == 0) std::cerr << "ProcessEvent Offset NOT FOUND" << std::endl;
    return O_ProcessEvent;
}

class Timer {
public:
    Timer() :
            m_beg(clock_::now()) {
    }
    void reset() {
        m_beg = clock_::now();
    }

    double elapsed() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                clock_::now() - m_beg).count();
    }

private:
    typedef std::chrono::high_resolution_clock clock_;
    typedef std::chrono::duration<double, std::ratio<1> > second_;
    std::chrono::time_point<clock_> m_beg;
};

#define PREFIX "[BR-SDK]: "

void SDK::Offsets::FindOffsets()
{
#ifdef _DEBUG
    Timer timer;
    std::cout << PREFIX << "Initializing BRMK-SDK offsets..." << std::endl;
    OGObjects();
    std::cout << PREFIX << "Found GObjects at: " << timer.elapsed() << "ms" << std::endl;
    OGWorld();
    std::cout << PREFIX << "Found GWorld at: " << timer.elapsed() << "ms" << std::endl;
    OAppendString();
    std::cout << PREFIX << "Found AppendString at: " << timer.elapsed() << "ms" << std::endl;
    //OGNames();
    //std::cout << PREFIX << "Found GNames at: " << timer.elapsed() << "ms" << std::endl;
    OProcessEvent();
    std::cout << PREFIX << "Found ProcessEvent at: " << timer.elapsed() << std::endl;
    std::cout << PREFIX << "Found BR-SDK offsets in: " << timer.elapsed() << "ms" << std::endl;
#else
    OGObjects();
    OGWorld();
    OAppendString();
    //OGNames();
    OProcessEvent();
#endif
}