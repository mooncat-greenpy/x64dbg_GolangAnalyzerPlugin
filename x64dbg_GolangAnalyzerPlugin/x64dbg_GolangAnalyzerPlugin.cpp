#include "x64dbg_GolangAnalyzerPlugin.h"
#include "golang_analyzer.h"


#define szx64dbg_GolangAnalyzerPluginInfo "GolangAnalyzerPlugin Usage:\n" 


int pluginHandle;
HWND hwndDlg;
int hMenu;
int hMenuDisasm;
int hMenuDump;
int hMenuStack;


extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}


DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy(initStruct->pluginName, PLUGIN_NAME);
    pluginHandle = initStruct->pluginHandle;

    init_analyzer_plugin();
    return true;
}


DLL_EXPORT bool plugstop()
{
    _plugin_menuclear(hMenu);

    stop_analyzer_plugin();
    return true;
}


DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    hMenuDisasm = setupStruct->hMenuDisasm;
    hMenuDump = setupStruct->hMenuDump;
    hMenuStack = setupStruct->hMenuStack;

    GuiAddLogMessage, szx64dbg_GolangAnalyzerPluginInfo;

    setup_analyzer_plugin();
}


extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY * info)
{

}


extern "C" __declspec(dllexport) void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG * info)
{

}


extern "C" __declspec(dllexport) void CBSYSTEMBREAKPOINT(CBTYPE cbType, PLUG_CB_SYSTEMBREAKPOINT * info)
{

}
