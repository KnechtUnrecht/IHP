#include "../third_party/imgui/imgui.h"
#include "../third_party/imgui/imgui_impl_win32.h"
#include "../third_party/imgui/imgui_impl_dx11.h"

#include <d3d11.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <shellapi.h>

#include "scanner/scanner_engine.h"
#include "gui/gui.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

// Forward declarations
static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;
static bool                     g_ResizeRequested = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;

static ihp::GUI* g_gui = nullptr;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)lpCmdLine;

    // Initialize COM for folder browser dialog
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    // Create application window
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"IHPClass";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    wc.hIconSm = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        WS_EX_ACCEPTFILES, // Accept drag-and-drop
        wc.lpszClassName,
        L"Imagine Hacking People",
        WS_OVERLAPPEDWINDOW,
        100, 100, 1280, 800,
        nullptr, nullptr, hInstance, nullptr);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, hInstance);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;  // disable imgui.ini file

    // Load fonts
    // Try Segoe UI first, fall back to Tahoma, then default
    ImFont* font_regular = nullptr;
    ImFont* font_large = nullptr;
    ImFont* font_small = nullptr;

    char win_dir[MAX_PATH];
    GetWindowsDirectoryA(win_dir, MAX_PATH);
    std::string fonts_dir = std::string(win_dir) + "\\Fonts\\";

    std::string segoe_path = fonts_dir + "segoeui.ttf";
    std::string segoe_bold_path = fonts_dir + "segoeuib.ttf";
    std::string tahoma_path = fonts_dir + "tahoma.ttf";

    // Try Segoe UI (available on Win7+)
    FILE* test = fopen(segoe_path.c_str(), "rb");
    if (test) {
        fclose(test);
        font_regular = io.Fonts->AddFontFromFileTTF(segoe_path.c_str(), 17.0f);
        font_large = io.Fonts->AddFontFromFileTTF(segoe_bold_path.c_str(), 28.0f);
        font_small = io.Fonts->AddFontFromFileTTF(segoe_path.c_str(), 14.0f);
    } else {
        // Fallback to Tahoma
        test = fopen(tahoma_path.c_str(), "rb");
        if (test) {
            fclose(test);
            font_regular = io.Fonts->AddFontFromFileTTF(tahoma_path.c_str(), 16.0f);
            font_large = io.Fonts->AddFontFromFileTTF(tahoma_path.c_str(), 26.0f);
            font_small = io.Fonts->AddFontFromFileTTF(tahoma_path.c_str(), 13.0f);
        }
    }
    // Load monospace font for code viewer (Consolas → Courier New fallback)
    ImFont* font_mono = nullptr;
    {
        std::string consolas_path = fonts_dir + "consola.ttf";
        FILE* mono_test = fopen(consolas_path.c_str(), "rb");
        if (mono_test) {
            fclose(mono_test);
            font_mono = io.Fonts->AddFontFromFileTTF(consolas_path.c_str(), 14.0f);
        } else {
            std::string courier_path = fonts_dir + "cour.ttf";
            mono_test = fopen(courier_path.c_str(), "rb");
            if (mono_test) {
                fclose(mono_test);
                font_mono = io.Fonts->AddFontFromFileTTF(courier_path.c_str(), 14.0f);
            }
        }
    }
    // If no fonts loaded, ImGui uses its built-in proggy font
    // Note: With ImGui 1.92+, font atlas is built automatically by the backend

    // Dark theme
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();

    // Rounded, spacious, modern look
    style.WindowRounding = 0.0f;
    style.ChildRounding = 8.0f;
    style.FrameRounding = 6.0f;
    style.GrabRounding = 6.0f;
    style.PopupRounding = 6.0f;
    style.ScrollbarRounding = 6.0f;
    style.TabRounding = 6.0f;
    style.FramePadding = ImVec2(10, 6);
    style.ItemSpacing = ImVec2(10, 8);
    style.ItemInnerSpacing = ImVec2(8, 6);
    style.WindowPadding = ImVec2(20, 16);
    style.ScrollbarSize = 14.0f;
    style.GrabMinSize = 12.0f;
    style.FrameBorderSize = 0.0f;
    style.WindowBorderSize = 0.0f;
    style.PopupBorderSize = 1.0f;
    style.IndentSpacing = 20.0f;

    // Modern dark color scheme with subtle red accent
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg]           = ImVec4(0.078f, 0.082f, 0.098f, 1.00f);
    colors[ImGuiCol_ChildBg]            = ImVec4(0.098f, 0.102f, 0.122f, 1.00f);
    colors[ImGuiCol_PopupBg]            = ImVec4(0.118f, 0.122f, 0.145f, 0.98f);
    colors[ImGuiCol_Border]             = ImVec4(0.18f, 0.19f, 0.22f, 0.60f);
    colors[ImGuiCol_BorderShadow]       = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    colors[ImGuiCol_FrameBg]            = ImVec4(0.13f, 0.14f, 0.17f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]     = ImVec4(0.17f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_FrameBgActive]      = ImVec4(0.20f, 0.14f, 0.14f, 1.00f);
    colors[ImGuiCol_TitleBg]            = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
    colors[ImGuiCol_TitleBgActive]      = ImVec4(0.10f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]   = ImVec4(0.07f, 0.07f, 0.09f, 0.60f);
    colors[ImGuiCol_MenuBarBg]          = ImVec4(0.10f, 0.10f, 0.13f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]        = ImVec4(0.08f, 0.08f, 0.10f, 0.60f);
    colors[ImGuiCol_ScrollbarGrab]      = ImVec4(0.25f, 0.18f, 0.18f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]=ImVec4(0.35f, 0.22f, 0.22f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]= ImVec4(0.45f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_CheckMark]          = ImVec4(0.90f, 0.35f, 0.30f, 1.00f);
    colors[ImGuiCol_SliderGrab]         = ImVec4(0.70f, 0.28f, 0.25f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]   = ImVec4(0.85f, 0.35f, 0.30f, 1.00f);
    colors[ImGuiCol_Button]             = ImVec4(0.16f, 0.17f, 0.20f, 1.00f);
    colors[ImGuiCol_ButtonHovered]      = ImVec4(0.22f, 0.16f, 0.16f, 1.00f);
    colors[ImGuiCol_ButtonActive]       = ImVec4(0.35f, 0.18f, 0.16f, 1.00f);
    colors[ImGuiCol_Header]             = ImVec4(0.16f, 0.12f, 0.12f, 1.00f);
    colors[ImGuiCol_HeaderHovered]      = ImVec4(0.25f, 0.15f, 0.15f, 1.00f);
    colors[ImGuiCol_HeaderActive]       = ImVec4(0.35f, 0.18f, 0.16f, 1.00f);
    colors[ImGuiCol_Separator]          = ImVec4(0.20f, 0.16f, 0.16f, 0.50f);
    colors[ImGuiCol_SeparatorHovered]   = ImVec4(0.45f, 0.20f, 0.18f, 0.70f);
    colors[ImGuiCol_SeparatorActive]    = ImVec4(0.60f, 0.25f, 0.22f, 1.00f);
    colors[ImGuiCol_ResizeGrip]         = ImVec4(0.30f, 0.18f, 0.16f, 0.25f);
    colors[ImGuiCol_ResizeGripHovered]  = ImVec4(0.45f, 0.22f, 0.20f, 0.65f);
    colors[ImGuiCol_ResizeGripActive]   = ImVec4(0.60f, 0.28f, 0.25f, 0.90f);
    colors[ImGuiCol_Tab]                = ImVec4(0.14f, 0.12f, 0.12f, 1.00f);
    colors[ImGuiCol_TabHovered]         = ImVec4(0.35f, 0.18f, 0.16f, 0.80f);
    colors[ImGuiCol_TableHeaderBg]      = ImVec4(0.12f, 0.10f, 0.10f, 1.00f);
    colors[ImGuiCol_TableRowBg]         = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    colors[ImGuiCol_TableRowBgAlt]      = ImVec4(1.0f, 1.0f, 1.0f, 0.02f);
    colors[ImGuiCol_TableBorderStrong]  = ImVec4(0.20f, 0.16f, 0.16f, 0.60f);
    colors[ImGuiCol_TableBorderLight]   = ImVec4(0.16f, 0.14f, 0.14f, 0.40f);
    colors[ImGuiCol_TextSelectedBg]     = ImVec4(0.45f, 0.20f, 0.18f, 0.40f);
    colors[ImGuiCol_PlotHistogram]      = ImVec4(0.85f, 0.32f, 0.28f, 1.00f);
    colors[ImGuiCol_PlotHistogramHovered]=ImVec4(0.95f, 0.40f, 0.35f, 1.00f);
    colors[ImGuiCol_Text]               = ImVec4(0.92f, 0.93f, 0.95f, 1.00f);
    colors[ImGuiCol_TextDisabled]       = ImVec4(0.45f, 0.46f, 0.50f, 1.00f);

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // Initialize scanner engine (signatures are embedded in the EXE)
    ihp::ScannerEngine engine;
    engine.init();

    // Initialize GUI
    ihp::GUI gui(engine, font_regular, font_large, font_small, font_mono);
    g_gui = &gui;

    // Handle command-line arguments (files passed via drag-drop onto exe)
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc > 1) {
        std::vector<std::string> files;
        for (int i = 1; i < argc; i++) {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, nullptr, 0, nullptr, nullptr);
            std::string str(size_needed - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, str.data(), size_needed, nullptr, nullptr);
            files.push_back(str);
        }
        gui.on_files_dropped(files);
        LocalFree(argv);
    }

    // Main loop
    ImVec4 clear_color = ImVec4(0.06f, 0.06f, 0.08f, 1.00f);
    bool done = false;

    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) {
                done = true;
            }
        }
        if (done) break;

        // Check if updater wants us to exit (self-update in progress)
        if (gui.should_exit()) {
            done = true;
            break;
        }

        // Handle window resize
        if (g_ResizeRequested) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
            g_ResizeRequested = false;
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Render our GUI
        gui.render();

        // Rendering
        ImGui::Render();
        const float clear_color_with_alpha[4] = {
            clear_color.x * clear_color.w, clear_color.y * clear_color.w,
            clear_color.z * clear_color.w, clear_color.w
        };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0); // vsync
    }

    // Cleanup
    g_gui = nullptr;
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, hInstance);
    CoUninitialize();

    return 0;
}

bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        featureLevelArray, 2, D3D11_SDK_VERSION, &sd,
        &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);

    if (hr == DXGI_ERROR_UNSUPPORTED) {
        hr = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
            featureLevelArray, 2, D3D11_SDK_VERSION, &sd,
            &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    }

    if (FAILED(hr)) return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)        { g_pSwapChain->Release();        g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext)  { g_pd3dDeviceContext->Release();  g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)         { g_pd3dDevice->Release();         g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED) return 0;
            g_ResizeWidth = (UINT)LOWORD(lParam);
            g_ResizeHeight = (UINT)HIWORD(lParam);
            g_ResizeRequested = true;
            return 0;

        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            UINT count = DragQueryFileA(hDrop, 0xFFFFFFFF, nullptr, 0);
            std::vector<std::string> files;
            for (UINT i = 0; i < count; i++) {
                char path[MAX_PATH];
                DragQueryFileA(hDrop, i, path, MAX_PATH);
                files.push_back(path);
            }
            DragFinish(hDrop);
            if (g_gui) {
                g_gui->on_files_dropped(files);
            }
            return 0;
        }

        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}
