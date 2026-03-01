# ThirdPersonNametag

A simple mod to show your own nametag in third person view for Minecraft Bedrock Edition — available for both **Windows** and **Android**.

I'd like to thank [Dasciam](https://github.com/Dasciam) for helping create the Android port. It wouldn't have been possible without her help.

## Features

- Shows your nametag when in third person view.
- Windows support: v26.2.1
- Android support: v26.2.1
- Linux support: not tested on v26.2.1 but 1.21.130.3 work

## Requirements

| Platform | Launcher                                                             |
| -------- | -------------------------------------------------------------------- |
| Windows  | [LeviLauncher (GDK)](https://github.com/LiteLDev/LeviLauncher)       |
| Android  | [LeviLauncher (Android)](https://github.com/LiteLDev/LeviLaunchroid) |
| Linu | [mcpelauncher-manifest](https://github.com/minecraft-linux/mcpelauncher-manifest) |

## Installation

### Windows

1. Download `ThirdPersonNametag.dll` from [Releases](../../releases) or GitHub Actions.
2. Install LeviLauncher (GDK).
3. Add `ThirdPersonNametag.dll` as a mod in LeviLauncher.
4. Launch Minecraft through LeviLauncher.

### Android

1. Download `libThirdPersonNametag.so` from [Releases](../../releases) or GitHub Actions.
2. Install LeviLauncher (Android).
3. Add `libThirdPersonNametag.so` as a mod in LeviLauncher.
4. Launch Minecraft through LeviLauncher.

### Linux

1. Download `libmcpelauncherTPN-x86_64.so` from [Releases](../../releases) or GitHub Actions.
2. Install mcpelauncher-manifest.
3. Add `libmcpelauncherTPN-x86_64.so` to mods folder
4. Launch Minecraft through mcpelauncher-ui-qt/mcpelauncher-client.

## Building

This is a single codebase that compiles to both targets.

### Windows DLL

```sh
cmake -B build -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
# Output: build/Release/ThirdPersonNametag.dll
```

### Android SO (requires NDK)

```sh
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build
# Output: build/libThirdPersonNametag.so
```

### Android SO (mcpelauncher) (requires NDK)

```sh
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=x86_64 \
  -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build
# Output: build/libThirdPersonNametag.so
```

CI builds both automatically via GitHub Actions.
