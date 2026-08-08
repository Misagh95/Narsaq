# Narsaq

Narsaq is a family of tools for scanning clean Cloudflare endpoints, testing proxy configurations, and rebuilding configurations with the best available endpoints. This monorepo contains the three official implementations.

| Project | Platform | Language | Source | Documentation |
| --- | --- | --- | --- | --- |
| Narsaq Android | Android 8.0+ | Kotlin | [`android/`](android/) | [English](android/README.md) / [فارسی](android/README.fa.md) |
| Narsaq Desktop | Windows | Python | [`desktop/`](desktop/) | [README](desktop/README.md) |
| Narsaq Go | Windows, Linux, macOS, Termux | Go | [`go/`](go/) | [README](go/README.md) |

## Repository layout

```text
Narsaq/
|-- android/   Android application and Gradle wrapper
|-- desktop/   Python desktop application and Windows release builder
|-- go/        Cross-platform Go implementation
|-- docs/      Shared documentation assets
`-- .github/   CI and release workflows
```

## Build

### Android

```bash
cd android
./gradlew testDebugUnitTest
./gradlew assembleDebug
```

On Windows, use `gradlew.bat` instead of `./gradlew`.

### Desktop

```bash
cd desktop
python narsaq_gui.py
```

To build the Windows release:

```bash
cd desktop
pip install pyinstaller==6.20.0 pillow pywebview==6.2.1
python build_release.py
```

### Go

```bash
cd go
go test ./...
go build ./...
```

## Releases

Each implementation has an independent tag namespace:

- `android-v1.1.0`
- `desktop-v1.0.0`
- `go-v1.1.0`

Desktop and Go release workflows can also be started manually from GitHub Actions.

## License

MIT
