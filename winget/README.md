# WinGet Package Manifests for OPENREVERSE Studio (`apexfromparis.OpenReverse`)

This directory contains the official **Windows Package Manager (WinGet)** manifests for submitting `OPENREVERSE Studio` to the official Microsoft WinGet community repository (`microsoft/winget-pkgs`).

---

## 📋 Package Details
- **PackageIdentifier**: `apexfromparis.OpenReverse`
- **Version**: `2.0.0`
- **InstallerType**: `portable` (`openreverse.exe`)
- **Commands**: `openreverse`

---

## 🚀 How to Submit to Microsoft WinGet (`microsoft/winget-pkgs`)

Once you publish a GitHub Release (`v2.0.0`) with `openreverse.exe` attached, follow these steps to make your CLI officially installable via `winget install apexfromparis.OpenReverse`:

### Option A: Using GitHub Web Interface (Easiest - 2 minutes)
1. Fork the official Microsoft repository: [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs).
2. In your fork, create a new folder structure inside the `manifests/a/` directory:
   ```text
   manifests/a/apexfromparis/OpenReverse/2.0.0/
   ```
3. Copy the 3 YAML files from this directory (`winget/apexfromparis/OpenReverse/2.0.0/`) into that folder:
   - `apexfromparis.OpenReverse.yaml`
   - `apexfromparis.OpenReverse.installer.yaml`
   - `apexfromparis.OpenReverse.locale.en-US.yaml`
4. Open a **Pull Request (PR)** against `microsoft/winget-pkgs:master`.
5. Microsoft's automated CI bots will test the installation. Once merged (usually within 15–30 minutes), any Windows user can install OPENREVERSE via:
   ```powershell
   winget install apexfromparis.OpenReverse
   ```

---

### Option B: Using Microsoft's Official `wingetcreate` CLI Tool
If you have `wingetcreate` installed:
```powershell
wingetcreate update --urls https://github.com/apexfromparis/powerfull-ida/releases/download/v2.0.0/openreverse.exe --version 2.0.0 --submit
```

---

## 🔍 Verifying the Manifests Locally
You can validate the schema using the WinGet CLI:
```powershell
winget validate .\apexfromparis\OpenReverse\2.0.0\
```
