# OpenReverse extensions

OpenReverse Community supports trusted native extensions through the public
Windows x64 C ABI in `sdk/include/openreverse/extension.h`. The host, project
system, analysis database, navigation, and workspace layout remain owned by the
Community application. An extension receives only the function table granted by
its validated manifest; it does not receive internal C++ objects or Dear ImGui
state.

The application is fully functional when the `extensions` directory is absent
or empty. A future separately maintained module may consume this same public
SDK, but no proprietary module or Pro feature is included in this repository.

## ABI and compatibility

API version 1 is selected by `OPENREVERSE_EXTENSION_API_VERSION`. It targets
64-bit Windows, uses `__cdecl`, fixed-width integers, explicit `struct_size`
fields, eight-byte structure packing, and the exported C entrypoint
`OpenReverseExtensionGetDescriptor`. C++ standard-library types, exceptions,
raw application pointers, and implementation classes never cross the ABI.

The manifest API version, extension semantic version, minimum host version, and
capability set must agree with the exported descriptor. OpenReverse rejects an
incompatible extension and reports a diagnostic in **Tools > Extensions**; it
does not call its initialization callback.

ABI v1 structures may be extended only compatibly. Callers initialize
`struct_size`, check the host API version, and must not read fields beyond the
size provided by the other side. Addresses are 64-bit values. Function records
are snapshots identified by address and RVA, not borrowed pointers.

## Directory and manifest

Install each extension in its own immediate child of the application-local
`extensions` directory:

```text
OpenReverse/
  OpenReverse.exe
  extensions/
    org.example.extension/
      manifest.json
      ExampleExtension.dll
```

OpenReverse examines only `manifest.json` files in those immediate child
directories. It does not load arbitrary DLLs from the executable directory or
recursively scan the filesystem. Symbolic-link directories and paths resolving
outside the configured root are rejected. The entrypoint must be a filename-only
`.dll` in the same directory as its manifest.

A manifest has this required shape:

```json
{
  "id": "org.example.extension",
  "name": "Example Extension",
  "version": "0.1.0",
  "api_version": 1,
  "minimum_openreverse_version": "2.0.0",
  "author": "Example Author",
  "description": "A concise description.",
  "entrypoint": "ExampleExtension.dll",
  "capabilities": ["analysis.read", "ui.command"]
}
```

IDs are lowercase, dot-qualified identifiers. Versions use exactly three
unsigned decimal components without leading zeroes. Manifests are limited to
64 KiB, 16 root members, 32 unique capabilities, bounded strings, and known
required field types. Duplicate extension IDs, malformed JSON, missing DLLs, missing
entrypoints, initialization failures, and version mismatches fail independently
without preventing compatible siblings from loading.

The loader resolves a canonical full path and uses `LoadLibraryExW` with
`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`. The current
working directory is not part of extension discovery.

## Capabilities

API v1 currently grants these capabilities:

| Manifest capability | Access |
| --- | --- |
| `analysis.read` | Read the active target and bounded function snapshots. |
| `project.read` | Read the current project path. |
| `project.extension_state` | Read or replace only this extension's JSON project object. |
| `navigation` | Request navigation to a valid address in the active module. |
| `ui.command` | Register commands during initialization. |
| `ui.panel` | Register host-rendered, read-only text panels during initialization. |

The ABI reserves names/bits for `analysis.action`, `ai.action`, `filesystem`,
`network`, `process.memory`, and `project.write`, but the Community host does not
grant them. Requesting one rejects the extension. Capability declarations are a
host API boundary, not an operating-system sandbox: native code can still call
Windows APIs directly.

## Ownership, buffers, and errors

Input `OpenReverseStringView` data is borrowed only for the duration of the
host call. Variable output uses caller-owned buffers. First call with a null or
small buffer to obtain `required_size`, allocate that many bytes, then retry.
Successful text output is UTF-8 and NUL-terminated. Extensions must copy any
data they need after a callback returns and must not retain application-owned
pointers.

Every fallible ABI function returns `OpenReverseResult`, including explicit
results for invalid arguments, missing objects, unsupported APIs, inactive
sessions/projects, denied capabilities, undersized buffers, duplicate IDs,
invalid state, and internal failure. C++ exceptions must not cross the ABI.
OpenReverse catches exceptions at controlled callback boundaries and converts
them to diagnostics where practical.

## Lifecycle

The lifecycle is:

1. Discover and validate the manifest.
2. Load the explicit DLL and obtain its descriptor.
3. Call `initialize`; commands and panels may be registered only during this
   callback on the UI thread.
4. Send `session_changed`, `project_opened`, and `project_closed` events while
   their corresponding application state is valid.
5. Call `shutdown` once, discard registrations, and unload in reverse load
   order after application work has stopped.

Callbacks are serialized on the application's owner/UI thread, and ABI v1 host
functions must be called from that thread during an OpenReverse callback. Calls
from extension-created worker threads return `OPENREVERSE_ERROR_INVALID_STATE`.
An extension must not keep callback event pointers, call UI registration later,
or invoke the host API after shutdown begins. Panel rendering returns bounded UTF-8 text; the
Community host owns the ImGui window and docking state. Commands are exposed
under **Tools > Extension commands**, panels under **View > Extension panels**.

## Extension project state

With `project.extension_state`, an extension can store one JSON object under its
own ID in the optional root `extensions` member of a `.orev` project. OpenReverse
treats the schema as extension-owned opaque data, validates and canonicalizes
it, includes it in project integrity, and preserves it when the extension is not
installed. State is limited to 256 KiB per extension, 128 extension IDs, depth
16, and 10,000 JSON nodes. It cannot contain executable behavior.

Extensions should include their own schema version inside the object and handle
missing state as a first run. They cannot use this API to read or overwrite
another extension's state.

## Build the example

`examples/hello_extension` uses only the public SDK header. It registers one
command, reads the function list, requests controlled navigation to the first
function, and supplies one small read-only panel. It contains no Pro behavior.

Build it independently from the repository root:

```powershell
cmake -S examples/hello_extension -B build/hello-extension
cmake --build build/hello-extension --config Release
```

Create an extension child directory beside `OpenReverse.exe`, then copy the
built `OpenReverseHelloExtension.dll` and the example `manifest.json` into it.
The normal application build does not install or activate the example.

## Trust and isolation

Native extensions execute in the OpenReverse process and therefore can crash,
corrupt, inspect, or otherwise affect the host with the user's privileges.
Manifest validation, ABI checks, bounded buffers, controlled callbacks, and
safe DLL search flags reduce accidental and loader-level failures; they do not
sandbox hostile native code. Install only extensions whose publisher and binary
you trust.

Stronger isolation through a separate extension host, RPC, process-level
restrictions, and signed distribution remains research. OpenReverse does not
currently claim extension sandboxing or signature verification.
