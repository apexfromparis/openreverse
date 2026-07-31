# KYV Automated Decompilation & Reverse Engineering Report

- **Target Process**: `hwid_crackme.exe` (PID: `22892`)
- **Base Address**: `0x7FF62DB40000`
- **Functions Discovered**: `168`
- **Cross-References (XREFs)**: `0`
- **Strings Discovered**: `399`

## [ALERT] Command & Control (C2) URLs Detected
- `http://c2.kyv-security.local/verify_hwid_license`

## [ALERT] Sensitive Registry Paths Detected
- `Software\KYV\License\ActivationKey`

## Decompiled Hex-Rays C Pseudocode (Key Functions)

### Function `sub_00007FF62DB41000` (0x7FF62DB41000)
- **Size**: `1570 bytes` | **Complexity V(G)**: `34` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB41000 | Address: 0x00007FF62DB41000
// Size: 1570 bytes | Basic Blocks: 81 | Complexity V(G): 34
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB41000(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB41000:
    // --- Basic Block 0 (0x00007FF62DB41000 -> 0x00007FF62DB4104A) ---
    qword ptr [rsp + 0x10], rdx; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r15d, r15d
    dword ptr [rsp + 0x80], r15d; // mov
    rcx, rdx; // mov
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r13, rax; // mov
    r8, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [r8 + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x41d3]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB41077;
    } else {
        goto loc_7FF62DB4104A;
    }

loc_7FF62DB4104A:
    // --- Basic Block 1 (0x00007FF62DB4104A -> 0x00007FF62DB4105F) ---
    rcx, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rcx + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x41be]
    // asm: cmp rax, r13
    if (jle_condition) {
        goto loc_7FF62DB41077;
    } else {
        goto loc_7FF62DB4105F;
    }

loc_7FF62DB4105F:
    // --- Basic Block 2 (0x00007FF62DB4105F -> 0x00007FF62DB41077) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x41a9]
    r14, rax; // mov
    // asm: sub r14, r13
    goto loc_7FF62DB4107A;

loc_7FF62DB41077:
    // --- Basic Block 3 (0x00007FF62DB41077 -> 0x00007FF62DB4107A) ---
    r14, r15; // mov

loc_7FF62DB4107A:
    // --- Basic Block 4 (0x00007FF62DB4107A -> 0x00007FF62DB41097) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x407e]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB410A4;
    } else {
        goto loc_7FF62DB41097;
    }

loc_7FF62DB41097:
    // --- Basic Block 5 (0x00007FF62DB41097 -> 0x00007FF62DB410A4) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB410A4:
    // --- Basic Block 6 (0x00007FF62DB410A4 -> 0x00007FF62DB410B8) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x4184]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB410BE;
    } else {
        goto loc_7FF62DB410B8;
    }

loc_7FF62DB410B8:
    // --- Basic Block 7 (0x00007FF62DB410B8 -> 0x00007FF62DB410BE) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB410FE;

loc_7FF62DB410BE:
    // --- Basic Block 8 (0x00007FF62DB410BE -> 0x00007FF62DB410D3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x403a]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB410F7;
    } else {
        goto loc_7FF62DB410D3;
    }

loc_7FF62DB410D3:
    // --- Basic Block 9 (0x00007FF62DB410D3 -> 0x00007FF62DB410D8) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB410F7;
    } else {
        goto loc_7FF62DB410D8;
    }

loc_7FF62DB410D8:
    // --- Basic Block 10 (0x00007FF62DB410D8 -> 0x00007FF62DB410F7) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x4087]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x4147]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB410FE;

loc_7FF62DB410F7:
    // --- Basic Block 11 (0x00007FF62DB410F7 -> 0x00007FF62DB410FE) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB410FE:
    // --- Basic Block 12 (0x00007FF62DB410FE -> 0x00007FF62DB41102) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB4110D;
    } else {
        goto loc_7FF62DB41102;
    }

loc_7FF62DB41102:
    // --- Basic Block 13 (0x00007FF62DB41102 -> 0x00007FF62DB4110D) ---
    r15d, 4; // mov
    goto loc_7FF62DB41204;

loc_7FF62DB4110D:
    // --- Basic Block 14 (0x00007FF62DB4110D -> 0x00007FF62DB41127) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x4113]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB4116B;
    } else {
        goto loc_7FF62DB41127;
    }

loc_7FF62DB41127:
    // --- Basic Block 15 (0x00007FF62DB41127 -> 0x00007FF62DB4112C) ---
    // asm: test r14, r14
    if (jle_condition) {
        goto loc_7FF62DB41166;
    } else {
        goto loc_7FF62DB4112C;
    }

loc_7FF62DB4112C:
    // --- Basic Block 16 (0x00007FF62DB4112C -> 0x00007FF62DB41161) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3fd5]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3fc1]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3fe4]
    // asm: cmp eax, -1
    if (je_condition) {
        goto loc_7FF62DB411CF;
    } else {
        goto loc_7FF62DB41161;
    }

loc_7FF62DB41161:
    // --- Basic Block 17 (0x00007FF62DB41161 -> 0x00007FF62DB41166) ---
    // asm: dec r14
    goto loc_7FF62DB41127;

loc_7FF62DB41166:
    // --- Basic Block 18 (0x00007FF62DB41166 -> 0x00007FF62DB4116B) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB4116B:
    // --- Basic Block 19 (0x00007FF62DB4116B -> 0x00007FF62DB4118F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3f95]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x4056]
    // asm: cmp rax, r13
    if (jne_condition) {
        goto loc_7FF62DB411CF;
    } else {
        goto loc_7FF62DB4118F;
    }

loc_7FF62DB4118F:
    // --- Basic Block 20 (0x00007FF62DB4118F -> 0x00007FF62DB41190) ---

loc_7FF62DB41190:
    // --- Basic Block 21 (0x00007FF62DB41190 -> 0x00007FF62DB41195) ---
    // asm: test r14, r14
    if (jle_condition) {
        goto loc_7FF62DB411DD;
    } else {
        goto loc_7FF62DB41195;
    }

loc_7FF62DB41195:
    // --- Basic Block 22 (0x00007FF62DB41195 -> 0x00007FF62DB411CA) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3f6c]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3f58]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3f7b]
    // asm: cmp eax, -1
    if (je_condition) {
        goto loc_7FF62DB411CF;
    } else {
        goto loc_7FF62DB411CA;
    }

loc_7FF62DB411CA:
    // --- Basic Block 23 (0x00007FF62DB411CA -> 0x00007FF62DB411CF) ---
    // asm: dec r14
    goto loc_7FF62DB41190;

loc_7FF62DB411CF:
    // --- Basic Block 24 (0x00007FF62DB411CF -> 0x00007FF62DB411DD) ---
    r15d, 4; // mov
    dword ptr [rsp + 0x80], r15d; // mov

loc_7FF62DB411DD:
    // --- Basic Block 25 (0x00007FF62DB411DD -> 0x00007FF62DB411F2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x4021]
    goto loc_7FF62DB41204;

loc_7FF62DB411F2:
    // --- Basic Block 26 (0x00007FF62DB411F2 -> 0x00007FF62DB41204) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r15d, dword ptr [rsp + 0x80]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB41204:
    // --- Basic Block 27 (0x00007FF62DB41204 -> 0x00007FF62DB41224) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r15d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3ee6]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB4122E;
    } else {
        goto loc_7FF62DB41224;
    }

loc_7FF62DB41224:
    // --- Basic Block 28 (0x00007FF62DB41224 -> 0x00007FF62DB4122E) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3f1b]

loc_7FF62DB4122E:
    // --- Basic Block 29 (0x00007FF62DB4122E -> 0x00007FF62DB41244) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ed1]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41251;
    } else {
        goto loc_7FF62DB41244;
    }

loc_7FF62DB41244:
    // --- Basic Block 30 (0x00007FF62DB41244 -> 0x00007FF62DB41251) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41251:
    // --- Basic Block 31 (0x00007FF62DB41251 -> 0x00007FF62DB41264) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF62DB41264:
    // --- Basic Block 32 (0x00007FF62DB41264 -> 0x00007FF62DB41279) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x38
    // asm: test rcx, rcx
    if (jne_condition) {
        goto loc_7FF62DB41280;
    } else {
        goto loc_7FF62DB41279;
    }

loc_7FF62DB41279:
    // --- Basic Block 33 (0x00007FF62DB41279 -> 0x00007FF62DB41280) ---
    eax = 0;
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF62DB41280:
    // --- Basic Block 34 (0x00007FF62DB41280 -> 0x00007FF62DB41289) ---
    // asm: cmp rcx, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB412C7;
    } else {
        goto loc_7FF62DB41289;
    }

loc_7FF62DB41289:
    // --- Basic Block 35 (0x00007FF62DB41289 -> 0x00007FF62DB41292) ---
    rax, [rcx + 0x27]; // lea
    // asm: cmp rax, rcx
    if (jbe_condition) {
        goto loc_7FF62DB412D0;
    } else {
        goto loc_7FF62DB41292;
    }

loc_7FF62DB41292:
    // --- Basic Block 36 (0x00007FF62DB41292 -> 0x00007FF62DB412A2) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB43274(); // 0x7ff62db43274
    rcx, rax; // mov
    // asm: test rax, rax
    if (jne_condition) {
        goto loc_7FF62DB412B6;
    } else {
        goto loc_7FF62DB412A2;
    }

loc_7FF62DB412A2:
    // --- Basic Block 37 (0x00007FF62DB412A2 -> 0x00007FF62DB412B6) ---
    r9d = 0;
    qword ptr [rsp + 0x20], rax; // mov
    r8d = 0;
    edx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x40cb]
    // asm: int3 

loc_7FF62DB412B6:
    // --- Basic Block 38 (0x00007FF62DB412B6 -> 0x00007FF62DB412C7) ---
    // asm: add rax, 0x27
    // asm: and rax, 0xffffffffffffffe0
    qword ptr [rax - 8], rcx; // mov
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF62DB412C7:
    // --- Basic Block 39 (0x00007FF62DB412C7 -> 0x00007FF62DB412D0) ---
    // asm: add rsp, 0x38
    goto loc_7FF62DB43274;

loc_7FF62DB412D0:
    // --- Basic Block 40 (0x00007FF62DB412D0 -> 0x00007FF62DB41311) ---
    rax_result = sub_7FF62DB42000(); // 0x7ff62db42000
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbp; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    // asm: sub rsp, 0x20
    // asm: movabs rbp, 0x7fffffffffffffff
    rdi, r8; // mov
    r14, rdx; // mov
    rsi, rcx; // mov
    // asm: cmp r8, rbp
    if (ja_condition) {
        goto loc_7FF62DB41392;
    } else {
        goto loc_7FF62DB41311;
    }

loc_7FF62DB41311:
    // --- Basic Block 41 (0x00007FF62DB41311 -> 0x00007FF62DB41317) ---
    // asm: cmp r8, 0xf
    if (ja_condition) {
        goto loc_7FF62DB4132E;
    } else {
        goto loc_7FF62DB41317;
    }

loc_7FF62DB41317:
    // --- Basic Block 42 (0x00007FF62DB41317 -> 0x00007FF62DB4132E) ---
    qword ptr [rcx + 0x10], r8; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rdi + rsi], 0; // mov
    goto loc_7FF62DB4137C;

loc_7FF62DB4132E:
    // --- Basic Block 43 (0x00007FF62DB4132E -> 0x00007FF62DB4133F) ---
    rax, rdi; // mov
    qword ptr [rsp + 0x30], rbx; // mov
    // asm: or rax, 0xf
    // asm: cmp rax, rbp
    if (ja_condition) {
        goto loc_7FF62DB4134E;
    } else {
        goto loc_7FF62DB4133F;
    }

loc_7FF62DB4133F:
    // --- Basic Block 44 (0x00007FF62DB4133F -> 0x00007FF62DB4134E) ---
    ecx, 0x16; // mov
    rbp, rax; // mov
    // asm: cmp rax, rcx
    // asm: cmovb rbp, rcx

loc_7FF62DB4134E:
    // --- Basic Block 45 (0x00007FF62DB4134E -> 0x00007FF62DB4137C) ---
    rcx, [rbp + 1]; // lea
    rax_result = sub_7FF62DB41270(); // 0x7ff62db41270
    r8, rdi; // mov
    qword ptr [rsi], rax; // mov
    rdx, r14; // mov
    qword ptr [rsi + 0x10], rdi; // mov
    rcx, rax; // mov
    qword ptr [rsi + 0x18], rbp; // mov
    rbx, rax; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rbx + rdi], 0; // mov
    rbx, qword ptr [rsp + 0x30]; // mov

loc_7FF62DB4137C:
    // --- Basic Block 46 (0x00007FF62DB4137C -> 0x00007FF62DB41392) ---
    rbp, qword ptr [rsp + 0x38]; // mov
    rsi, qword ptr [rsp + 0x40]; // mov
    rdi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41392:
    // --- Basic Block 47 (0x00007FF62DB41392 -> 0x00007FF62DB413E2) ---
    rax_result = sub_7FF62DB420A0(); // 0x7ff62db420a0
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rdx; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    r13, r8; // mov
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r14d, r14d
    dword ptr [rsp + 0x88], r14d; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e3b]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413E2;
    }

loc_7FF62DB413E2:
    // --- Basic Block 48 (0x00007FF62DB413E2 -> 0x00007FF62DB413F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e26]
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413F7;
    }

loc_7FF62DB413F7:
    // --- Basic Block 49 (0x00007FF62DB413F7 -> 0x00007FF62DB4140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e11]
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF62DB41412;

loc_7FF62DB4140F:
    // --- Basic Block 50 (0x00007FF62DB4140F -> 0x00007FF62DB41412) ---
    r15, r14; // mov

loc_7FF62DB41412:
    // --- Basic Block 51 (0x00007FF62DB41412 -> 0x00007FF62DB4142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ce6]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4143C;
    } else {
        goto loc_7FF62DB4142F;
    }

loc_7FF62DB4142F:
    // --- Basic Block 52 (0x00007FF62DB4142F -> 0x00007FF62DB4143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4143C:
    // --- Basic Block 53 (0x00007FF62DB4143C -> 0x00007FF62DB41450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3dec]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41456;
    } else {
        goto loc_7FF62DB41450;
    }

loc_7FF62DB41450:
    // --- Basic Block 54 (0x00007FF62DB41450 -> 0x00007FF62DB41456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB41456:
    // --- Basic Block 55 (0x00007FF62DB41456 -> 0x00007FF62DB4146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x3ca2]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB4146B;
    }

loc_7FF62DB4146B:
    // --- Basic Block 56 (0x00007FF62DB4146B -> 0x00007FF62DB41470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB41470;
    }

loc_7FF62DB41470:
    // --- Basic Block 57 (0x00007FF62DB41470 -> 0x00007FF62DB4148F) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x3cef]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3daf]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB4148F:
    // --- Basic Block 58 (0x00007FF62DB4148F -> 0x00007FF62DB41496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB41496:
    // --- Basic Block 59 (0x00007FF62DB41496 -> 0x00007FF62DB4149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB414A5;
    } else {
        goto loc_7FF62DB4149A;
    }

loc_7FF62DB4149A:
    // --- Basic Block 60 (0x00007FF62DB4149A -> 0x00007FF62DB414A5) ---
    r14d, 4; // mov
    goto loc_7FF62DB415C2;

loc_7FF62DB414A5:
    // --- Basic Block 61 (0x00007FF62DB414A5 -> 0x00007FF62DB414C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x3d7b]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB41578;
    } else {
        goto loc_7FF62DB414C3;
    }

loc_7FF62DB414C3:
    // --- Basic Block 62 (0x00007FF62DB414C3 -> 0x00007FF62DB414CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41573;
    } else {
        goto loc_7FF62DB414CC;
    }

loc_7FF62DB414CC:
    // --- Basic Block 63 (0x00007FF62DB414CC -> 0x00007FF62DB41501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3c35]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3c21]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3c44]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB4156B;
    } else {
        goto loc_7FF62DB41501;
    }

loc_7FF62DB41501:
    // --- Basic Block 64 (0x00007FF62DB41501 -> 0x00007FF62DB41510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41510:
    // --- Basic Block 65 (0x00007FF62DB41510 -> 0x00007FF62DB41515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41556;
    } else {
        goto loc_7FF62DB41515;
    }

loc_7FF62DB41515:
    // --- Basic Block 66 (0x00007FF62DB41515 -> 0x00007FF62DB4154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3bec]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3bd8]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3bfb]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB415A8;
    } else {
        goto loc_7FF62DB4154A;
    }

loc_7FF62DB4154A:
    // --- Basic Block 67 (0x00007FF62DB4154A -> 0x00007FF62DB4154E) ---
    // asm: or r14d, 4

loc_7FF62DB4154E:
    // --- Basic Block 68 (0x00007FF62DB4154E -> 0x00007FF62DB41556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41556:
    // --- Basic Block 69 (0x00007FF62DB41556 -> 0x00007FF62DB4156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x3ca8]
    goto loc_7FF62DB415C2;

loc_7FF62DB4156B:
    // --- Basic Block 70 (0x00007FF62DB4156B -> 0x00007FF62DB41573) ---
    // asm: dec r15
    goto loc_7FF62DB414C3;

loc_7FF62DB41573:
    // --- Basic Block 71 (0x00007FF62DB41573 -> 0x00007FF62DB41578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB41578:
    // --- Basic Block 72 (0x00007FF62DB41578 -> 0x00007FF62DB415A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b88]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x3c49]
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF62DB41510;
    } else {
        goto loc_7FF62DB415A0;
    }

loc_7FF62DB415A0:
    // --- Basic Block 73 (0x00007FF62DB415A0 -> 0x00007FF62DB415A8) ---
    r14d, 4; // mov
    goto loc_7FF62DB4154E;

loc_7FF62DB415A8:
    // --- Basic Block 74 (0x00007FF62DB415A8 -> 0x00007FF62DB415B0) ---
    // asm: dec r15
    goto loc_7FF62DB41510;

loc_7FF62DB415B0:
    // --- Basic Block 75 (0x00007FF62DB415B0 -> 0x00007FF62DB415C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB415C2:
    // --- Basic Block 76 (0x00007FF62DB415C2 -> 0x00007FF62DB415E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3b28]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB415EC;
    } else {
        goto loc_7FF62DB415E2;
    }

loc_7FF62DB415E2:
    // --- Basic Block 77 (0x00007FF62DB415E2 -> 0x00007FF62DB415EC) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3b5d]

loc_7FF62DB415EC:
    // --- Basic Block 78 (0x00007FF62DB415EC -> 0x00007FF62DB41602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b13]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4160F;
    } else {
        goto loc_7FF62DB41602;
    }

loc_7FF62DB41602:
    // --- Basic Block 79 (0x00007FF62DB41602 -> 0x00007FF62DB4160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4160F:
    // --- Basic Block 80 (0x00007FF62DB4160F -> 0x00007FF62DB41622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF62DB41014` (0x7FF62DB41014)
- **Size**: `1550 bytes` | **Complexity V(G)**: `34` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB41014 | Address: 0x00007FF62DB41014
// Size: 1550 bytes | Basic Blocks: 81 | Complexity V(G): 34
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB41014(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB41014:
    // --- Basic Block 0 (0x00007FF62DB41014 -> 0x00007FF62DB4104A) ---
    // asm: sub rsp, 0x30
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r15d, r15d
    dword ptr [rsp + 0x80], r15d; // mov
    rcx, rdx; // mov
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r13, rax; // mov
    r8, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [r8 + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x41d3]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB41077;
    } else {
        goto loc_7FF62DB4104A;
    }

loc_7FF62DB4104A:
    // --- Basic Block 1 (0x00007FF62DB4104A -> 0x00007FF62DB4105F) ---
    rcx, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rcx + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x41be]
    // asm: cmp rax, r13
    if (jle_condition) {
        goto loc_7FF62DB41077;
    } else {
        goto loc_7FF62DB4105F;
    }

loc_7FF62DB4105F:
    // --- Basic Block 2 (0x00007FF62DB4105F -> 0x00007FF62DB41077) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x41a9]
    r14, rax; // mov
    // asm: sub r14, r13
    goto loc_7FF62DB4107A;

loc_7FF62DB41077:
    // --- Basic Block 3 (0x00007FF62DB41077 -> 0x00007FF62DB4107A) ---
    r14, r15; // mov

loc_7FF62DB4107A:
    // --- Basic Block 4 (0x00007FF62DB4107A -> 0x00007FF62DB41097) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x407e]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB410A4;
    } else {
        goto loc_7FF62DB41097;
    }

loc_7FF62DB41097:
    // --- Basic Block 5 (0x00007FF62DB41097 -> 0x00007FF62DB410A4) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB410A4:
    // --- Basic Block 6 (0x00007FF62DB410A4 -> 0x00007FF62DB410B8) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x4184]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB410BE;
    } else {
        goto loc_7FF62DB410B8;
    }

loc_7FF62DB410B8:
    // --- Basic Block 7 (0x00007FF62DB410B8 -> 0x00007FF62DB410BE) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB410FE;

loc_7FF62DB410BE:
    // --- Basic Block 8 (0x00007FF62DB410BE -> 0x00007FF62DB410D3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x403a]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB410F7;
    } else {
        goto loc_7FF62DB410D3;
    }

loc_7FF62DB410D3:
    // --- Basic Block 9 (0x00007FF62DB410D3 -> 0x00007FF62DB410D8) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB410F7;
    } else {
        goto loc_7FF62DB410D8;
    }

loc_7FF62DB410D8:
    // --- Basic Block 10 (0x00007FF62DB410D8 -> 0x00007FF62DB410F7) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x4087]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x4147]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB410FE;

loc_7FF62DB410F7:
    // --- Basic Block 11 (0x00007FF62DB410F7 -> 0x00007FF62DB410FE) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB410FE:
    // --- Basic Block 12 (0x00007FF62DB410FE -> 0x00007FF62DB41102) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB4110D;
    } else {
        goto loc_7FF62DB41102;
    }

loc_7FF62DB41102:
    // --- Basic Block 13 (0x00007FF62DB41102 -> 0x00007FF62DB4110D) ---
    r15d, 4; // mov
    goto loc_7FF62DB41204;

loc_7FF62DB4110D:
    // --- Basic Block 14 (0x00007FF62DB4110D -> 0x00007FF62DB41127) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x4113]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB4116B;
    } else {
        goto loc_7FF62DB41127;
    }

loc_7FF62DB41127:
    // --- Basic Block 15 (0x00007FF62DB41127 -> 0x00007FF62DB4112C) ---
    // asm: test r14, r14
    if (jle_condition) {
        goto loc_7FF62DB41166;
    } else {
        goto loc_7FF62DB4112C;
    }

loc_7FF62DB4112C:
    // --- Basic Block 16 (0x00007FF62DB4112C -> 0x00007FF62DB41161) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3fd5]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3fc1]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3fe4]
    // asm: cmp eax, -1
    if (je_condition) {
        goto loc_7FF62DB411CF;
    } else {
        goto loc_7FF62DB41161;
    }

loc_7FF62DB41161:
    // --- Basic Block 17 (0x00007FF62DB41161 -> 0x00007FF62DB41166) ---
    // asm: dec r14
    goto loc_7FF62DB41127;

loc_7FF62DB41166:
    // --- Basic Block 18 (0x00007FF62DB41166 -> 0x00007FF62DB4116B) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB4116B:
    // --- Basic Block 19 (0x00007FF62DB4116B -> 0x00007FF62DB4118F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3f95]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x4056]
    // asm: cmp rax, r13
    if (jne_condition) {
        goto loc_7FF62DB411CF;
    } else {
        goto loc_7FF62DB4118F;
    }

loc_7FF62DB4118F:
    // --- Basic Block 20 (0x00007FF62DB4118F -> 0x00007FF62DB41190) ---

loc_7FF62DB41190:
    // --- Basic Block 21 (0x00007FF62DB41190 -> 0x00007FF62DB41195) ---
    // asm: test r14, r14
    if (jle_condition) {
        goto loc_7FF62DB411DD;
    } else {
        goto loc_7FF62DB41195;
    }

loc_7FF62DB41195:
    // --- Basic Block 22 (0x00007FF62DB41195 -> 0x00007FF62DB411CA) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3f6c]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3f58]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3f7b]
    // asm: cmp eax, -1
    if (je_condition) {
        goto loc_7FF62DB411CF;
    } else {
        goto loc_7FF62DB411CA;
    }

loc_7FF62DB411CA:
    // --- Basic Block 23 (0x00007FF62DB411CA -> 0x00007FF62DB411CF) ---
    // asm: dec r14
    goto loc_7FF62DB41190;

loc_7FF62DB411CF:
    // --- Basic Block 24 (0x00007FF62DB411CF -> 0x00007FF62DB411DD) ---
    r15d, 4; // mov
    dword ptr [rsp + 0x80], r15d; // mov

loc_7FF62DB411DD:
    // --- Basic Block 25 (0x00007FF62DB411DD -> 0x00007FF62DB411F2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x4021]
    goto loc_7FF62DB41204;

loc_7FF62DB411F2:
    // --- Basic Block 26 (0x00007FF62DB411F2 -> 0x00007FF62DB41204) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r15d, dword ptr [rsp + 0x80]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB41204:
    // --- Basic Block 27 (0x00007FF62DB41204 -> 0x00007FF62DB41224) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r15d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3ee6]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB4122E;
    } else {
        goto loc_7FF62DB41224;
    }

loc_7FF62DB41224:
    // --- Basic Block 28 (0x00007FF62DB41224 -> 0x00007FF62DB4122E) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3f1b]

loc_7FF62DB4122E:
    // --- Basic Block 29 (0x00007FF62DB4122E -> 0x00007FF62DB41244) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ed1]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41251;
    } else {
        goto loc_7FF62DB41244;
    }

loc_7FF62DB41244:
    // --- Basic Block 30 (0x00007FF62DB41244 -> 0x00007FF62DB41251) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41251:
    // --- Basic Block 31 (0x00007FF62DB41251 -> 0x00007FF62DB41264) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF62DB41264:
    // --- Basic Block 32 (0x00007FF62DB41264 -> 0x00007FF62DB41279) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x38
    // asm: test rcx, rcx
    if (jne_condition) {
        goto loc_7FF62DB41280;
    } else {
        goto loc_7FF62DB41279;
    }

loc_7FF62DB41279:
    // --- Basic Block 33 (0x00007FF62DB41279 -> 0x00007FF62DB41280) ---
    eax = 0;
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF62DB41280:
    // --- Basic Block 34 (0x00007FF62DB41280 -> 0x00007FF62DB41289) ---
    // asm: cmp rcx, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB412C7;
    } else {
        goto loc_7FF62DB41289;
    }

loc_7FF62DB41289:
    // --- Basic Block 35 (0x00007FF62DB41289 -> 0x00007FF62DB41292) ---
    rax, [rcx + 0x27]; // lea
    // asm: cmp rax, rcx
    if (jbe_condition) {
        goto loc_7FF62DB412D0;
    } else {
        goto loc_7FF62DB41292;
    }

loc_7FF62DB41292:
    // --- Basic Block 36 (0x00007FF62DB41292 -> 0x00007FF62DB412A2) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB43274(); // 0x7ff62db43274
    rcx, rax; // mov
    // asm: test rax, rax
    if (jne_condition) {
        goto loc_7FF62DB412B6;
    } else {
        goto loc_7FF62DB412A2;
    }

loc_7FF62DB412A2:
    // --- Basic Block 37 (0x00007FF62DB412A2 -> 0x00007FF62DB412B6) ---
    r9d = 0;
    qword ptr [rsp + 0x20], rax; // mov
    r8d = 0;
    edx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x40cb]
    // asm: int3 

loc_7FF62DB412B6:
    // --- Basic Block 38 (0x00007FF62DB412B6 -> 0x00007FF62DB412C7) ---
    // asm: add rax, 0x27
    // asm: and rax, 0xffffffffffffffe0
    qword ptr [rax - 8], rcx; // mov
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF62DB412C7:
    // --- Basic Block 39 (0x00007FF62DB412C7 -> 0x00007FF62DB412D0) ---
    // asm: add rsp, 0x38
    goto loc_7FF62DB43274;

loc_7FF62DB412D0:
    // --- Basic Block 40 (0x00007FF62DB412D0 -> 0x00007FF62DB41311) ---
    rax_result = sub_7FF62DB42000(); // 0x7ff62db42000
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbp; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    // asm: sub rsp, 0x20
    // asm: movabs rbp, 0x7fffffffffffffff
    rdi, r8; // mov
    r14, rdx; // mov
    rsi, rcx; // mov
    // asm: cmp r8, rbp
    if (ja_condition) {
        goto loc_7FF62DB41392;
    } else {
        goto loc_7FF62DB41311;
    }

loc_7FF62DB41311:
    // --- Basic Block 41 (0x00007FF62DB41311 -> 0x00007FF62DB41317) ---
    // asm: cmp r8, 0xf
    if (ja_condition) {
        goto loc_7FF62DB4132E;
    } else {
        goto loc_7FF62DB41317;
    }

loc_7FF62DB41317:
    // --- Basic Block 42 (0x00007FF62DB41317 -> 0x00007FF62DB4132E) ---
    qword ptr [rcx + 0x10], r8; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rdi + rsi], 0; // mov
    goto loc_7FF62DB4137C;

loc_7FF62DB4132E:
    // --- Basic Block 43 (0x00007FF62DB4132E -> 0x00007FF62DB4133F) ---
    rax, rdi; // mov
    qword ptr [rsp + 0x30], rbx; // mov
    // asm: or rax, 0xf
    // asm: cmp rax, rbp
    if (ja_condition) {
        goto loc_7FF62DB4134E;
    } else {
        goto loc_7FF62DB4133F;
    }

loc_7FF62DB4133F:
    // --- Basic Block 44 (0x00007FF62DB4133F -> 0x00007FF62DB4134E) ---
    ecx, 0x16; // mov
    rbp, rax; // mov
    // asm: cmp rax, rcx
    // asm: cmovb rbp, rcx

loc_7FF62DB4134E:
    // --- Basic Block 45 (0x00007FF62DB4134E -> 0x00007FF62DB4137C) ---
    rcx, [rbp + 1]; // lea
    rax_result = sub_7FF62DB41270(); // 0x7ff62db41270
    r8, rdi; // mov
    qword ptr [rsi], rax; // mov
    rdx, r14; // mov
    qword ptr [rsi + 0x10], rdi; // mov
    rcx, rax; // mov
    qword ptr [rsi + 0x18], rbp; // mov
    rbx, rax; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rbx + rdi], 0; // mov
    rbx, qword ptr [rsp + 0x30]; // mov

loc_7FF62DB4137C:
    // --- Basic Block 46 (0x00007FF62DB4137C -> 0x00007FF62DB41392) ---
    rbp, qword ptr [rsp + 0x38]; // mov
    rsi, qword ptr [rsp + 0x40]; // mov
    rdi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41392:
    // --- Basic Block 47 (0x00007FF62DB41392 -> 0x00007FF62DB413E2) ---
    rax_result = sub_7FF62DB420A0(); // 0x7ff62db420a0
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rdx; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    r13, r8; // mov
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r14d, r14d
    dword ptr [rsp + 0x88], r14d; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e3b]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413E2;
    }

loc_7FF62DB413E2:
    // --- Basic Block 48 (0x00007FF62DB413E2 -> 0x00007FF62DB413F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e26]
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413F7;
    }

loc_7FF62DB413F7:
    // --- Basic Block 49 (0x00007FF62DB413F7 -> 0x00007FF62DB4140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e11]
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF62DB41412;

loc_7FF62DB4140F:
    // --- Basic Block 50 (0x00007FF62DB4140F -> 0x00007FF62DB41412) ---
    r15, r14; // mov

loc_7FF62DB41412:
    // --- Basic Block 51 (0x00007FF62DB41412 -> 0x00007FF62DB4142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ce6]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4143C;
    } else {
        goto loc_7FF62DB4142F;
    }

loc_7FF62DB4142F:
    // --- Basic Block 52 (0x00007FF62DB4142F -> 0x00007FF62DB4143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4143C:
    // --- Basic Block 53 (0x00007FF62DB4143C -> 0x00007FF62DB41450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3dec]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41456;
    } else {
        goto loc_7FF62DB41450;
    }

loc_7FF62DB41450:
    // --- Basic Block 54 (0x00007FF62DB41450 -> 0x00007FF62DB41456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB41456:
    // --- Basic Block 55 (0x00007FF62DB41456 -> 0x00007FF62DB4146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x3ca2]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB4146B;
    }

loc_7FF62DB4146B:
    // --- Basic Block 56 (0x00007FF62DB4146B -> 0x00007FF62DB41470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB41470;
    }

loc_7FF62DB41470:
    // --- Basic Block 57 (0x00007FF62DB41470 -> 0x00007FF62DB4148F) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x3cef]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3daf]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB4148F:
    // --- Basic Block 58 (0x00007FF62DB4148F -> 0x00007FF62DB41496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB41496:
    // --- Basic Block 59 (0x00007FF62DB41496 -> 0x00007FF62DB4149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB414A5;
    } else {
        goto loc_7FF62DB4149A;
    }

loc_7FF62DB4149A:
    // --- Basic Block 60 (0x00007FF62DB4149A -> 0x00007FF62DB414A5) ---
    r14d, 4; // mov
    goto loc_7FF62DB415C2;

loc_7FF62DB414A5:
    // --- Basic Block 61 (0x00007FF62DB414A5 -> 0x00007FF62DB414C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x3d7b]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB41578;
    } else {
        goto loc_7FF62DB414C3;
    }

loc_7FF62DB414C3:
    // --- Basic Block 62 (0x00007FF62DB414C3 -> 0x00007FF62DB414CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41573;
    } else {
        goto loc_7FF62DB414CC;
    }

loc_7FF62DB414CC:
    // --- Basic Block 63 (0x00007FF62DB414CC -> 0x00007FF62DB41501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3c35]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3c21]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3c44]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB4156B;
    } else {
        goto loc_7FF62DB41501;
    }

loc_7FF62DB41501:
    // --- Basic Block 64 (0x00007FF62DB41501 -> 0x00007FF62DB41510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41510:
    // --- Basic Block 65 (0x00007FF62DB41510 -> 0x00007FF62DB41515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41556;
    } else {
        goto loc_7FF62DB41515;
    }

loc_7FF62DB41515:
    // --- Basic Block 66 (0x00007FF62DB41515 -> 0x00007FF62DB4154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3bec]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3bd8]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3bfb]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB415A8;
    } else {
        goto loc_7FF62DB4154A;
    }

loc_7FF62DB4154A:
    // --- Basic Block 67 (0x00007FF62DB4154A -> 0x00007FF62DB4154E) ---
    // asm: or r14d, 4

loc_7FF62DB4154E:
    // --- Basic Block 68 (0x00007FF62DB4154E -> 0x00007FF62DB41556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41556:
    // --- Basic Block 69 (0x00007FF62DB41556 -> 0x00007FF62DB4156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x3ca8]
    goto loc_7FF62DB415C2;

loc_7FF62DB4156B:
    // --- Basic Block 70 (0x00007FF62DB4156B -> 0x00007FF62DB41573) ---
    // asm: dec r15
    goto loc_7FF62DB414C3;

loc_7FF62DB41573:
    // --- Basic Block 71 (0x00007FF62DB41573 -> 0x00007FF62DB41578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB41578:
    // --- Basic Block 72 (0x00007FF62DB41578 -> 0x00007FF62DB415A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b88]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x3c49]
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF62DB41510;
    } else {
        goto loc_7FF62DB415A0;
    }

loc_7FF62DB415A0:
    // --- Basic Block 73 (0x00007FF62DB415A0 -> 0x00007FF62DB415A8) ---
    r14d, 4; // mov
    goto loc_7FF62DB4154E;

loc_7FF62DB415A8:
    // --- Basic Block 74 (0x00007FF62DB415A8 -> 0x00007FF62DB415B0) ---
    // asm: dec r15
    goto loc_7FF62DB41510;

loc_7FF62DB415B0:
    // --- Basic Block 75 (0x00007FF62DB415B0 -> 0x00007FF62DB415C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB415C2:
    // --- Basic Block 76 (0x00007FF62DB415C2 -> 0x00007FF62DB415E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3b28]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB415EC;
    } else {
        goto loc_7FF62DB415E2;
    }

loc_7FF62DB415E2:
    // --- Basic Block 77 (0x00007FF62DB415E2 -> 0x00007FF62DB415EC) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3b5d]

loc_7FF62DB415EC:
    // --- Basic Block 78 (0x00007FF62DB415EC -> 0x00007FF62DB41602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b13]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4160F;
    } else {
        goto loc_7FF62DB41602;
    }

loc_7FF62DB41602:
    // --- Basic Block 79 (0x00007FF62DB41602 -> 0x00007FF62DB4160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4160F:
    // --- Basic Block 80 (0x00007FF62DB4160F -> 0x00007FF62DB41622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF62DB41270` (0x7FF62DB41270)
- **Size**: `1602 bytes` | **Complexity V(G)**: `23` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB41270 | Address: 0x00007FF62DB41270
// Size: 1602 bytes | Basic Blocks: 74 | Complexity V(G): 23
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB41270(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB41270:
    // --- Basic Block 0 (0x00007FF62DB41270 -> 0x00007FF62DB41279) ---
    // asm: sub rsp, 0x38
    // asm: test rcx, rcx
    if (jne_condition) {
        goto loc_7FF62DB41280;
    } else {
        goto loc_7FF62DB41279;
    }

loc_7FF62DB41279:
    // --- Basic Block 1 (0x00007FF62DB41279 -> 0x00007FF62DB41280) ---
    eax = 0;
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF62DB41280:
    // --- Basic Block 2 (0x00007FF62DB41280 -> 0x00007FF62DB41289) ---
    // asm: cmp rcx, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB412C7;
    } else {
        goto loc_7FF62DB41289;
    }

loc_7FF62DB41289:
    // --- Basic Block 3 (0x00007FF62DB41289 -> 0x00007FF62DB41292) ---
    rax, [rcx + 0x27]; // lea
    // asm: cmp rax, rcx
    if (jbe_condition) {
        goto loc_7FF62DB412D0;
    } else {
        goto loc_7FF62DB41292;
    }

loc_7FF62DB41292:
    // --- Basic Block 4 (0x00007FF62DB41292 -> 0x00007FF62DB412A2) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB43274(); // 0x7ff62db43274
    rcx, rax; // mov
    // asm: test rax, rax
    if (jne_condition) {
        goto loc_7FF62DB412B6;
    } else {
        goto loc_7FF62DB412A2;
    }

loc_7FF62DB412A2:
    // --- Basic Block 5 (0x00007FF62DB412A2 -> 0x00007FF62DB412B6) ---
    r9d = 0;
    qword ptr [rsp + 0x20], rax; // mov
    r8d = 0;
    edx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x40cb]
    // asm: int3 

loc_7FF62DB412B6:
    // --- Basic Block 6 (0x00007FF62DB412B6 -> 0x00007FF62DB412C7) ---
    // asm: add rax, 0x27
    // asm: and rax, 0xffffffffffffffe0
    qword ptr [rax - 8], rcx; // mov
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF62DB412C7:
    // --- Basic Block 7 (0x00007FF62DB412C7 -> 0x00007FF62DB412D0) ---
    // asm: add rsp, 0x38
    goto loc_7FF62DB43274;

loc_7FF62DB412D0:
    // --- Basic Block 8 (0x00007FF62DB412D0 -> 0x00007FF62DB41311) ---
    rax_result = sub_7FF62DB42000(); // 0x7ff62db42000
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbp; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    // asm: sub rsp, 0x20
    // asm: movabs rbp, 0x7fffffffffffffff
    rdi, r8; // mov
    r14, rdx; // mov
    rsi, rcx; // mov
    // asm: cmp r8, rbp
    if (ja_condition) {
        goto loc_7FF62DB41392;
    } else {
        goto loc_7FF62DB41311;
    }

loc_7FF62DB41311:
    // --- Basic Block 9 (0x00007FF62DB41311 -> 0x00007FF62DB41317) ---
    // asm: cmp r8, 0xf
    if (ja_condition) {
        goto loc_7FF62DB4132E;
    } else {
        goto loc_7FF62DB41317;
    }

loc_7FF62DB41317:
    // --- Basic Block 10 (0x00007FF62DB41317 -> 0x00007FF62DB4132E) ---
    qword ptr [rcx + 0x10], r8; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rdi + rsi], 0; // mov
    goto loc_7FF62DB4137C;

loc_7FF62DB4132E:
    // --- Basic Block 11 (0x00007FF62DB4132E -> 0x00007FF62DB4133F) ---
    rax, rdi; // mov
    qword ptr [rsp + 0x30], rbx; // mov
    // asm: or rax, 0xf
    // asm: cmp rax, rbp
    if (ja_condition) {
        goto loc_7FF62DB4134E;
    } else {
        goto loc_7FF62DB4133F;
    }

loc_7FF62DB4133F:
    // --- Basic Block 12 (0x00007FF62DB4133F -> 0x00007FF62DB4134E) ---
    ecx, 0x16; // mov
    rbp, rax; // mov
    // asm: cmp rax, rcx
    // asm: cmovb rbp, rcx

loc_7FF62DB4134E:
    // --- Basic Block 13 (0x00007FF62DB4134E -> 0x00007FF62DB4137C) ---
    rcx, [rbp + 1]; // lea
    rax_result = sub_7FF62DB41270(); // 0x7ff62db41270
    r8, rdi; // mov
    qword ptr [rsi], rax; // mov
    rdx, r14; // mov
    qword ptr [rsi + 0x10], rdi; // mov
    rcx, rax; // mov
    qword ptr [rsi + 0x18], rbp; // mov
    rbx, rax; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rbx + rdi], 0; // mov
    rbx, qword ptr [rsp + 0x30]; // mov

loc_7FF62DB4137C:
    // --- Basic Block 14 (0x00007FF62DB4137C -> 0x00007FF62DB41392) ---
    rbp, qword ptr [rsp + 0x38]; // mov
    rsi, qword ptr [rsp + 0x40]; // mov
    rdi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41392:
    // --- Basic Block 15 (0x00007FF62DB41392 -> 0x00007FF62DB413E2) ---
    rax_result = sub_7FF62DB420A0(); // 0x7ff62db420a0
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rdx; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    r13, r8; // mov
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r14d, r14d
    dword ptr [rsp + 0x88], r14d; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e3b]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413E2;
    }

loc_7FF62DB413E2:
    // --- Basic Block 16 (0x00007FF62DB413E2 -> 0x00007FF62DB413F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e26]
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413F7;
    }

loc_7FF62DB413F7:
    // --- Basic Block 17 (0x00007FF62DB413F7 -> 0x00007FF62DB4140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e11]
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF62DB41412;

loc_7FF62DB4140F:
    // --- Basic Block 18 (0x00007FF62DB4140F -> 0x00007FF62DB41412) ---
    r15, r14; // mov

loc_7FF62DB41412:
    // --- Basic Block 19 (0x00007FF62DB41412 -> 0x00007FF62DB4142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ce6]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4143C;
    } else {
        goto loc_7FF62DB4142F;
    }

loc_7FF62DB4142F:
    // --- Basic Block 20 (0x00007FF62DB4142F -> 0x00007FF62DB4143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4143C:
    // --- Basic Block 21 (0x00007FF62DB4143C -> 0x00007FF62DB41450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3dec]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41456;
    } else {
        goto loc_7FF62DB41450;
    }

loc_7FF62DB41450:
    // --- Basic Block 22 (0x00007FF62DB41450 -> 0x00007FF62DB41456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB41456:
    // --- Basic Block 23 (0x00007FF62DB41456 -> 0x00007FF62DB4146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x3ca2]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB4146B;
    }

loc_7FF62DB4146B:
    // --- Basic Block 24 (0x00007FF62DB4146B -> 0x00007FF62DB41470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB41470;
    }

loc_7FF62DB41470:
    // --- Basic Block 25 (0x00007FF62DB41470 -> 0x00007FF62DB4148F) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x3cef]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3daf]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB4148F:
    // --- Basic Block 26 (0x00007FF62DB4148F -> 0x00007FF62DB41496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB41496:
    // --- Basic Block 27 (0x00007FF62DB41496 -> 0x00007FF62DB4149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB414A5;
    } else {
        goto loc_7FF62DB4149A;
    }

loc_7FF62DB4149A:
    // --- Basic Block 28 (0x00007FF62DB4149A -> 0x00007FF62DB414A5) ---
    r14d, 4; // mov
    goto loc_7FF62DB415C2;

loc_7FF62DB414A5:
    // --- Basic Block 29 (0x00007FF62DB414A5 -> 0x00007FF62DB414C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x3d7b]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB41578;
    } else {
        goto loc_7FF62DB414C3;
    }

loc_7FF62DB414C3:
    // --- Basic Block 30 (0x00007FF62DB414C3 -> 0x00007FF62DB414CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41573;
    } else {
        goto loc_7FF62DB414CC;
    }

loc_7FF62DB414CC:
    // --- Basic Block 31 (0x00007FF62DB414CC -> 0x00007FF62DB41501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3c35]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3c21]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3c44]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB4156B;
    } else {
        goto loc_7FF62DB41501;
    }

loc_7FF62DB41501:
    // --- Basic Block 32 (0x00007FF62DB41501 -> 0x00007FF62DB41510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41510:
    // --- Basic Block 33 (0x00007FF62DB41510 -> 0x00007FF62DB41515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41556;
    } else {
        goto loc_7FF62DB41515;
    }

loc_7FF62DB41515:
    // --- Basic Block 34 (0x00007FF62DB41515 -> 0x00007FF62DB4154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3bec]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3bd8]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3bfb]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB415A8;
    } else {
        goto loc_7FF62DB4154A;
    }

loc_7FF62DB4154A:
    // --- Basic Block 35 (0x00007FF62DB4154A -> 0x00007FF62DB4154E) ---
    // asm: or r14d, 4

loc_7FF62DB4154E:
    // --- Basic Block 36 (0x00007FF62DB4154E -> 0x00007FF62DB41556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41556:
    // --- Basic Block 37 (0x00007FF62DB41556 -> 0x00007FF62DB4156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x3ca8]
    goto loc_7FF62DB415C2;

loc_7FF62DB4156B:
    // --- Basic Block 38 (0x00007FF62DB4156B -> 0x00007FF62DB41573) ---
    // asm: dec r15
    goto loc_7FF62DB414C3;

loc_7FF62DB41573:
    // --- Basic Block 39 (0x00007FF62DB41573 -> 0x00007FF62DB41578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB41578:
    // --- Basic Block 40 (0x00007FF62DB41578 -> 0x00007FF62DB415A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b88]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x3c49]
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF62DB41510;
    } else {
        goto loc_7FF62DB415A0;
    }

loc_7FF62DB415A0:
    // --- Basic Block 41 (0x00007FF62DB415A0 -> 0x00007FF62DB415A8) ---
    r14d, 4; // mov
    goto loc_7FF62DB4154E;

loc_7FF62DB415A8:
    // --- Basic Block 42 (0x00007FF62DB415A8 -> 0x00007FF62DB415B0) ---
    // asm: dec r15
    goto loc_7FF62DB41510;

loc_7FF62DB415B0:
    // --- Basic Block 43 (0x00007FF62DB415B0 -> 0x00007FF62DB415C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB415C2:
    // --- Basic Block 44 (0x00007FF62DB415C2 -> 0x00007FF62DB415E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3b28]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB415EC;
    } else {
        goto loc_7FF62DB415E2;
    }

loc_7FF62DB415E2:
    // --- Basic Block 45 (0x00007FF62DB415E2 -> 0x00007FF62DB415EC) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3b5d]

loc_7FF62DB415EC:
    // --- Basic Block 46 (0x00007FF62DB415EC -> 0x00007FF62DB41602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b13]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4160F;
    } else {
        goto loc_7FF62DB41602;
    }

loc_7FF62DB41602:
    // --- Basic Block 47 (0x00007FF62DB41602 -> 0x00007FF62DB4160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4160F:
    // --- Basic Block 48 (0x00007FF62DB4160F -> 0x00007FF62DB41622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF62DB41622:
    // --- Basic Block 49 (0x00007FF62DB41622 -> 0x00007FF62DB41684) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbx; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x40
    // asm: movzx r15d, r8b
    r14, rdx; // mov
    rdi, rcx; // mov
    ebx = 0;
    dword ptr [rsp + 0x20], ebx; // mov
    sil = 0;
    byte ptr [rsp + 0x88], sil; // mov
    r12, rcx; // mov
    qword ptr [rsp + 0x28], rcx; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a91]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41691;
    } else {
        goto loc_7FF62DB41684;
    }

loc_7FF62DB41684:
    // --- Basic Block 50 (0x00007FF62DB41684 -> 0x00007FF62DB41691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41691:
    // --- Basic Block 51 (0x00007FF62DB41691 -> 0x00007FF62DB416A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB45170(); // qword ptr [rip + 0x3ad4]
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF62DB41774;
    } else {
        goto loc_7FF62DB416A8;
    }

loc_7FF62DB416A8:
    // --- Basic Block 52 (0x00007FF62DB416A8 -> 0x00007FF62DB416B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB416B9;
    } else {
        goto loc_7FF62DB416B6;
    }

loc_7FF62DB416B6:
    // --- Basic Block 53 (0x00007FF62DB416B6 -> 0x00007FF62DB416B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF62DB416B9:
    // --- Basic Block 54 (0x00007FF62DB416B9 -> 0x00007FF62DB416E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a44]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F0(); // qword ptr [rip + 0x3b1b]
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF62DB416E0:
    // --- Basic Block 55 (0x00007FF62DB416E0 -> 0x00007FF62DB416E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB416EC;
    } else {
        goto loc_7FF62DB416E5;
    }

loc_7FF62DB416E5:
    // --- Basic Block 56 (0x00007FF62DB416E5 -> 0x00007FF62DB416EC) ---
    ebx, 1; // mov
    goto loc_7FF62DB41722;

loc_7FF62DB416EC:
    // --- Basic Block 57 (0x00007FF62DB416EC -> 0x00007FF62DB416F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF62DB41717;
    } else {
        goto loc_7FF62DB416F1;
    }

loc_7FF62DB416F1:
    // --- Basic Block 58 (0x00007FF62DB416F1 -> 0x00007FF62DB41717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a04]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F8(); // qword ptr [rip + 0x3ae3]
    goto loc_7FF62DB41726;

loc_7FF62DB41717:
    // --- Basic Block 59 (0x00007FF62DB41717 -> 0x00007FF62DB4171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF62DB41728;
    } else {
        goto loc_7FF62DB4171D;
    }

loc_7FF62DB4171D:
    // --- Basic Block 60 (0x00007FF62DB4171D -> 0x00007FF62DB41722) ---
    ebx, 2; // mov

loc_7FF62DB41722:
    // --- Basic Block 61 (0x00007FF62DB41722 -> 0x00007FF62DB41726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF62DB41726:
    // --- Basic Block 62 (0x00007FF62DB41726 -> 0x00007FF62DB41728) ---
    goto loc_7FF62DB4176F;

loc_7FF62DB41728:
    // --- Basic Block 63 (0x00007FF62DB41728 -> 0x00007FF62DB41759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF62DB424C0(); // 0x7ff62db424c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x39c2]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451E8(); // qword ptr [rip + 0x3a91]
    goto loc_7FF62DB416E0;

loc_7FF62DB41759:
    // --- Basic Block 64 (0x00007FF62DB41759 -> 0x00007FF62DB4176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF62DB4176F:
    // --- Basic Block 65 (0x00007FF62DB4176F -> 0x00007FF62DB41774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF62DB41777;
    } else {
        goto loc_7FF62DB41774;
    }

loc_7FF62DB41774:
    // --- Basic Block 66 (0x00007FF62DB41774 -> 0x00007FF62DB41777) ---
    // asm: or ebx, 2

loc_7FF62DB41777:
    // --- Basic Block 67 (0x00007FF62DB41777 -> 0x00007FF62DB417A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3974]
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3972]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB417B0;
    } else {
        goto loc_7FF62DB417A3;
    }

loc_7FF62DB417A3:
    // --- Basic Block 68 (0x00007FF62DB417A3 -> 0x00007FF62DB417B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB417B0:
    // --- Basic Block 69 (0x00007FF62DB417B0 -> 0x00007FF62DB417CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF62DB417CE:
    // --- Basic Block 70 (0x00007FF62DB417CE -> 0x00007FF62DB4180C) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4180C:
    // --- Basic Block 71 (0x00007FF62DB4180C -> 0x00007FF62DB4184C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 72 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 73 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF62DB412E0` (0x7FF62DB412E0)
- **Size**: `1490 bytes` | **Complexity V(G)**: `21` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB412E0 | Address: 0x00007FF62DB412E0
// Size: 1490 bytes | Basic Blocks: 66 | Complexity V(G): 21
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB412E0(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB412E0:
    // --- Basic Block 0 (0x00007FF62DB412E0 -> 0x00007FF62DB41311) ---
    qword ptr [rsp + 0x10], rbp; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    // asm: sub rsp, 0x20
    // asm: movabs rbp, 0x7fffffffffffffff
    rdi, r8; // mov
    r14, rdx; // mov
    rsi, rcx; // mov
    // asm: cmp r8, rbp
    if (ja_condition) {
        goto loc_7FF62DB41392;
    } else {
        goto loc_7FF62DB41311;
    }

loc_7FF62DB41311:
    // --- Basic Block 1 (0x00007FF62DB41311 -> 0x00007FF62DB41317) ---
    // asm: cmp r8, 0xf
    if (ja_condition) {
        goto loc_7FF62DB4132E;
    } else {
        goto loc_7FF62DB41317;
    }

loc_7FF62DB41317:
    // --- Basic Block 2 (0x00007FF62DB41317 -> 0x00007FF62DB4132E) ---
    qword ptr [rcx + 0x10], r8; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rdi + rsi], 0; // mov
    goto loc_7FF62DB4137C;

loc_7FF62DB4132E:
    // --- Basic Block 3 (0x00007FF62DB4132E -> 0x00007FF62DB4133F) ---
    rax, rdi; // mov
    qword ptr [rsp + 0x30], rbx; // mov
    // asm: or rax, 0xf
    // asm: cmp rax, rbp
    if (ja_condition) {
        goto loc_7FF62DB4134E;
    } else {
        goto loc_7FF62DB4133F;
    }

loc_7FF62DB4133F:
    // --- Basic Block 4 (0x00007FF62DB4133F -> 0x00007FF62DB4134E) ---
    ecx, 0x16; // mov
    rbp, rax; // mov
    // asm: cmp rax, rcx
    // asm: cmovb rbp, rcx

loc_7FF62DB4134E:
    // --- Basic Block 5 (0x00007FF62DB4134E -> 0x00007FF62DB4137C) ---
    rcx, [rbp + 1]; // lea
    rax_result = sub_7FF62DB41270(); // 0x7ff62db41270
    r8, rdi; // mov
    qword ptr [rsi], rax; // mov
    rdx, r14; // mov
    qword ptr [rsi + 0x10], rdi; // mov
    rcx, rax; // mov
    qword ptr [rsi + 0x18], rbp; // mov
    rbx, rax; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rbx + rdi], 0; // mov
    rbx, qword ptr [rsp + 0x30]; // mov

loc_7FF62DB4137C:
    // --- Basic Block 6 (0x00007FF62DB4137C -> 0x00007FF62DB41392) ---
    rbp, qword ptr [rsp + 0x38]; // mov
    rsi, qword ptr [rsp + 0x40]; // mov
    rdi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41392:
    // --- Basic Block 7 (0x00007FF62DB41392 -> 0x00007FF62DB413E2) ---
    rax_result = sub_7FF62DB420A0(); // 0x7ff62db420a0
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rdx; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    r13, r8; // mov
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r14d, r14d
    dword ptr [rsp + 0x88], r14d; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e3b]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413E2;
    }

loc_7FF62DB413E2:
    // --- Basic Block 8 (0x00007FF62DB413E2 -> 0x00007FF62DB413F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e26]
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413F7;
    }

loc_7FF62DB413F7:
    // --- Basic Block 9 (0x00007FF62DB413F7 -> 0x00007FF62DB4140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e11]
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF62DB41412;

loc_7FF62DB4140F:
    // --- Basic Block 10 (0x00007FF62DB4140F -> 0x00007FF62DB41412) ---
    r15, r14; // mov

loc_7FF62DB41412:
    // --- Basic Block 11 (0x00007FF62DB41412 -> 0x00007FF62DB4142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ce6]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4143C;
    } else {
        goto loc_7FF62DB4142F;
    }

loc_7FF62DB4142F:
    // --- Basic Block 12 (0x00007FF62DB4142F -> 0x00007FF62DB4143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4143C:
    // --- Basic Block 13 (0x00007FF62DB4143C -> 0x00007FF62DB41450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3dec]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41456;
    } else {
        goto loc_7FF62DB41450;
    }

loc_7FF62DB41450:
    // --- Basic Block 14 (0x00007FF62DB41450 -> 0x00007FF62DB41456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB41456:
    // --- Basic Block 15 (0x00007FF62DB41456 -> 0x00007FF62DB4146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x3ca2]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB4146B;
    }

loc_7FF62DB4146B:
    // --- Basic Block 16 (0x00007FF62DB4146B -> 0x00007FF62DB41470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB41470;
    }

loc_7FF62DB41470:
    // --- Basic Block 17 (0x00007FF62DB41470 -> 0x00007FF62DB4148F) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x3cef]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3daf]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB4148F:
    // --- Basic Block 18 (0x00007FF62DB4148F -> 0x00007FF62DB41496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB41496:
    // --- Basic Block 19 (0x00007FF62DB41496 -> 0x00007FF62DB4149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB414A5;
    } else {
        goto loc_7FF62DB4149A;
    }

loc_7FF62DB4149A:
    // --- Basic Block 20 (0x00007FF62DB4149A -> 0x00007FF62DB414A5) ---
    r14d, 4; // mov
    goto loc_7FF62DB415C2;

loc_7FF62DB414A5:
    // --- Basic Block 21 (0x00007FF62DB414A5 -> 0x00007FF62DB414C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x3d7b]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB41578;
    } else {
        goto loc_7FF62DB414C3;
    }

loc_7FF62DB414C3:
    // --- Basic Block 22 (0x00007FF62DB414C3 -> 0x00007FF62DB414CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41573;
    } else {
        goto loc_7FF62DB414CC;
    }

loc_7FF62DB414CC:
    // --- Basic Block 23 (0x00007FF62DB414CC -> 0x00007FF62DB41501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3c35]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3c21]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3c44]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB4156B;
    } else {
        goto loc_7FF62DB41501;
    }

loc_7FF62DB41501:
    // --- Basic Block 24 (0x00007FF62DB41501 -> 0x00007FF62DB41510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41510:
    // --- Basic Block 25 (0x00007FF62DB41510 -> 0x00007FF62DB41515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41556;
    } else {
        goto loc_7FF62DB41515;
    }

loc_7FF62DB41515:
    // --- Basic Block 26 (0x00007FF62DB41515 -> 0x00007FF62DB4154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3bec]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3bd8]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3bfb]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB415A8;
    } else {
        goto loc_7FF62DB4154A;
    }

loc_7FF62DB4154A:
    // --- Basic Block 27 (0x00007FF62DB4154A -> 0x00007FF62DB4154E) ---
    // asm: or r14d, 4

loc_7FF62DB4154E:
    // --- Basic Block 28 (0x00007FF62DB4154E -> 0x00007FF62DB41556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41556:
    // --- Basic Block 29 (0x00007FF62DB41556 -> 0x00007FF62DB4156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x3ca8]
    goto loc_7FF62DB415C2;

loc_7FF62DB4156B:
    // --- Basic Block 30 (0x00007FF62DB4156B -> 0x00007FF62DB41573) ---
    // asm: dec r15
    goto loc_7FF62DB414C3;

loc_7FF62DB41573:
    // --- Basic Block 31 (0x00007FF62DB41573 -> 0x00007FF62DB41578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB41578:
    // --- Basic Block 32 (0x00007FF62DB41578 -> 0x00007FF62DB415A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b88]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x3c49]
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF62DB41510;
    } else {
        goto loc_7FF62DB415A0;
    }

loc_7FF62DB415A0:
    // --- Basic Block 33 (0x00007FF62DB415A0 -> 0x00007FF62DB415A8) ---
    r14d, 4; // mov
    goto loc_7FF62DB4154E;

loc_7FF62DB415A8:
    // --- Basic Block 34 (0x00007FF62DB415A8 -> 0x00007FF62DB415B0) ---
    // asm: dec r15
    goto loc_7FF62DB41510;

loc_7FF62DB415B0:
    // --- Basic Block 35 (0x00007FF62DB415B0 -> 0x00007FF62DB415C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB415C2:
    // --- Basic Block 36 (0x00007FF62DB415C2 -> 0x00007FF62DB415E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3b28]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB415EC;
    } else {
        goto loc_7FF62DB415E2;
    }

loc_7FF62DB415E2:
    // --- Basic Block 37 (0x00007FF62DB415E2 -> 0x00007FF62DB415EC) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3b5d]

loc_7FF62DB415EC:
    // --- Basic Block 38 (0x00007FF62DB415EC -> 0x00007FF62DB41602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b13]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4160F;
    } else {
        goto loc_7FF62DB41602;
    }

loc_7FF62DB41602:
    // --- Basic Block 39 (0x00007FF62DB41602 -> 0x00007FF62DB4160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4160F:
    // --- Basic Block 40 (0x00007FF62DB4160F -> 0x00007FF62DB41622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF62DB41622:
    // --- Basic Block 41 (0x00007FF62DB41622 -> 0x00007FF62DB41684) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbx; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x40
    // asm: movzx r15d, r8b
    r14, rdx; // mov
    rdi, rcx; // mov
    ebx = 0;
    dword ptr [rsp + 0x20], ebx; // mov
    sil = 0;
    byte ptr [rsp + 0x88], sil; // mov
    r12, rcx; // mov
    qword ptr [rsp + 0x28], rcx; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a91]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41691;
    } else {
        goto loc_7FF62DB41684;
    }

loc_7FF62DB41684:
    // --- Basic Block 42 (0x00007FF62DB41684 -> 0x00007FF62DB41691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41691:
    // --- Basic Block 43 (0x00007FF62DB41691 -> 0x00007FF62DB416A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB45170(); // qword ptr [rip + 0x3ad4]
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF62DB41774;
    } else {
        goto loc_7FF62DB416A8;
    }

loc_7FF62DB416A8:
    // --- Basic Block 44 (0x00007FF62DB416A8 -> 0x00007FF62DB416B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB416B9;
    } else {
        goto loc_7FF62DB416B6;
    }

loc_7FF62DB416B6:
    // --- Basic Block 45 (0x00007FF62DB416B6 -> 0x00007FF62DB416B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF62DB416B9:
    // --- Basic Block 46 (0x00007FF62DB416B9 -> 0x00007FF62DB416E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a44]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F0(); // qword ptr [rip + 0x3b1b]
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF62DB416E0:
    // --- Basic Block 47 (0x00007FF62DB416E0 -> 0x00007FF62DB416E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB416EC;
    } else {
        goto loc_7FF62DB416E5;
    }

loc_7FF62DB416E5:
    // --- Basic Block 48 (0x00007FF62DB416E5 -> 0x00007FF62DB416EC) ---
    ebx, 1; // mov
    goto loc_7FF62DB41722;

loc_7FF62DB416EC:
    // --- Basic Block 49 (0x00007FF62DB416EC -> 0x00007FF62DB416F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF62DB41717;
    } else {
        goto loc_7FF62DB416F1;
    }

loc_7FF62DB416F1:
    // --- Basic Block 50 (0x00007FF62DB416F1 -> 0x00007FF62DB41717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a04]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F8(); // qword ptr [rip + 0x3ae3]
    goto loc_7FF62DB41726;

loc_7FF62DB41717:
    // --- Basic Block 51 (0x00007FF62DB41717 -> 0x00007FF62DB4171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF62DB41728;
    } else {
        goto loc_7FF62DB4171D;
    }

loc_7FF62DB4171D:
    // --- Basic Block 52 (0x00007FF62DB4171D -> 0x00007FF62DB41722) ---
    ebx, 2; // mov

loc_7FF62DB41722:
    // --- Basic Block 53 (0x00007FF62DB41722 -> 0x00007FF62DB41726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF62DB41726:
    // --- Basic Block 54 (0x00007FF62DB41726 -> 0x00007FF62DB41728) ---
    goto loc_7FF62DB4176F;

loc_7FF62DB41728:
    // --- Basic Block 55 (0x00007FF62DB41728 -> 0x00007FF62DB41759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF62DB424C0(); // 0x7ff62db424c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x39c2]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451E8(); // qword ptr [rip + 0x3a91]
    goto loc_7FF62DB416E0;

loc_7FF62DB41759:
    // --- Basic Block 56 (0x00007FF62DB41759 -> 0x00007FF62DB4176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF62DB4176F:
    // --- Basic Block 57 (0x00007FF62DB4176F -> 0x00007FF62DB41774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF62DB41777;
    } else {
        goto loc_7FF62DB41774;
    }

loc_7FF62DB41774:
    // --- Basic Block 58 (0x00007FF62DB41774 -> 0x00007FF62DB41777) ---
    // asm: or ebx, 2

loc_7FF62DB41777:
    // --- Basic Block 59 (0x00007FF62DB41777 -> 0x00007FF62DB417A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3974]
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3972]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB417B0;
    } else {
        goto loc_7FF62DB417A3;
    }

loc_7FF62DB417A3:
    // --- Basic Block 60 (0x00007FF62DB417A3 -> 0x00007FF62DB417B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB417B0:
    // --- Basic Block 61 (0x00007FF62DB417B0 -> 0x00007FF62DB417CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF62DB417CE:
    // --- Basic Block 62 (0x00007FF62DB417CE -> 0x00007FF62DB4180C) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4180C:
    // --- Basic Block 63 (0x00007FF62DB4180C -> 0x00007FF62DB4184C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 64 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 65 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF62DB412F0` (0x7FF62DB412F0)
- **Size**: `1474 bytes` | **Complexity V(G)**: `21` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB412F0 | Address: 0x00007FF62DB412F0
// Size: 1474 bytes | Basic Blocks: 66 | Complexity V(G): 21
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB412F0(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB412F0:
    // --- Basic Block 0 (0x00007FF62DB412F0 -> 0x00007FF62DB41311) ---
    // asm: sub rsp, 0x20
    // asm: movabs rbp, 0x7fffffffffffffff
    rdi, r8; // mov
    r14, rdx; // mov
    rsi, rcx; // mov
    // asm: cmp r8, rbp
    if (ja_condition) {
        goto loc_7FF62DB41392;
    } else {
        goto loc_7FF62DB41311;
    }

loc_7FF62DB41311:
    // --- Basic Block 1 (0x00007FF62DB41311 -> 0x00007FF62DB41317) ---
    // asm: cmp r8, 0xf
    if (ja_condition) {
        goto loc_7FF62DB4132E;
    } else {
        goto loc_7FF62DB41317;
    }

loc_7FF62DB41317:
    // --- Basic Block 2 (0x00007FF62DB41317 -> 0x00007FF62DB4132E) ---
    qword ptr [rcx + 0x10], r8; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rdi + rsi], 0; // mov
    goto loc_7FF62DB4137C;

loc_7FF62DB4132E:
    // --- Basic Block 3 (0x00007FF62DB4132E -> 0x00007FF62DB4133F) ---
    rax, rdi; // mov
    qword ptr [rsp + 0x30], rbx; // mov
    // asm: or rax, 0xf
    // asm: cmp rax, rbp
    if (ja_condition) {
        goto loc_7FF62DB4134E;
    } else {
        goto loc_7FF62DB4133F;
    }

loc_7FF62DB4133F:
    // --- Basic Block 4 (0x00007FF62DB4133F -> 0x00007FF62DB4134E) ---
    ecx, 0x16; // mov
    rbp, rax; // mov
    // asm: cmp rax, rcx
    // asm: cmovb rbp, rcx

loc_7FF62DB4134E:
    // --- Basic Block 5 (0x00007FF62DB4134E -> 0x00007FF62DB4137C) ---
    rcx, [rbp + 1]; // lea
    rax_result = sub_7FF62DB41270(); // 0x7ff62db41270
    r8, rdi; // mov
    qword ptr [rsi], rax; // mov
    rdx, r14; // mov
    qword ptr [rsi + 0x10], rdi; // mov
    rcx, rax; // mov
    qword ptr [rsi + 0x18], rbp; // mov
    rbx, rax; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rbx + rdi], 0; // mov
    rbx, qword ptr [rsp + 0x30]; // mov

loc_7FF62DB4137C:
    // --- Basic Block 6 (0x00007FF62DB4137C -> 0x00007FF62DB41392) ---
    rbp, qword ptr [rsp + 0x38]; // mov
    rsi, qword ptr [rsp + 0x40]; // mov
    rdi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41392:
    // --- Basic Block 7 (0x00007FF62DB41392 -> 0x00007FF62DB413E2) ---
    rax_result = sub_7FF62DB420A0(); // 0x7ff62db420a0
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rdx; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    r13, r8; // mov
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r14d, r14d
    dword ptr [rsp + 0x88], r14d; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e3b]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413E2;
    }

loc_7FF62DB413E2:
    // --- Basic Block 8 (0x00007FF62DB413E2 -> 0x00007FF62DB413F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e26]
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413F7;
    }

loc_7FF62DB413F7:
    // --- Basic Block 9 (0x00007FF62DB413F7 -> 0x00007FF62DB4140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e11]
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF62DB41412;

loc_7FF62DB4140F:
    // --- Basic Block 10 (0x00007FF62DB4140F -> 0x00007FF62DB41412) ---
    r15, r14; // mov

loc_7FF62DB41412:
    // --- Basic Block 11 (0x00007FF62DB41412 -> 0x00007FF62DB4142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ce6]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4143C;
    } else {
        goto loc_7FF62DB4142F;
    }

loc_7FF62DB4142F:
    // --- Basic Block 12 (0x00007FF62DB4142F -> 0x00007FF62DB4143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4143C:
    // --- Basic Block 13 (0x00007FF62DB4143C -> 0x00007FF62DB41450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3dec]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41456;
    } else {
        goto loc_7FF62DB41450;
    }

loc_7FF62DB41450:
    // --- Basic Block 14 (0x00007FF62DB41450 -> 0x00007FF62DB41456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB41456:
    // --- Basic Block 15 (0x00007FF62DB41456 -> 0x00007FF62DB4146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x3ca2]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB4146B;
    }

loc_7FF62DB4146B:
    // --- Basic Block 16 (0x00007FF62DB4146B -> 0x00007FF62DB41470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB41470;
    }

loc_7FF62DB41470:
    // --- Basic Block 17 (0x00007FF62DB41470 -> 0x00007FF62DB4148F) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x3cef]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3daf]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB4148F:
    // --- Basic Block 18 (0x00007FF62DB4148F -> 0x00007FF62DB41496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB41496:
    // --- Basic Block 19 (0x00007FF62DB41496 -> 0x00007FF62DB4149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB414A5;
    } else {
        goto loc_7FF62DB4149A;
    }

loc_7FF62DB4149A:
    // --- Basic Block 20 (0x00007FF62DB4149A -> 0x00007FF62DB414A5) ---
    r14d, 4; // mov
    goto loc_7FF62DB415C2;

loc_7FF62DB414A5:
    // --- Basic Block 21 (0x00007FF62DB414A5 -> 0x00007FF62DB414C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x3d7b]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB41578;
    } else {
        goto loc_7FF62DB414C3;
    }

loc_7FF62DB414C3:
    // --- Basic Block 22 (0x00007FF62DB414C3 -> 0x00007FF62DB414CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41573;
    } else {
        goto loc_7FF62DB414CC;
    }

loc_7FF62DB414CC:
    // --- Basic Block 23 (0x00007FF62DB414CC -> 0x00007FF62DB41501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3c35]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3c21]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3c44]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB4156B;
    } else {
        goto loc_7FF62DB41501;
    }

loc_7FF62DB41501:
    // --- Basic Block 24 (0x00007FF62DB41501 -> 0x00007FF62DB41510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41510:
    // --- Basic Block 25 (0x00007FF62DB41510 -> 0x00007FF62DB41515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41556;
    } else {
        goto loc_7FF62DB41515;
    }

loc_7FF62DB41515:
    // --- Basic Block 26 (0x00007FF62DB41515 -> 0x00007FF62DB4154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3bec]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3bd8]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3bfb]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB415A8;
    } else {
        goto loc_7FF62DB4154A;
    }

loc_7FF62DB4154A:
    // --- Basic Block 27 (0x00007FF62DB4154A -> 0x00007FF62DB4154E) ---
    // asm: or r14d, 4

loc_7FF62DB4154E:
    // --- Basic Block 28 (0x00007FF62DB4154E -> 0x00007FF62DB41556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41556:
    // --- Basic Block 29 (0x00007FF62DB41556 -> 0x00007FF62DB4156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x3ca8]
    goto loc_7FF62DB415C2;

loc_7FF62DB4156B:
    // --- Basic Block 30 (0x00007FF62DB4156B -> 0x00007FF62DB41573) ---
    // asm: dec r15
    goto loc_7FF62DB414C3;

loc_7FF62DB41573:
    // --- Basic Block 31 (0x00007FF62DB41573 -> 0x00007FF62DB41578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB41578:
    // --- Basic Block 32 (0x00007FF62DB41578 -> 0x00007FF62DB415A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b88]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x3c49]
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF62DB41510;
    } else {
        goto loc_7FF62DB415A0;
    }

loc_7FF62DB415A0:
    // --- Basic Block 33 (0x00007FF62DB415A0 -> 0x00007FF62DB415A8) ---
    r14d, 4; // mov
    goto loc_7FF62DB4154E;

loc_7FF62DB415A8:
    // --- Basic Block 34 (0x00007FF62DB415A8 -> 0x00007FF62DB415B0) ---
    // asm: dec r15
    goto loc_7FF62DB41510;

loc_7FF62DB415B0:
    // --- Basic Block 35 (0x00007FF62DB415B0 -> 0x00007FF62DB415C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB415C2:
    // --- Basic Block 36 (0x00007FF62DB415C2 -> 0x00007FF62DB415E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3b28]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB415EC;
    } else {
        goto loc_7FF62DB415E2;
    }

loc_7FF62DB415E2:
    // --- Basic Block 37 (0x00007FF62DB415E2 -> 0x00007FF62DB415EC) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3b5d]

loc_7FF62DB415EC:
    // --- Basic Block 38 (0x00007FF62DB415EC -> 0x00007FF62DB41602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b13]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4160F;
    } else {
        goto loc_7FF62DB41602;
    }

loc_7FF62DB41602:
    // --- Basic Block 39 (0x00007FF62DB41602 -> 0x00007FF62DB4160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4160F:
    // --- Basic Block 40 (0x00007FF62DB4160F -> 0x00007FF62DB41622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF62DB41622:
    // --- Basic Block 41 (0x00007FF62DB41622 -> 0x00007FF62DB41684) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbx; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x40
    // asm: movzx r15d, r8b
    r14, rdx; // mov
    rdi, rcx; // mov
    ebx = 0;
    dword ptr [rsp + 0x20], ebx; // mov
    sil = 0;
    byte ptr [rsp + 0x88], sil; // mov
    r12, rcx; // mov
    qword ptr [rsp + 0x28], rcx; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a91]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41691;
    } else {
        goto loc_7FF62DB41684;
    }

loc_7FF62DB41684:
    // --- Basic Block 42 (0x00007FF62DB41684 -> 0x00007FF62DB41691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41691:
    // --- Basic Block 43 (0x00007FF62DB41691 -> 0x00007FF62DB416A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB45170(); // qword ptr [rip + 0x3ad4]
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF62DB41774;
    } else {
        goto loc_7FF62DB416A8;
    }

loc_7FF62DB416A8:
    // --- Basic Block 44 (0x00007FF62DB416A8 -> 0x00007FF62DB416B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB416B9;
    } else {
        goto loc_7FF62DB416B6;
    }

loc_7FF62DB416B6:
    // --- Basic Block 45 (0x00007FF62DB416B6 -> 0x00007FF62DB416B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF62DB416B9:
    // --- Basic Block 46 (0x00007FF62DB416B9 -> 0x00007FF62DB416E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a44]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F0(); // qword ptr [rip + 0x3b1b]
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF62DB416E0:
    // --- Basic Block 47 (0x00007FF62DB416E0 -> 0x00007FF62DB416E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB416EC;
    } else {
        goto loc_7FF62DB416E5;
    }

loc_7FF62DB416E5:
    // --- Basic Block 48 (0x00007FF62DB416E5 -> 0x00007FF62DB416EC) ---
    ebx, 1; // mov
    goto loc_7FF62DB41722;

loc_7FF62DB416EC:
    // --- Basic Block 49 (0x00007FF62DB416EC -> 0x00007FF62DB416F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF62DB41717;
    } else {
        goto loc_7FF62DB416F1;
    }

loc_7FF62DB416F1:
    // --- Basic Block 50 (0x00007FF62DB416F1 -> 0x00007FF62DB41717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a04]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F8(); // qword ptr [rip + 0x3ae3]
    goto loc_7FF62DB41726;

loc_7FF62DB41717:
    // --- Basic Block 51 (0x00007FF62DB41717 -> 0x00007FF62DB4171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF62DB41728;
    } else {
        goto loc_7FF62DB4171D;
    }

loc_7FF62DB4171D:
    // --- Basic Block 52 (0x00007FF62DB4171D -> 0x00007FF62DB41722) ---
    ebx, 2; // mov

loc_7FF62DB41722:
    // --- Basic Block 53 (0x00007FF62DB41722 -> 0x00007FF62DB41726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF62DB41726:
    // --- Basic Block 54 (0x00007FF62DB41726 -> 0x00007FF62DB41728) ---
    goto loc_7FF62DB4176F;

loc_7FF62DB41728:
    // --- Basic Block 55 (0x00007FF62DB41728 -> 0x00007FF62DB41759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF62DB424C0(); // 0x7ff62db424c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x39c2]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451E8(); // qword ptr [rip + 0x3a91]
    goto loc_7FF62DB416E0;

loc_7FF62DB41759:
    // --- Basic Block 56 (0x00007FF62DB41759 -> 0x00007FF62DB4176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF62DB4176F:
    // --- Basic Block 57 (0x00007FF62DB4176F -> 0x00007FF62DB41774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF62DB41777;
    } else {
        goto loc_7FF62DB41774;
    }

loc_7FF62DB41774:
    // --- Basic Block 58 (0x00007FF62DB41774 -> 0x00007FF62DB41777) ---
    // asm: or ebx, 2

loc_7FF62DB41777:
    // --- Basic Block 59 (0x00007FF62DB41777 -> 0x00007FF62DB417A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3974]
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3972]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB417B0;
    } else {
        goto loc_7FF62DB417A3;
    }

loc_7FF62DB417A3:
    // --- Basic Block 60 (0x00007FF62DB417A3 -> 0x00007FF62DB417B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB417B0:
    // --- Basic Block 61 (0x00007FF62DB417B0 -> 0x00007FF62DB417CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF62DB417CE:
    // --- Basic Block 62 (0x00007FF62DB417CE -> 0x00007FF62DB4180C) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4180C:
    // --- Basic Block 63 (0x00007FF62DB4180C -> 0x00007FF62DB4184C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 64 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 65 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF62DB41331` (0x7FF62DB41331)
- **Size**: `1409 bytes` | **Complexity V(G)**: `19` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB41331 | Address: 0x00007FF62DB41331
// Size: 1409 bytes | Basic Blocks: 62 | Complexity V(G): 19
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB41331(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB41331:
    // --- Basic Block 0 (0x00007FF62DB41331 -> 0x00007FF62DB4133F) ---
    qword ptr [rsp + 0x30], rbx; // mov
    // asm: or rax, 0xf
    // asm: cmp rax, rbp
    if (ja_condition) {
        goto loc_7FF62DB4134E;
    } else {
        goto loc_7FF62DB4133F;
    }

loc_7FF62DB4133F:
    // --- Basic Block 1 (0x00007FF62DB4133F -> 0x00007FF62DB4134E) ---
    ecx, 0x16; // mov
    rbp, rax; // mov
    // asm: cmp rax, rcx
    // asm: cmovb rbp, rcx

loc_7FF62DB4134E:
    // --- Basic Block 2 (0x00007FF62DB4134E -> 0x00007FF62DB41392) ---
    rcx, [rbp + 1]; // lea
    rax_result = sub_7FF62DB41270(); // 0x7ff62db41270
    r8, rdi; // mov
    qword ptr [rsi], rax; // mov
    rdx, r14; // mov
    qword ptr [rsi + 0x10], rdi; // mov
    rcx, rax; // mov
    qword ptr [rsi + 0x18], rbp; // mov
    rbx, rax; // mov
    rax_result = sub_7FF62DB440FE(); // 0x7ff62db440fe
    byte ptr [rbx + rdi], 0; // mov
    rbx, qword ptr [rsp + 0x30]; // mov
    rbp, qword ptr [rsp + 0x38]; // mov
    rsi, qword ptr [rsp + 0x40]; // mov
    rdi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41392:
    // --- Basic Block 3 (0x00007FF62DB41392 -> 0x00007FF62DB413E2) ---
    rax_result = sub_7FF62DB420A0(); // 0x7ff62db420a0
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rdx; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    r13, r8; // mov
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r14d, r14d
    dword ptr [rsp + 0x88], r14d; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e3b]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413E2;
    }

loc_7FF62DB413E2:
    // --- Basic Block 4 (0x00007FF62DB413E2 -> 0x00007FF62DB413F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e26]
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413F7;
    }

loc_7FF62DB413F7:
    // --- Basic Block 5 (0x00007FF62DB413F7 -> 0x00007FF62DB4140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e11]
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF62DB41412;

loc_7FF62DB4140F:
    // --- Basic Block 6 (0x00007FF62DB4140F -> 0x00007FF62DB41412) ---
    r15, r14; // mov

loc_7FF62DB41412:
    // --- Basic Block 7 (0x00007FF62DB41412 -> 0x00007FF62DB4142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ce6]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4143C;
    } else {
        goto loc_7FF62DB4142F;
    }

loc_7FF62DB4142F:
    // --- Basic Block 8 (0x00007FF62DB4142F -> 0x00007FF62DB4143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4143C:
    // --- Basic Block 9 (0x00007FF62DB4143C -> 0x00007FF62DB41450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3dec]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41456;
    } else {
        goto loc_7FF62DB41450;
    }

loc_7FF62DB41450:
    // --- Basic Block 10 (0x00007FF62DB41450 -> 0x00007FF62DB41456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB41456:
    // --- Basic Block 11 (0x00007FF62DB41456 -> 0x00007FF62DB4146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x3ca2]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB4146B;
    }

loc_7FF62DB4146B:
    // --- Basic Block 12 (0x00007FF62DB4146B -> 0x00007FF62DB41470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB41470;
    }

loc_7FF62DB41470:
    // --- Basic Block 13 (0x00007FF62DB41470 -> 0x00007FF62DB4148F) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x3cef]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3daf]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB4148F:
    // --- Basic Block 14 (0x00007FF62DB4148F -> 0x00007FF62DB41496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB41496:
    // --- Basic Block 15 (0x00007FF62DB41496 -> 0x00007FF62DB4149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB414A5;
    } else {
        goto loc_7FF62DB4149A;
    }

loc_7FF62DB4149A:
    // --- Basic Block 16 (0x00007FF62DB4149A -> 0x00007FF62DB414A5) ---
    r14d, 4; // mov
    goto loc_7FF62DB415C2;

loc_7FF62DB414A5:
    // --- Basic Block 17 (0x00007FF62DB414A5 -> 0x00007FF62DB414C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x3d7b]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB41578;
    } else {
        goto loc_7FF62DB414C3;
    }

loc_7FF62DB414C3:
    // --- Basic Block 18 (0x00007FF62DB414C3 -> 0x00007FF62DB414CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41573;
    } else {
        goto loc_7FF62DB414CC;
    }

loc_7FF62DB414CC:
    // --- Basic Block 19 (0x00007FF62DB414CC -> 0x00007FF62DB41501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3c35]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3c21]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3c44]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB4156B;
    } else {
        goto loc_7FF62DB41501;
    }

loc_7FF62DB41501:
    // --- Basic Block 20 (0x00007FF62DB41501 -> 0x00007FF62DB41510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41510:
    // --- Basic Block 21 (0x00007FF62DB41510 -> 0x00007FF62DB41515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41556;
    } else {
        goto loc_7FF62DB41515;
    }

loc_7FF62DB41515:
    // --- Basic Block 22 (0x00007FF62DB41515 -> 0x00007FF62DB4154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3bec]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3bd8]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3bfb]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB415A8;
    } else {
        goto loc_7FF62DB4154A;
    }

loc_7FF62DB4154A:
    // --- Basic Block 23 (0x00007FF62DB4154A -> 0x00007FF62DB4154E) ---
    // asm: or r14d, 4

loc_7FF62DB4154E:
    // --- Basic Block 24 (0x00007FF62DB4154E -> 0x00007FF62DB41556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41556:
    // --- Basic Block 25 (0x00007FF62DB41556 -> 0x00007FF62DB4156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x3ca8]
    goto loc_7FF62DB415C2;

loc_7FF62DB4156B:
    // --- Basic Block 26 (0x00007FF62DB4156B -> 0x00007FF62DB41573) ---
    // asm: dec r15
    goto loc_7FF62DB414C3;

loc_7FF62DB41573:
    // --- Basic Block 27 (0x00007FF62DB41573 -> 0x00007FF62DB41578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB41578:
    // --- Basic Block 28 (0x00007FF62DB41578 -> 0x00007FF62DB415A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b88]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x3c49]
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF62DB41510;
    } else {
        goto loc_7FF62DB415A0;
    }

loc_7FF62DB415A0:
    // --- Basic Block 29 (0x00007FF62DB415A0 -> 0x00007FF62DB415A8) ---
    r14d, 4; // mov
    goto loc_7FF62DB4154E;

loc_7FF62DB415A8:
    // --- Basic Block 30 (0x00007FF62DB415A8 -> 0x00007FF62DB415B0) ---
    // asm: dec r15
    goto loc_7FF62DB41510;

loc_7FF62DB415B0:
    // --- Basic Block 31 (0x00007FF62DB415B0 -> 0x00007FF62DB415C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB415C2:
    // --- Basic Block 32 (0x00007FF62DB415C2 -> 0x00007FF62DB415E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3b28]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB415EC;
    } else {
        goto loc_7FF62DB415E2;
    }

loc_7FF62DB415E2:
    // --- Basic Block 33 (0x00007FF62DB415E2 -> 0x00007FF62DB415EC) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3b5d]

loc_7FF62DB415EC:
    // --- Basic Block 34 (0x00007FF62DB415EC -> 0x00007FF62DB41602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b13]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4160F;
    } else {
        goto loc_7FF62DB41602;
    }

loc_7FF62DB41602:
    // --- Basic Block 35 (0x00007FF62DB41602 -> 0x00007FF62DB4160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4160F:
    // --- Basic Block 36 (0x00007FF62DB4160F -> 0x00007FF62DB41622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF62DB41622:
    // --- Basic Block 37 (0x00007FF62DB41622 -> 0x00007FF62DB41684) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbx; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x40
    // asm: movzx r15d, r8b
    r14, rdx; // mov
    rdi, rcx; // mov
    ebx = 0;
    dword ptr [rsp + 0x20], ebx; // mov
    sil = 0;
    byte ptr [rsp + 0x88], sil; // mov
    r12, rcx; // mov
    qword ptr [rsp + 0x28], rcx; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a91]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41691;
    } else {
        goto loc_7FF62DB41684;
    }

loc_7FF62DB41684:
    // --- Basic Block 38 (0x00007FF62DB41684 -> 0x00007FF62DB41691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41691:
    // --- Basic Block 39 (0x00007FF62DB41691 -> 0x00007FF62DB416A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB45170(); // qword ptr [rip + 0x3ad4]
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF62DB41774;
    } else {
        goto loc_7FF62DB416A8;
    }

loc_7FF62DB416A8:
    // --- Basic Block 40 (0x00007FF62DB416A8 -> 0x00007FF62DB416B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB416B9;
    } else {
        goto loc_7FF62DB416B6;
    }

loc_7FF62DB416B6:
    // --- Basic Block 41 (0x00007FF62DB416B6 -> 0x00007FF62DB416B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF62DB416B9:
    // --- Basic Block 42 (0x00007FF62DB416B9 -> 0x00007FF62DB416E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a44]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F0(); // qword ptr [rip + 0x3b1b]
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF62DB416E0:
    // --- Basic Block 43 (0x00007FF62DB416E0 -> 0x00007FF62DB416E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB416EC;
    } else {
        goto loc_7FF62DB416E5;
    }

loc_7FF62DB416E5:
    // --- Basic Block 44 (0x00007FF62DB416E5 -> 0x00007FF62DB416EC) ---
    ebx, 1; // mov
    goto loc_7FF62DB41722;

loc_7FF62DB416EC:
    // --- Basic Block 45 (0x00007FF62DB416EC -> 0x00007FF62DB416F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF62DB41717;
    } else {
        goto loc_7FF62DB416F1;
    }

loc_7FF62DB416F1:
    // --- Basic Block 46 (0x00007FF62DB416F1 -> 0x00007FF62DB41717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a04]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F8(); // qword ptr [rip + 0x3ae3]
    goto loc_7FF62DB41726;

loc_7FF62DB41717:
    // --- Basic Block 47 (0x00007FF62DB41717 -> 0x00007FF62DB4171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF62DB41728;
    } else {
        goto loc_7FF62DB4171D;
    }

loc_7FF62DB4171D:
    // --- Basic Block 48 (0x00007FF62DB4171D -> 0x00007FF62DB41722) ---
    ebx, 2; // mov

loc_7FF62DB41722:
    // --- Basic Block 49 (0x00007FF62DB41722 -> 0x00007FF62DB41726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF62DB41726:
    // --- Basic Block 50 (0x00007FF62DB41726 -> 0x00007FF62DB41728) ---
    goto loc_7FF62DB4176F;

loc_7FF62DB41728:
    // --- Basic Block 51 (0x00007FF62DB41728 -> 0x00007FF62DB41759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF62DB424C0(); // 0x7ff62db424c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x39c2]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451E8(); // qword ptr [rip + 0x3a91]
    goto loc_7FF62DB416E0;

loc_7FF62DB41759:
    // --- Basic Block 52 (0x00007FF62DB41759 -> 0x00007FF62DB4176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF62DB4176F:
    // --- Basic Block 53 (0x00007FF62DB4176F -> 0x00007FF62DB41774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF62DB41777;
    } else {
        goto loc_7FF62DB41774;
    }

loc_7FF62DB41774:
    // --- Basic Block 54 (0x00007FF62DB41774 -> 0x00007FF62DB41777) ---
    // asm: or ebx, 2

loc_7FF62DB41777:
    // --- Basic Block 55 (0x00007FF62DB41777 -> 0x00007FF62DB417A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3974]
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3972]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB417B0;
    } else {
        goto loc_7FF62DB417A3;
    }

loc_7FF62DB417A3:
    // --- Basic Block 56 (0x00007FF62DB417A3 -> 0x00007FF62DB417B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB417B0:
    // --- Basic Block 57 (0x00007FF62DB417B0 -> 0x00007FF62DB417CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF62DB417CE:
    // --- Basic Block 58 (0x00007FF62DB417CE -> 0x00007FF62DB4180C) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4180C:
    // --- Basic Block 59 (0x00007FF62DB4180C -> 0x00007FF62DB4184C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 60 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 61 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF62DB413A0` (0x7FF62DB413A0)
- **Size**: `1614 bytes` | **Complexity V(G)**: `23` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB413A0 | Address: 0x00007FF62DB413A0
// Size: 1614 bytes | Basic Blocks: 72 | Complexity V(G): 23
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB413A0(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB413A0:
    // --- Basic Block 0 (0x00007FF62DB413A0 -> 0x00007FF62DB413E2) ---
    qword ptr [rsp + 0x10], rdx; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    r13, r8; // mov
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r14d, r14d
    dword ptr [rsp + 0x88], r14d; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e3b]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413E2;
    }

loc_7FF62DB413E2:
    // --- Basic Block 1 (0x00007FF62DB413E2 -> 0x00007FF62DB413F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e26]
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413F7;
    }

loc_7FF62DB413F7:
    // --- Basic Block 2 (0x00007FF62DB413F7 -> 0x00007FF62DB4140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e11]
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF62DB41412;

loc_7FF62DB4140F:
    // --- Basic Block 3 (0x00007FF62DB4140F -> 0x00007FF62DB41412) ---
    r15, r14; // mov

loc_7FF62DB41412:
    // --- Basic Block 4 (0x00007FF62DB41412 -> 0x00007FF62DB4142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ce6]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4143C;
    } else {
        goto loc_7FF62DB4142F;
    }

loc_7FF62DB4142F:
    // --- Basic Block 5 (0x00007FF62DB4142F -> 0x00007FF62DB4143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4143C:
    // --- Basic Block 6 (0x00007FF62DB4143C -> 0x00007FF62DB41450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3dec]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41456;
    } else {
        goto loc_7FF62DB41450;
    }

loc_7FF62DB41450:
    // --- Basic Block 7 (0x00007FF62DB41450 -> 0x00007FF62DB41456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB41456:
    // --- Basic Block 8 (0x00007FF62DB41456 -> 0x00007FF62DB4146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x3ca2]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB4146B;
    }

loc_7FF62DB4146B:
    // --- Basic Block 9 (0x00007FF62DB4146B -> 0x00007FF62DB41470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB41470;
    }

loc_7FF62DB41470:
    // --- Basic Block 10 (0x00007FF62DB41470 -> 0x00007FF62DB4148F) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x3cef]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3daf]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB4148F:
    // --- Basic Block 11 (0x00007FF62DB4148F -> 0x00007FF62DB41496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB41496:
    // --- Basic Block 12 (0x00007FF62DB41496 -> 0x00007FF62DB4149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB414A5;
    } else {
        goto loc_7FF62DB4149A;
    }

loc_7FF62DB4149A:
    // --- Basic Block 13 (0x00007FF62DB4149A -> 0x00007FF62DB414A5) ---
    r14d, 4; // mov
    goto loc_7FF62DB415C2;

loc_7FF62DB414A5:
    // --- Basic Block 14 (0x00007FF62DB414A5 -> 0x00007FF62DB414C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x3d7b]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB41578;
    } else {
        goto loc_7FF62DB414C3;
    }

loc_7FF62DB414C3:
    // --- Basic Block 15 (0x00007FF62DB414C3 -> 0x00007FF62DB414CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41573;
    } else {
        goto loc_7FF62DB414CC;
    }

loc_7FF62DB414CC:
    // --- Basic Block 16 (0x00007FF62DB414CC -> 0x00007FF62DB41501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3c35]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3c21]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3c44]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB4156B;
    } else {
        goto loc_7FF62DB41501;
    }

loc_7FF62DB41501:
    // --- Basic Block 17 (0x00007FF62DB41501 -> 0x00007FF62DB41510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41510:
    // --- Basic Block 18 (0x00007FF62DB41510 -> 0x00007FF62DB41515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41556;
    } else {
        goto loc_7FF62DB41515;
    }

loc_7FF62DB41515:
    // --- Basic Block 19 (0x00007FF62DB41515 -> 0x00007FF62DB4154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3bec]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3bd8]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3bfb]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB415A8;
    } else {
        goto loc_7FF62DB4154A;
    }

loc_7FF62DB4154A:
    // --- Basic Block 20 (0x00007FF62DB4154A -> 0x00007FF62DB4154E) ---
    // asm: or r14d, 4

loc_7FF62DB4154E:
    // --- Basic Block 21 (0x00007FF62DB4154E -> 0x00007FF62DB41556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41556:
    // --- Basic Block 22 (0x00007FF62DB41556 -> 0x00007FF62DB4156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x3ca8]
    goto loc_7FF62DB415C2;

loc_7FF62DB4156B:
    // --- Basic Block 23 (0x00007FF62DB4156B -> 0x00007FF62DB41573) ---
    // asm: dec r15
    goto loc_7FF62DB414C3;

loc_7FF62DB41573:
    // --- Basic Block 24 (0x00007FF62DB41573 -> 0x00007FF62DB41578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB41578:
    // --- Basic Block 25 (0x00007FF62DB41578 -> 0x00007FF62DB415A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b88]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x3c49]
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF62DB41510;
    } else {
        goto loc_7FF62DB415A0;
    }

loc_7FF62DB415A0:
    // --- Basic Block 26 (0x00007FF62DB415A0 -> 0x00007FF62DB415A8) ---
    r14d, 4; // mov
    goto loc_7FF62DB4154E;

loc_7FF62DB415A8:
    // --- Basic Block 27 (0x00007FF62DB415A8 -> 0x00007FF62DB415B0) ---
    // asm: dec r15
    goto loc_7FF62DB41510;

loc_7FF62DB415B0:
    // --- Basic Block 28 (0x00007FF62DB415B0 -> 0x00007FF62DB415C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB415C2:
    // --- Basic Block 29 (0x00007FF62DB415C2 -> 0x00007FF62DB415E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3b28]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB415EC;
    } else {
        goto loc_7FF62DB415E2;
    }

loc_7FF62DB415E2:
    // --- Basic Block 30 (0x00007FF62DB415E2 -> 0x00007FF62DB415EC) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3b5d]

loc_7FF62DB415EC:
    // --- Basic Block 31 (0x00007FF62DB415EC -> 0x00007FF62DB41602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b13]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4160F;
    } else {
        goto loc_7FF62DB41602;
    }

loc_7FF62DB41602:
    // --- Basic Block 32 (0x00007FF62DB41602 -> 0x00007FF62DB4160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4160F:
    // --- Basic Block 33 (0x00007FF62DB4160F -> 0x00007FF62DB41622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF62DB41622:
    // --- Basic Block 34 (0x00007FF62DB41622 -> 0x00007FF62DB41684) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbx; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x40
    // asm: movzx r15d, r8b
    r14, rdx; // mov
    rdi, rcx; // mov
    ebx = 0;
    dword ptr [rsp + 0x20], ebx; // mov
    sil = 0;
    byte ptr [rsp + 0x88], sil; // mov
    r12, rcx; // mov
    qword ptr [rsp + 0x28], rcx; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a91]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41691;
    } else {
        goto loc_7FF62DB41684;
    }

loc_7FF62DB41684:
    // --- Basic Block 35 (0x00007FF62DB41684 -> 0x00007FF62DB41691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41691:
    // --- Basic Block 36 (0x00007FF62DB41691 -> 0x00007FF62DB416A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB45170(); // qword ptr [rip + 0x3ad4]
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF62DB41774;
    } else {
        goto loc_7FF62DB416A8;
    }

loc_7FF62DB416A8:
    // --- Basic Block 37 (0x00007FF62DB416A8 -> 0x00007FF62DB416B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB416B9;
    } else {
        goto loc_7FF62DB416B6;
    }

loc_7FF62DB416B6:
    // --- Basic Block 38 (0x00007FF62DB416B6 -> 0x00007FF62DB416B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF62DB416B9:
    // --- Basic Block 39 (0x00007FF62DB416B9 -> 0x00007FF62DB416E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a44]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F0(); // qword ptr [rip + 0x3b1b]
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF62DB416E0:
    // --- Basic Block 40 (0x00007FF62DB416E0 -> 0x00007FF62DB416E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB416EC;
    } else {
        goto loc_7FF62DB416E5;
    }

loc_7FF62DB416E5:
    // --- Basic Block 41 (0x00007FF62DB416E5 -> 0x00007FF62DB416EC) ---
    ebx, 1; // mov
    goto loc_7FF62DB41722;

loc_7FF62DB416EC:
    // --- Basic Block 42 (0x00007FF62DB416EC -> 0x00007FF62DB416F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF62DB41717;
    } else {
        goto loc_7FF62DB416F1;
    }

loc_7FF62DB416F1:
    // --- Basic Block 43 (0x00007FF62DB416F1 -> 0x00007FF62DB41717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a04]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F8(); // qword ptr [rip + 0x3ae3]
    goto loc_7FF62DB41726;

loc_7FF62DB41717:
    // --- Basic Block 44 (0x00007FF62DB41717 -> 0x00007FF62DB4171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF62DB41728;
    } else {
        goto loc_7FF62DB4171D;
    }

loc_7FF62DB4171D:
    // --- Basic Block 45 (0x00007FF62DB4171D -> 0x00007FF62DB41722) ---
    ebx, 2; // mov

loc_7FF62DB41722:
    // --- Basic Block 46 (0x00007FF62DB41722 -> 0x00007FF62DB41726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF62DB41726:
    // --- Basic Block 47 (0x00007FF62DB41726 -> 0x00007FF62DB41728) ---
    goto loc_7FF62DB4176F;

loc_7FF62DB41728:
    // --- Basic Block 48 (0x00007FF62DB41728 -> 0x00007FF62DB41759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF62DB424C0(); // 0x7ff62db424c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x39c2]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451E8(); // qword ptr [rip + 0x3a91]
    goto loc_7FF62DB416E0;

loc_7FF62DB41759:
    // --- Basic Block 49 (0x00007FF62DB41759 -> 0x00007FF62DB4176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF62DB4176F:
    // --- Basic Block 50 (0x00007FF62DB4176F -> 0x00007FF62DB41774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF62DB41777;
    } else {
        goto loc_7FF62DB41774;
    }

loc_7FF62DB41774:
    // --- Basic Block 51 (0x00007FF62DB41774 -> 0x00007FF62DB41777) ---
    // asm: or ebx, 2

loc_7FF62DB41777:
    // --- Basic Block 52 (0x00007FF62DB41777 -> 0x00007FF62DB417A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3974]
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3972]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB417B0;
    } else {
        goto loc_7FF62DB417A3;
    }

loc_7FF62DB417A3:
    // --- Basic Block 53 (0x00007FF62DB417A3 -> 0x00007FF62DB417B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB417B0:
    // --- Basic Block 54 (0x00007FF62DB417B0 -> 0x00007FF62DB417CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF62DB417CE:
    // --- Basic Block 55 (0x00007FF62DB417CE -> 0x00007FF62DB4180C) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4180C:
    // --- Basic Block 56 (0x00007FF62DB4180C -> 0x00007FF62DB4184C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 57 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 58 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB418B2:
    // --- Basic Block 59 (0x00007FF62DB418B2 -> 0x00007FF62DB418C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF62DB42020;

loc_7FF62DB418C5:
    // --- Basic Block 60 (0x00007FF62DB418C5 -> 0x00007FF62DB418F2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x30
    // asm: test byte ptr [rcx + 0x70], 1
    rax, [rip + 0x3cc6]; // lea
    qword ptr [rcx], rax; // mov
    rbx, rcx; // mov
    if (je_condition) {
        goto loc_7FF62DB41955;
    } else {
        goto loc_7FF62DB418F2;
    }

loc_7FF62DB418F2:
    // --- Basic Block 61 (0x00007FF62DB418F2 -> 0x00007FF62DB41900) ---
    rax_result = sub_7FF62DB450B8(); // qword ptr [rip + 0x37c0]
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41908;
    } else {
        goto loc_7FF62DB41900;
    }

loc_7FF62DB41900:
    // --- Basic Block 62 (0x00007FF62DB41900 -> 0x00007FF62DB41908) ---
    rax_result = sub_7FF62DB450D8(); // qword ptr [rip + 0x37d2]
    goto loc_7FF62DB4190E;

loc_7FF62DB41908:
    // --- Basic Block 63 (0x00007FF62DB41908 -> 0x00007FF62DB4190E) ---
    rax_result = sub_7FF62DB450C0(); // qword ptr [rip + 0x37b2]

loc_7FF62DB4190E:
    // --- Basic Block 64 (0x00007FF62DB4190E -> 0x00007FF62DB41932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x3786]
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x377a]
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB4194A;
    } else {
        goto loc_7FF62DB41932;
    }

loc_7FF62DB41932:
    // --- Basic Block 65 (0x00007FF62DB41932 -> 0x00007FF62DB41947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF62DB41999;
    } else {
        goto loc_7FF62DB41947;
    }

loc_7FF62DB41947:
    // --- Basic Block 66 (0x00007FF62DB41947 -> 0x00007FF62DB4194A) ---
    rdi, rax; // mov

loc_7FF62DB4194A:
    // --- Basic Block 67 (0x00007FF62DB4194A -> 0x00007FF62DB41955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41955:
    // --- Basic Block 68 (0x00007FF62DB41955 -> 0x00007FF62DB41999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450D0(); // qword ptr [rip + 0x376a]
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450E0(); // qword ptr [rip + 0x376c]
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_7FF62DB45200;

loc_7FF62DB41999:
    // --- Basic Block 69 (0x00007FF62DB41999 -> 0x00007FF62DB419DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x39ce]
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3739]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB419E9;
    } else {
        goto loc_7FF62DB419DC;
    }

loc_7FF62DB419DC:
    // --- Basic Block 70 (0x00007FF62DB419DC -> 0x00007FF62DB419E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB419E9:
    // --- Basic Block 71 (0x00007FF62DB419E9 -> 0x00007FF62DB419EE) ---
    // asm: add rsp, 0x28
    return rax_result;

}
```

### Function `sub_00007FF62DB413B4` (0x7FF62DB413B4)
- **Size**: `1594 bytes` | **Complexity V(G)**: `23` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB413B4 | Address: 0x00007FF62DB413B4
// Size: 1594 bytes | Basic Blocks: 72 | Complexity V(G): 23
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB413B4(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB413B4:
    // --- Basic Block 0 (0x00007FF62DB413B4 -> 0x00007FF62DB413E2) ---
    // asm: sub rsp, 0x30
    r13, r8; // mov
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r14d, r14d
    dword ptr [rsp + 0x88], r14d; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e3b]
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413E2;
    }

loc_7FF62DB413E2:
    // --- Basic Block 1 (0x00007FF62DB413E2 -> 0x00007FF62DB413F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e26]
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF62DB4140F;
    } else {
        goto loc_7FF62DB413F7;
    }

loc_7FF62DB413F7:
    // --- Basic Block 2 (0x00007FF62DB413F7 -> 0x00007FF62DB4140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45218(); // qword ptr [rip + 0x3e11]
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF62DB41412;

loc_7FF62DB4140F:
    // --- Basic Block 3 (0x00007FF62DB4140F -> 0x00007FF62DB41412) ---
    r15, r14; // mov

loc_7FF62DB41412:
    // --- Basic Block 4 (0x00007FF62DB41412 -> 0x00007FF62DB4142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3ce6]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4143C;
    } else {
        goto loc_7FF62DB4142F;
    }

loc_7FF62DB4142F:
    // --- Basic Block 5 (0x00007FF62DB4142F -> 0x00007FF62DB4143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4143C:
    // --- Basic Block 6 (0x00007FF62DB4143C -> 0x00007FF62DB41450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3dec]
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41456;
    } else {
        goto loc_7FF62DB41450;
    }

loc_7FF62DB41450:
    // --- Basic Block 7 (0x00007FF62DB41450 -> 0x00007FF62DB41456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB41456:
    // --- Basic Block 8 (0x00007FF62DB41456 -> 0x00007FF62DB4146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45108(); // qword ptr [rip + 0x3ca2]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB4146B;
    }

loc_7FF62DB4146B:
    // --- Basic Block 9 (0x00007FF62DB4146B -> 0x00007FF62DB41470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF62DB4148F;
    } else {
        goto loc_7FF62DB41470;
    }

loc_7FF62DB41470:
    // --- Basic Block 10 (0x00007FF62DB41470 -> 0x00007FF62DB4148F) ---
    rcx, rax; // mov
    rax_result = sub_7FF62DB45168(); // qword ptr [rip + 0x3cef]
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45238(); // qword ptr [rip + 0x3daf]
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF62DB41496;

loc_7FF62DB4148F:
    // --- Basic Block 11 (0x00007FF62DB4148F -> 0x00007FF62DB41496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF62DB41496:
    // --- Basic Block 12 (0x00007FF62DB41496 -> 0x00007FF62DB4149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB414A5;
    } else {
        goto loc_7FF62DB4149A;
    }

loc_7FF62DB4149A:
    // --- Basic Block 13 (0x00007FF62DB4149A -> 0x00007FF62DB414A5) ---
    r14d, 4; // mov
    goto loc_7FF62DB415C2;

loc_7FF62DB414A5:
    // --- Basic Block 14 (0x00007FF62DB414A5 -> 0x00007FF62DB414C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45230(); // qword ptr [rip + 0x3d7b]
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF62DB41578;
    } else {
        goto loc_7FF62DB414C3;
    }

loc_7FF62DB414C3:
    // --- Basic Block 15 (0x00007FF62DB414C3 -> 0x00007FF62DB414CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41573;
    } else {
        goto loc_7FF62DB414CC;
    }

loc_7FF62DB414CC:
    // --- Basic Block 16 (0x00007FF62DB414CC -> 0x00007FF62DB41501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3c35]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3c21]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3c44]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB4156B;
    } else {
        goto loc_7FF62DB41501;
    }

loc_7FF62DB41501:
    // --- Basic Block 17 (0x00007FF62DB41501 -> 0x00007FF62DB41510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41510:
    // --- Basic Block 18 (0x00007FF62DB41510 -> 0x00007FF62DB41515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF62DB41556;
    } else {
        goto loc_7FF62DB41515;
    }

loc_7FF62DB41515:
    // --- Basic Block 19 (0x00007FF62DB41515 -> 0x00007FF62DB4154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = sub_7FF62DB45118(); // qword ptr [rip + 0x3bec]
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3bd8]
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = sub_7FF62DB45140(); // qword ptr [rip + 0x3bfb]
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB415A8;
    } else {
        goto loc_7FF62DB4154A;
    }

loc_7FF62DB4154A:
    // --- Basic Block 20 (0x00007FF62DB4154A -> 0x00007FF62DB4154E) ---
    // asm: or r14d, 4

loc_7FF62DB4154E:
    // --- Basic Block 21 (0x00007FF62DB4154E -> 0x00007FF62DB41556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF62DB41556:
    // --- Basic Block 22 (0x00007FF62DB41556 -> 0x00007FF62DB4156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = sub_7FF62DB45210(); // qword ptr [rip + 0x3ca8]
    goto loc_7FF62DB415C2;

loc_7FF62DB4156B:
    // --- Basic Block 23 (0x00007FF62DB4156B -> 0x00007FF62DB41573) ---
    // asm: dec r15
    goto loc_7FF62DB414C3;

loc_7FF62DB41573:
    // --- Basic Block 24 (0x00007FF62DB41573 -> 0x00007FF62DB41578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF62DB41578:
    // --- Basic Block 25 (0x00007FF62DB41578 -> 0x00007FF62DB415A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b88]
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF62DB451E0(); // qword ptr [rip + 0x3c49]
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF62DB41510;
    } else {
        goto loc_7FF62DB415A0;
    }

loc_7FF62DB415A0:
    // --- Basic Block 26 (0x00007FF62DB415A0 -> 0x00007FF62DB415A8) ---
    r14d, 4; // mov
    goto loc_7FF62DB4154E;

loc_7FF62DB415A8:
    // --- Basic Block 27 (0x00007FF62DB415A8 -> 0x00007FF62DB415B0) ---
    // asm: dec r15
    goto loc_7FF62DB41510;

loc_7FF62DB415B0:
    // --- Basic Block 28 (0x00007FF62DB415B0 -> 0x00007FF62DB415C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF62DB415C2:
    // --- Basic Block 29 (0x00007FF62DB415C2 -> 0x00007FF62DB415E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3b28]
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB415EC;
    } else {
        goto loc_7FF62DB415E2;
    }

loc_7FF62DB415E2:
    // --- Basic Block 30 (0x00007FF62DB415E2 -> 0x00007FF62DB415EC) ---
    rcx, r12; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x3b5d]

loc_7FF62DB415EC:
    // --- Basic Block 31 (0x00007FF62DB415EC -> 0x00007FF62DB41602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3b13]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB4160F;
    } else {
        goto loc_7FF62DB41602;
    }

loc_7FF62DB41602:
    // --- Basic Block 32 (0x00007FF62DB41602 -> 0x00007FF62DB4160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB4160F:
    // --- Basic Block 33 (0x00007FF62DB4160F -> 0x00007FF62DB41622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF62DB41622:
    // --- Basic Block 34 (0x00007FF62DB41622 -> 0x00007FF62DB41684) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbx; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x40
    // asm: movzx r15d, r8b
    r14, rdx; // mov
    rdi, rcx; // mov
    ebx = 0;
    dword ptr [rsp + 0x20], ebx; // mov
    sil = 0;
    byte ptr [rsp + 0x88], sil; // mov
    r12, rcx; // mov
    qword ptr [rsp + 0x28], rcx; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a91]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41691;
    } else {
        goto loc_7FF62DB41684;
    }

loc_7FF62DB41684:
    // --- Basic Block 35 (0x00007FF62DB41684 -> 0x00007FF62DB41691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41691:
    // --- Basic Block 36 (0x00007FF62DB41691 -> 0x00007FF62DB416A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB45170(); // qword ptr [rip + 0x3ad4]
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF62DB41774;
    } else {
        goto loc_7FF62DB416A8;
    }

loc_7FF62DB416A8:
    // --- Basic Block 37 (0x00007FF62DB416A8 -> 0x00007FF62DB416B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB416B9;
    } else {
        goto loc_7FF62DB416B6;
    }

loc_7FF62DB416B6:
    // --- Basic Block 38 (0x00007FF62DB416B6 -> 0x00007FF62DB416B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF62DB416B9:
    // --- Basic Block 39 (0x00007FF62DB416B9 -> 0x00007FF62DB416E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a44]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F0(); // qword ptr [rip + 0x3b1b]
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF62DB416E0:
    // --- Basic Block 40 (0x00007FF62DB416E0 -> 0x00007FF62DB416E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB416EC;
    } else {
        goto loc_7FF62DB416E5;
    }

loc_7FF62DB416E5:
    // --- Basic Block 41 (0x00007FF62DB416E5 -> 0x00007FF62DB416EC) ---
    ebx, 1; // mov
    goto loc_7FF62DB41722;

loc_7FF62DB416EC:
    // --- Basic Block 42 (0x00007FF62DB416EC -> 0x00007FF62DB416F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF62DB41717;
    } else {
        goto loc_7FF62DB416F1;
    }

loc_7FF62DB416F1:
    // --- Basic Block 43 (0x00007FF62DB416F1 -> 0x00007FF62DB41717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a04]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F8(); // qword ptr [rip + 0x3ae3]
    goto loc_7FF62DB41726;

loc_7FF62DB41717:
    // --- Basic Block 44 (0x00007FF62DB41717 -> 0x00007FF62DB4171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF62DB41728;
    } else {
        goto loc_7FF62DB4171D;
    }

loc_7FF62DB4171D:
    // --- Basic Block 45 (0x00007FF62DB4171D -> 0x00007FF62DB41722) ---
    ebx, 2; // mov

loc_7FF62DB41722:
    // --- Basic Block 46 (0x00007FF62DB41722 -> 0x00007FF62DB41726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF62DB41726:
    // --- Basic Block 47 (0x00007FF62DB41726 -> 0x00007FF62DB41728) ---
    goto loc_7FF62DB4176F;

loc_7FF62DB41728:
    // --- Basic Block 48 (0x00007FF62DB41728 -> 0x00007FF62DB41759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF62DB424C0(); // 0x7ff62db424c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x39c2]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451E8(); // qword ptr [rip + 0x3a91]
    goto loc_7FF62DB416E0;

loc_7FF62DB41759:
    // --- Basic Block 49 (0x00007FF62DB41759 -> 0x00007FF62DB4176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF62DB4176F:
    // --- Basic Block 50 (0x00007FF62DB4176F -> 0x00007FF62DB41774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF62DB41777;
    } else {
        goto loc_7FF62DB41774;
    }

loc_7FF62DB41774:
    // --- Basic Block 51 (0x00007FF62DB41774 -> 0x00007FF62DB41777) ---
    // asm: or ebx, 2

loc_7FF62DB41777:
    // --- Basic Block 52 (0x00007FF62DB41777 -> 0x00007FF62DB417A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3974]
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3972]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB417B0;
    } else {
        goto loc_7FF62DB417A3;
    }

loc_7FF62DB417A3:
    // --- Basic Block 53 (0x00007FF62DB417A3 -> 0x00007FF62DB417B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB417B0:
    // --- Basic Block 54 (0x00007FF62DB417B0 -> 0x00007FF62DB417CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF62DB417CE:
    // --- Basic Block 55 (0x00007FF62DB417CE -> 0x00007FF62DB4180C) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4180C:
    // --- Basic Block 56 (0x00007FF62DB4180C -> 0x00007FF62DB4184C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 57 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 58 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB418B2:
    // --- Basic Block 59 (0x00007FF62DB418B2 -> 0x00007FF62DB418C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF62DB42020;

loc_7FF62DB418C5:
    // --- Basic Block 60 (0x00007FF62DB418C5 -> 0x00007FF62DB418F2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x30
    // asm: test byte ptr [rcx + 0x70], 1
    rax, [rip + 0x3cc6]; // lea
    qword ptr [rcx], rax; // mov
    rbx, rcx; // mov
    if (je_condition) {
        goto loc_7FF62DB41955;
    } else {
        goto loc_7FF62DB418F2;
    }

loc_7FF62DB418F2:
    // --- Basic Block 61 (0x00007FF62DB418F2 -> 0x00007FF62DB41900) ---
    rax_result = sub_7FF62DB450B8(); // qword ptr [rip + 0x37c0]
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41908;
    } else {
        goto loc_7FF62DB41900;
    }

loc_7FF62DB41900:
    // --- Basic Block 62 (0x00007FF62DB41900 -> 0x00007FF62DB41908) ---
    rax_result = sub_7FF62DB450D8(); // qword ptr [rip + 0x37d2]
    goto loc_7FF62DB4190E;

loc_7FF62DB41908:
    // --- Basic Block 63 (0x00007FF62DB41908 -> 0x00007FF62DB4190E) ---
    rax_result = sub_7FF62DB450C0(); // qword ptr [rip + 0x37b2]

loc_7FF62DB4190E:
    // --- Basic Block 64 (0x00007FF62DB4190E -> 0x00007FF62DB41932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x3786]
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x377a]
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB4194A;
    } else {
        goto loc_7FF62DB41932;
    }

loc_7FF62DB41932:
    // --- Basic Block 65 (0x00007FF62DB41932 -> 0x00007FF62DB41947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF62DB41999;
    } else {
        goto loc_7FF62DB41947;
    }

loc_7FF62DB41947:
    // --- Basic Block 66 (0x00007FF62DB41947 -> 0x00007FF62DB4194A) ---
    rdi, rax; // mov

loc_7FF62DB4194A:
    // --- Basic Block 67 (0x00007FF62DB4194A -> 0x00007FF62DB41955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41955:
    // --- Basic Block 68 (0x00007FF62DB41955 -> 0x00007FF62DB41999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450D0(); // qword ptr [rip + 0x376a]
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450E0(); // qword ptr [rip + 0x376c]
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_7FF62DB45200;

loc_7FF62DB41999:
    // --- Basic Block 69 (0x00007FF62DB41999 -> 0x00007FF62DB419DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x39ce]
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3739]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB419E9;
    } else {
        goto loc_7FF62DB419DC;
    }

loc_7FF62DB419DC:
    // --- Basic Block 70 (0x00007FF62DB419DC -> 0x00007FF62DB419E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB419E9:
    // --- Basic Block 71 (0x00007FF62DB419E9 -> 0x00007FF62DB419EE) ---
    // asm: add rsp, 0x28
    return rax_result;

}
```

### Function `sub_00007FF62DB41630` (0x7FF62DB41630)
- **Size**: `1506 bytes` | **Complexity V(G)**: `10` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB41630 | Address: 0x00007FF62DB41630
// Size: 1506 bytes | Basic Blocks: 59 | Complexity V(G): 10
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB41630(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB41630:
    // --- Basic Block 0 (0x00007FF62DB41630 -> 0x00007FF62DB41684) ---
    qword ptr [rsp + 0x10], rbx; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x40
    // asm: movzx r15d, r8b
    r14, rdx; // mov
    rdi, rcx; // mov
    ebx = 0;
    dword ptr [rsp + 0x20], ebx; // mov
    sil = 0;
    byte ptr [rsp + 0x88], sil; // mov
    r12, rcx; // mov
    qword ptr [rsp + 0x28], rcx; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a91]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41691;
    } else {
        goto loc_7FF62DB41684;
    }

loc_7FF62DB41684:
    // --- Basic Block 1 (0x00007FF62DB41684 -> 0x00007FF62DB41691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41691:
    // --- Basic Block 2 (0x00007FF62DB41691 -> 0x00007FF62DB416A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB45170(); // qword ptr [rip + 0x3ad4]
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF62DB41774;
    } else {
        goto loc_7FF62DB416A8;
    }

loc_7FF62DB416A8:
    // --- Basic Block 3 (0x00007FF62DB416A8 -> 0x00007FF62DB416B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB416B9;
    } else {
        goto loc_7FF62DB416B6;
    }

loc_7FF62DB416B6:
    // --- Basic Block 4 (0x00007FF62DB416B6 -> 0x00007FF62DB416B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF62DB416B9:
    // --- Basic Block 5 (0x00007FF62DB416B9 -> 0x00007FF62DB416E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a44]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F0(); // qword ptr [rip + 0x3b1b]
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF62DB416E0:
    // --- Basic Block 6 (0x00007FF62DB416E0 -> 0x00007FF62DB416E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB416EC;
    } else {
        goto loc_7FF62DB416E5;
    }

loc_7FF62DB416E5:
    // --- Basic Block 7 (0x00007FF62DB416E5 -> 0x00007FF62DB416EC) ---
    ebx, 1; // mov
    goto loc_7FF62DB41722;

loc_7FF62DB416EC:
    // --- Basic Block 8 (0x00007FF62DB416EC -> 0x00007FF62DB416F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF62DB41717;
    } else {
        goto loc_7FF62DB416F1;
    }

loc_7FF62DB416F1:
    // --- Basic Block 9 (0x00007FF62DB416F1 -> 0x00007FF62DB41717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a04]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F8(); // qword ptr [rip + 0x3ae3]
    goto loc_7FF62DB41726;

loc_7FF62DB41717:
    // --- Basic Block 10 (0x00007FF62DB41717 -> 0x00007FF62DB4171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF62DB41728;
    } else {
        goto loc_7FF62DB4171D;
    }

loc_7FF62DB4171D:
    // --- Basic Block 11 (0x00007FF62DB4171D -> 0x00007FF62DB41722) ---
    ebx, 2; // mov

loc_7FF62DB41722:
    // --- Basic Block 12 (0x00007FF62DB41722 -> 0x00007FF62DB41726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF62DB41726:
    // --- Basic Block 13 (0x00007FF62DB41726 -> 0x00007FF62DB41728) ---
    goto loc_7FF62DB4176F;

loc_7FF62DB41728:
    // --- Basic Block 14 (0x00007FF62DB41728 -> 0x00007FF62DB41759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF62DB424C0(); // 0x7ff62db424c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x39c2]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451E8(); // qword ptr [rip + 0x3a91]
    goto loc_7FF62DB416E0;

loc_7FF62DB41759:
    // --- Basic Block 15 (0x00007FF62DB41759 -> 0x00007FF62DB4176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF62DB4176F:
    // --- Basic Block 16 (0x00007FF62DB4176F -> 0x00007FF62DB41774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF62DB41777;
    } else {
        goto loc_7FF62DB41774;
    }

loc_7FF62DB41774:
    // --- Basic Block 17 (0x00007FF62DB41774 -> 0x00007FF62DB41777) ---
    // asm: or ebx, 2

loc_7FF62DB41777:
    // --- Basic Block 18 (0x00007FF62DB41777 -> 0x00007FF62DB417A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3974]
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3972]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB417B0;
    } else {
        goto loc_7FF62DB417A3;
    }

loc_7FF62DB417A3:
    // --- Basic Block 19 (0x00007FF62DB417A3 -> 0x00007FF62DB417B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB417B0:
    // --- Basic Block 20 (0x00007FF62DB417B0 -> 0x00007FF62DB417CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF62DB417CE:
    // --- Basic Block 21 (0x00007FF62DB417CE -> 0x00007FF62DB4180C) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4180C:
    // --- Basic Block 22 (0x00007FF62DB4180C -> 0x00007FF62DB4184C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 23 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 24 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB418B2:
    // --- Basic Block 25 (0x00007FF62DB418B2 -> 0x00007FF62DB418C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF62DB42020;

loc_7FF62DB418C5:
    // --- Basic Block 26 (0x00007FF62DB418C5 -> 0x00007FF62DB418F2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x30
    // asm: test byte ptr [rcx + 0x70], 1
    rax, [rip + 0x3cc6]; // lea
    qword ptr [rcx], rax; // mov
    rbx, rcx; // mov
    if (je_condition) {
        goto loc_7FF62DB41955;
    } else {
        goto loc_7FF62DB418F2;
    }

loc_7FF62DB418F2:
    // --- Basic Block 27 (0x00007FF62DB418F2 -> 0x00007FF62DB41900) ---
    rax_result = sub_7FF62DB450B8(); // qword ptr [rip + 0x37c0]
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41908;
    } else {
        goto loc_7FF62DB41900;
    }

loc_7FF62DB41900:
    // --- Basic Block 28 (0x00007FF62DB41900 -> 0x00007FF62DB41908) ---
    rax_result = sub_7FF62DB450D8(); // qword ptr [rip + 0x37d2]
    goto loc_7FF62DB4190E;

loc_7FF62DB41908:
    // --- Basic Block 29 (0x00007FF62DB41908 -> 0x00007FF62DB4190E) ---
    rax_result = sub_7FF62DB450C0(); // qword ptr [rip + 0x37b2]

loc_7FF62DB4190E:
    // --- Basic Block 30 (0x00007FF62DB4190E -> 0x00007FF62DB41932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x3786]
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x377a]
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB4194A;
    } else {
        goto loc_7FF62DB41932;
    }

loc_7FF62DB41932:
    // --- Basic Block 31 (0x00007FF62DB41932 -> 0x00007FF62DB41947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF62DB41999;
    } else {
        goto loc_7FF62DB41947;
    }

loc_7FF62DB41947:
    // --- Basic Block 32 (0x00007FF62DB41947 -> 0x00007FF62DB4194A) ---
    rdi, rax; // mov

loc_7FF62DB4194A:
    // --- Basic Block 33 (0x00007FF62DB4194A -> 0x00007FF62DB41955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41955:
    // --- Basic Block 34 (0x00007FF62DB41955 -> 0x00007FF62DB41999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450D0(); // qword ptr [rip + 0x376a]
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450E0(); // qword ptr [rip + 0x376c]
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_7FF62DB45200;

loc_7FF62DB41999:
    // --- Basic Block 35 (0x00007FF62DB41999 -> 0x00007FF62DB419DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x39ce]
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3739]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB419E9;
    } else {
        goto loc_7FF62DB419DC;
    }

loc_7FF62DB419DC:
    // --- Basic Block 36 (0x00007FF62DB419DC -> 0x00007FF62DB419E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB419E9:
    // --- Basic Block 37 (0x00007FF62DB419E9 -> 0x00007FF62DB419EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB419EE:
    // --- Basic Block 38 (0x00007FF62DB419EE -> 0x00007FF62DB41A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF62DB440EC;

loc_7FF62DB41A03:
    // --- Basic Block 39 (0x00007FF62DB41A03 -> 0x00007FF62DB41A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36e9]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A39;
    } else {
        goto loc_7FF62DB41A2C;
    }

loc_7FF62DB41A2C:
    // --- Basic Block 40 (0x00007FF62DB41A2C -> 0x00007FF62DB41A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A39:
    // --- Basic Block 41 (0x00007FF62DB41A39 -> 0x00007FF62DB41A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB41A3E:
    // --- Basic Block 42 (0x00007FF62DB41A3E -> 0x00007FF62DB41A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41A5C;
    } else {
        goto loc_7FF62DB41A52;
    }

loc_7FF62DB41A52:
    // --- Basic Block 43 (0x00007FF62DB41A52 -> 0x00007FF62DB41A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x36ed]

loc_7FF62DB41A5C:
    // --- Basic Block 44 (0x00007FF62DB41A5C -> 0x00007FF62DB41A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36a1]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A81;
    } else {
        goto loc_7FF62DB41A74;
    }

loc_7FF62DB41A74:
    // --- Basic Block 45 (0x00007FF62DB41A74 -> 0x00007FF62DB41A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A81:
    // --- Basic Block 46 (0x00007FF62DB41A81 -> 0x00007FF62DB41A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41A87:
    // --- Basic Block 47 (0x00007FF62DB41A87 -> 0x00007FF62DB41AEB) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rax, qword ptr [rcx]; // mov
    rbx, [rcx + 0x88]; // lea
    // asm: movsxd rdx, dword ptr [rax + 4]
    rax, [rip + 0x3b85]; // lea
    qword ptr [rdx + rbx - 0x88], rax; // mov
    rax, qword ptr [rcx]; // mov
    // asm: add rcx, 8
    // asm: movsxd rdx, dword ptr [rax + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rdx + rbx - 0x8c], r8d; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x377c]
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_7FF62DB450F8;

loc_7FF62DB41AEB:
    // --- Basic Block 48 (0x00007FF62DB41AEB -> 0x00007FF62DB41AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF62DB41B00;

loc_7FF62DB41AF8:
    // --- Basic Block 49 (0x00007FF62DB41AF8 -> 0x00007FF62DB41B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF62DB41B00:
    // --- Basic Block 50 (0x00007FF62DB41B00 -> 0x00007FF62DB41B69) ---
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x20
    rsi, [rcx - 0x88]; // lea
    rbx, rcx; // mov
    rax, qword ptr [rsi]; // mov
    edi, edx; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    rax, [rip + 0x3b07]; // lea
    qword ptr [r8 + rcx - 0x88], rax; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    r9d, [r8 - 0x88]; // lea
    dword ptr [r8 + rcx - 0x8c], r9d; // mov
    rcx, [rsi + 8]; // lea
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x36fe]
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450F8(); // qword ptr [rip + 0x3595]
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF62DB41B76;
    } else {
        goto loc_7FF62DB41B69;
    }

loc_7FF62DB41B69:
    // --- Basic Block 51 (0x00007FF62DB41B69 -> 0x00007FF62DB41B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41B76:
    // --- Basic Block 52 (0x00007FF62DB41B76 -> 0x00007FF62DB41B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41B89:
    // --- Basic Block 53 (0x00007FF62DB41B89 -> 0x00007FF62DB41BA9) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41BB6;
    } else {
        goto loc_7FF62DB41BA9;
    }

loc_7FF62DB41BA9:
    // --- Basic Block 54 (0x00007FF62DB41BA9 -> 0x00007FF62DB41BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41BB6:
    // --- Basic Block 55 (0x00007FF62DB41BB6 -> 0x00007FF62DB41BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41BC4:
    // --- Basic Block 56 (0x00007FF62DB41BC4 -> 0x00007FF62DB41BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    rax, [rip + 0x3947]; // lea
    rdi, rcx; // mov
    qword ptr [rcx], rax; // mov
    ebx, edx; // mov
    // asm: add rcx, 8
    rax_result = sub_7FF62DB440EC(); // 0x7ff62db440ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41C04;
    } else {
        goto loc_7FF62DB41BF7;
    }

loc_7FF62DB41BF7:
    // --- Basic Block 57 (0x00007FF62DB41BF7 -> 0x00007FF62DB41C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41C04:
    // --- Basic Block 58 (0x00007FF62DB41C04 -> 0x00007FF62DB41C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF62DB41647` (0x7FF62DB41647)
- **Size**: `1483 bytes` | **Complexity V(G)**: `10` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB41647 | Address: 0x00007FF62DB41647
// Size: 1483 bytes | Basic Blocks: 59 | Complexity V(G): 10
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB41647(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB41647:
    // --- Basic Block 0 (0x00007FF62DB41647 -> 0x00007FF62DB41684) ---
    // asm: sub rsp, 0x40
    // asm: movzx r15d, r8b
    r14, rdx; // mov
    rdi, rcx; // mov
    ebx = 0;
    dword ptr [rsp + 0x20], ebx; // mov
    sil = 0;
    byte ptr [rsp + 0x88], sil; // mov
    r12, rcx; // mov
    qword ptr [rsp + 0x28], rcx; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a91]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41691;
    } else {
        goto loc_7FF62DB41684;
    }

loc_7FF62DB41684:
    // --- Basic Block 1 (0x00007FF62DB41684 -> 0x00007FF62DB41691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41691:
    // --- Basic Block 2 (0x00007FF62DB41691 -> 0x00007FF62DB416A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB45170(); // qword ptr [rip + 0x3ad4]
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF62DB41774;
    } else {
        goto loc_7FF62DB416A8;
    }

loc_7FF62DB416A8:
    // --- Basic Block 3 (0x00007FF62DB416A8 -> 0x00007FF62DB416B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB416B9;
    } else {
        goto loc_7FF62DB416B6;
    }

loc_7FF62DB416B6:
    // --- Basic Block 4 (0x00007FF62DB416B6 -> 0x00007FF62DB416B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF62DB416B9:
    // --- Basic Block 5 (0x00007FF62DB416B9 -> 0x00007FF62DB416E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a44]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F0(); // qword ptr [rip + 0x3b1b]
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF62DB416E0:
    // --- Basic Block 6 (0x00007FF62DB416E0 -> 0x00007FF62DB416E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF62DB416EC;
    } else {
        goto loc_7FF62DB416E5;
    }

loc_7FF62DB416E5:
    // --- Basic Block 7 (0x00007FF62DB416E5 -> 0x00007FF62DB416EC) ---
    ebx, 1; // mov
    goto loc_7FF62DB41722;

loc_7FF62DB416EC:
    // --- Basic Block 8 (0x00007FF62DB416EC -> 0x00007FF62DB416F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF62DB41717;
    } else {
        goto loc_7FF62DB416F1;
    }

loc_7FF62DB416F1:
    // --- Basic Block 9 (0x00007FF62DB416F1 -> 0x00007FF62DB41717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3a04]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451F8(); // qword ptr [rip + 0x3ae3]
    goto loc_7FF62DB41726;

loc_7FF62DB41717:
    // --- Basic Block 10 (0x00007FF62DB41717 -> 0x00007FF62DB4171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF62DB41728;
    } else {
        goto loc_7FF62DB4171D;
    }

loc_7FF62DB4171D:
    // --- Basic Block 11 (0x00007FF62DB4171D -> 0x00007FF62DB41722) ---
    ebx, 2; // mov

loc_7FF62DB41722:
    // --- Basic Block 12 (0x00007FF62DB41722 -> 0x00007FF62DB41726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF62DB41726:
    // --- Basic Block 13 (0x00007FF62DB41726 -> 0x00007FF62DB41728) ---
    goto loc_7FF62DB4176F;

loc_7FF62DB41728:
    // --- Basic Block 14 (0x00007FF62DB41728 -> 0x00007FF62DB41759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF62DB424C0(); // 0x7ff62db424c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x39c2]
    rcx, rax; // mov
    rax_result = sub_7FF62DB451E8(); // qword ptr [rip + 0x3a91]
    goto loc_7FF62DB416E0;

loc_7FF62DB41759:
    // --- Basic Block 15 (0x00007FF62DB41759 -> 0x00007FF62DB4176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF62DB4176F:
    // --- Basic Block 16 (0x00007FF62DB4176F -> 0x00007FF62DB41774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF62DB41777;
    } else {
        goto loc_7FF62DB41774;
    }

loc_7FF62DB41774:
    // --- Basic Block 17 (0x00007FF62DB41774 -> 0x00007FF62DB41777) ---
    // asm: or ebx, 2

loc_7FF62DB41777:
    // --- Basic Block 18 (0x00007FF62DB41777 -> 0x00007FF62DB417A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = sub_7FF62DB45100(); // qword ptr [rip + 0x3974]
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3972]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB417B0;
    } else {
        goto loc_7FF62DB417A3;
    }

loc_7FF62DB417A3:
    // --- Basic Block 19 (0x00007FF62DB417A3 -> 0x00007FF62DB417B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB417B0:
    // --- Basic Block 20 (0x00007FF62DB417B0 -> 0x00007FF62DB417CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF62DB417CE:
    // --- Basic Block 21 (0x00007FF62DB417CE -> 0x00007FF62DB4180C) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4180C:
    // --- Basic Block 22 (0x00007FF62DB4180C -> 0x00007FF62DB4184C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 23 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 24 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB418B2:
    // --- Basic Block 25 (0x00007FF62DB418B2 -> 0x00007FF62DB418C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF62DB42020;

loc_7FF62DB418C5:
    // --- Basic Block 26 (0x00007FF62DB418C5 -> 0x00007FF62DB418F2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x30
    // asm: test byte ptr [rcx + 0x70], 1
    rax, [rip + 0x3cc6]; // lea
    qword ptr [rcx], rax; // mov
    rbx, rcx; // mov
    if (je_condition) {
        goto loc_7FF62DB41955;
    } else {
        goto loc_7FF62DB418F2;
    }

loc_7FF62DB418F2:
    // --- Basic Block 27 (0x00007FF62DB418F2 -> 0x00007FF62DB41900) ---
    rax_result = sub_7FF62DB450B8(); // qword ptr [rip + 0x37c0]
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41908;
    } else {
        goto loc_7FF62DB41900;
    }

loc_7FF62DB41900:
    // --- Basic Block 28 (0x00007FF62DB41900 -> 0x00007FF62DB41908) ---
    rax_result = sub_7FF62DB450D8(); // qword ptr [rip + 0x37d2]
    goto loc_7FF62DB4190E;

loc_7FF62DB41908:
    // --- Basic Block 29 (0x00007FF62DB41908 -> 0x00007FF62DB4190E) ---
    rax_result = sub_7FF62DB450C0(); // qword ptr [rip + 0x37b2]

loc_7FF62DB4190E:
    // --- Basic Block 30 (0x00007FF62DB4190E -> 0x00007FF62DB41932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x3786]
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x377a]
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB4194A;
    } else {
        goto loc_7FF62DB41932;
    }

loc_7FF62DB41932:
    // --- Basic Block 31 (0x00007FF62DB41932 -> 0x00007FF62DB41947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF62DB41999;
    } else {
        goto loc_7FF62DB41947;
    }

loc_7FF62DB41947:
    // --- Basic Block 32 (0x00007FF62DB41947 -> 0x00007FF62DB4194A) ---
    rdi, rax; // mov

loc_7FF62DB4194A:
    // --- Basic Block 33 (0x00007FF62DB4194A -> 0x00007FF62DB41955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41955:
    // --- Basic Block 34 (0x00007FF62DB41955 -> 0x00007FF62DB41999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450D0(); // qword ptr [rip + 0x376a]
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450E0(); // qword ptr [rip + 0x376c]
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_7FF62DB45200;

loc_7FF62DB41999:
    // --- Basic Block 35 (0x00007FF62DB41999 -> 0x00007FF62DB419DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x39ce]
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3739]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB419E9;
    } else {
        goto loc_7FF62DB419DC;
    }

loc_7FF62DB419DC:
    // --- Basic Block 36 (0x00007FF62DB419DC -> 0x00007FF62DB419E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB419E9:
    // --- Basic Block 37 (0x00007FF62DB419E9 -> 0x00007FF62DB419EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB419EE:
    // --- Basic Block 38 (0x00007FF62DB419EE -> 0x00007FF62DB41A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF62DB440EC;

loc_7FF62DB41A03:
    // --- Basic Block 39 (0x00007FF62DB41A03 -> 0x00007FF62DB41A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36e9]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A39;
    } else {
        goto loc_7FF62DB41A2C;
    }

loc_7FF62DB41A2C:
    // --- Basic Block 40 (0x00007FF62DB41A2C -> 0x00007FF62DB41A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A39:
    // --- Basic Block 41 (0x00007FF62DB41A39 -> 0x00007FF62DB41A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB41A3E:
    // --- Basic Block 42 (0x00007FF62DB41A3E -> 0x00007FF62DB41A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41A5C;
    } else {
        goto loc_7FF62DB41A52;
    }

loc_7FF62DB41A52:
    // --- Basic Block 43 (0x00007FF62DB41A52 -> 0x00007FF62DB41A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x36ed]

loc_7FF62DB41A5C:
    // --- Basic Block 44 (0x00007FF62DB41A5C -> 0x00007FF62DB41A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36a1]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A81;
    } else {
        goto loc_7FF62DB41A74;
    }

loc_7FF62DB41A74:
    // --- Basic Block 45 (0x00007FF62DB41A74 -> 0x00007FF62DB41A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A81:
    // --- Basic Block 46 (0x00007FF62DB41A81 -> 0x00007FF62DB41A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41A87:
    // --- Basic Block 47 (0x00007FF62DB41A87 -> 0x00007FF62DB41AEB) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rax, qword ptr [rcx]; // mov
    rbx, [rcx + 0x88]; // lea
    // asm: movsxd rdx, dword ptr [rax + 4]
    rax, [rip + 0x3b85]; // lea
    qword ptr [rdx + rbx - 0x88], rax; // mov
    rax, qword ptr [rcx]; // mov
    // asm: add rcx, 8
    // asm: movsxd rdx, dword ptr [rax + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rdx + rbx - 0x8c], r8d; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x377c]
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_7FF62DB450F8;

loc_7FF62DB41AEB:
    // --- Basic Block 48 (0x00007FF62DB41AEB -> 0x00007FF62DB41AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF62DB41B00;

loc_7FF62DB41AF8:
    // --- Basic Block 49 (0x00007FF62DB41AF8 -> 0x00007FF62DB41B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF62DB41B00:
    // --- Basic Block 50 (0x00007FF62DB41B00 -> 0x00007FF62DB41B69) ---
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x20
    rsi, [rcx - 0x88]; // lea
    rbx, rcx; // mov
    rax, qword ptr [rsi]; // mov
    edi, edx; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    rax, [rip + 0x3b07]; // lea
    qword ptr [r8 + rcx - 0x88], rax; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    r9d, [r8 - 0x88]; // lea
    dword ptr [r8 + rcx - 0x8c], r9d; // mov
    rcx, [rsi + 8]; // lea
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x36fe]
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450F8(); // qword ptr [rip + 0x3595]
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF62DB41B76;
    } else {
        goto loc_7FF62DB41B69;
    }

loc_7FF62DB41B69:
    // --- Basic Block 51 (0x00007FF62DB41B69 -> 0x00007FF62DB41B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41B76:
    // --- Basic Block 52 (0x00007FF62DB41B76 -> 0x00007FF62DB41B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41B89:
    // --- Basic Block 53 (0x00007FF62DB41B89 -> 0x00007FF62DB41BA9) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41BB6;
    } else {
        goto loc_7FF62DB41BA9;
    }

loc_7FF62DB41BA9:
    // --- Basic Block 54 (0x00007FF62DB41BA9 -> 0x00007FF62DB41BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41BB6:
    // --- Basic Block 55 (0x00007FF62DB41BB6 -> 0x00007FF62DB41BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41BC4:
    // --- Basic Block 56 (0x00007FF62DB41BC4 -> 0x00007FF62DB41BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    rax, [rip + 0x3947]; // lea
    rdi, rcx; // mov
    qword ptr [rcx], rax; // mov
    ebx, edx; // mov
    // asm: add rcx, 8
    rax_result = sub_7FF62DB440EC(); // 0x7ff62db440ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41C04;
    } else {
        goto loc_7FF62DB41BF7;
    }

loc_7FF62DB41BF7:
    // --- Basic Block 57 (0x00007FF62DB41BF7 -> 0x00007FF62DB41C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41C04:
    // --- Basic Block 58 (0x00007FF62DB41C04 -> 0x00007FF62DB41C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF62DB417D0` (0x7FF62DB417D0)
- **Size**: `1321 bytes` | **Complexity V(G)**: `5` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB417D0 | Address: 0x00007FF62DB417D0
// Size: 1321 bytes | Basic Blocks: 45 | Complexity V(G): 5
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB417D0(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB417D0:
    // --- Basic Block 0 (0x00007FF62DB417D0 -> 0x00007FF62DB4180C) ---
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4180C:
    // --- Basic Block 1 (0x00007FF62DB4180C -> 0x00007FF62DB4184C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 2 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 3 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB418B2:
    // --- Basic Block 4 (0x00007FF62DB418B2 -> 0x00007FF62DB418C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF62DB42020;

loc_7FF62DB418C5:
    // --- Basic Block 5 (0x00007FF62DB418C5 -> 0x00007FF62DB418F2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x30
    // asm: test byte ptr [rcx + 0x70], 1
    rax, [rip + 0x3cc6]; // lea
    qword ptr [rcx], rax; // mov
    rbx, rcx; // mov
    if (je_condition) {
        goto loc_7FF62DB41955;
    } else {
        goto loc_7FF62DB418F2;
    }

loc_7FF62DB418F2:
    // --- Basic Block 6 (0x00007FF62DB418F2 -> 0x00007FF62DB41900) ---
    rax_result = sub_7FF62DB450B8(); // qword ptr [rip + 0x37c0]
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41908;
    } else {
        goto loc_7FF62DB41900;
    }

loc_7FF62DB41900:
    // --- Basic Block 7 (0x00007FF62DB41900 -> 0x00007FF62DB41908) ---
    rax_result = sub_7FF62DB450D8(); // qword ptr [rip + 0x37d2]
    goto loc_7FF62DB4190E;

loc_7FF62DB41908:
    // --- Basic Block 8 (0x00007FF62DB41908 -> 0x00007FF62DB4190E) ---
    rax_result = sub_7FF62DB450C0(); // qword ptr [rip + 0x37b2]

loc_7FF62DB4190E:
    // --- Basic Block 9 (0x00007FF62DB4190E -> 0x00007FF62DB41932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x3786]
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x377a]
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB4194A;
    } else {
        goto loc_7FF62DB41932;
    }

loc_7FF62DB41932:
    // --- Basic Block 10 (0x00007FF62DB41932 -> 0x00007FF62DB41947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF62DB41999;
    } else {
        goto loc_7FF62DB41947;
    }

loc_7FF62DB41947:
    // --- Basic Block 11 (0x00007FF62DB41947 -> 0x00007FF62DB4194A) ---
    rdi, rax; // mov

loc_7FF62DB4194A:
    // --- Basic Block 12 (0x00007FF62DB4194A -> 0x00007FF62DB41955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41955:
    // --- Basic Block 13 (0x00007FF62DB41955 -> 0x00007FF62DB41999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450D0(); // qword ptr [rip + 0x376a]
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450E0(); // qword ptr [rip + 0x376c]
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_7FF62DB45200;

loc_7FF62DB41999:
    // --- Basic Block 14 (0x00007FF62DB41999 -> 0x00007FF62DB419DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x39ce]
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3739]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB419E9;
    } else {
        goto loc_7FF62DB419DC;
    }

loc_7FF62DB419DC:
    // --- Basic Block 15 (0x00007FF62DB419DC -> 0x00007FF62DB419E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB419E9:
    // --- Basic Block 16 (0x00007FF62DB419E9 -> 0x00007FF62DB419EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB419EE:
    // --- Basic Block 17 (0x00007FF62DB419EE -> 0x00007FF62DB41A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF62DB440EC;

loc_7FF62DB41A03:
    // --- Basic Block 18 (0x00007FF62DB41A03 -> 0x00007FF62DB41A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36e9]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A39;
    } else {
        goto loc_7FF62DB41A2C;
    }

loc_7FF62DB41A2C:
    // --- Basic Block 19 (0x00007FF62DB41A2C -> 0x00007FF62DB41A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A39:
    // --- Basic Block 20 (0x00007FF62DB41A39 -> 0x00007FF62DB41A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB41A3E:
    // --- Basic Block 21 (0x00007FF62DB41A3E -> 0x00007FF62DB41A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41A5C;
    } else {
        goto loc_7FF62DB41A52;
    }

loc_7FF62DB41A52:
    // --- Basic Block 22 (0x00007FF62DB41A52 -> 0x00007FF62DB41A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x36ed]

loc_7FF62DB41A5C:
    // --- Basic Block 23 (0x00007FF62DB41A5C -> 0x00007FF62DB41A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36a1]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A81;
    } else {
        goto loc_7FF62DB41A74;
    }

loc_7FF62DB41A74:
    // --- Basic Block 24 (0x00007FF62DB41A74 -> 0x00007FF62DB41A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A81:
    // --- Basic Block 25 (0x00007FF62DB41A81 -> 0x00007FF62DB41A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41A87:
    // --- Basic Block 26 (0x00007FF62DB41A87 -> 0x00007FF62DB41AEB) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rax, qword ptr [rcx]; // mov
    rbx, [rcx + 0x88]; // lea
    // asm: movsxd rdx, dword ptr [rax + 4]
    rax, [rip + 0x3b85]; // lea
    qword ptr [rdx + rbx - 0x88], rax; // mov
    rax, qword ptr [rcx]; // mov
    // asm: add rcx, 8
    // asm: movsxd rdx, dword ptr [rax + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rdx + rbx - 0x8c], r8d; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x377c]
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_7FF62DB450F8;

loc_7FF62DB41AEB:
    // --- Basic Block 27 (0x00007FF62DB41AEB -> 0x00007FF62DB41AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF62DB41B00;

loc_7FF62DB41AF8:
    // --- Basic Block 28 (0x00007FF62DB41AF8 -> 0x00007FF62DB41B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF62DB41B00:
    // --- Basic Block 29 (0x00007FF62DB41B00 -> 0x00007FF62DB41B69) ---
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x20
    rsi, [rcx - 0x88]; // lea
    rbx, rcx; // mov
    rax, qword ptr [rsi]; // mov
    edi, edx; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    rax, [rip + 0x3b07]; // lea
    qword ptr [r8 + rcx - 0x88], rax; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    r9d, [r8 - 0x88]; // lea
    dword ptr [r8 + rcx - 0x8c], r9d; // mov
    rcx, [rsi + 8]; // lea
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x36fe]
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450F8(); // qword ptr [rip + 0x3595]
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF62DB41B76;
    } else {
        goto loc_7FF62DB41B69;
    }

loc_7FF62DB41B69:
    // --- Basic Block 30 (0x00007FF62DB41B69 -> 0x00007FF62DB41B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41B76:
    // --- Basic Block 31 (0x00007FF62DB41B76 -> 0x00007FF62DB41B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41B89:
    // --- Basic Block 32 (0x00007FF62DB41B89 -> 0x00007FF62DB41BA9) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41BB6;
    } else {
        goto loc_7FF62DB41BA9;
    }

loc_7FF62DB41BA9:
    // --- Basic Block 33 (0x00007FF62DB41BA9 -> 0x00007FF62DB41BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41BB6:
    // --- Basic Block 34 (0x00007FF62DB41BB6 -> 0x00007FF62DB41BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41BC4:
    // --- Basic Block 35 (0x00007FF62DB41BC4 -> 0x00007FF62DB41BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    rax, [rip + 0x3947]; // lea
    rdi, rcx; // mov
    qword ptr [rcx], rax; // mov
    ebx, edx; // mov
    // asm: add rcx, 8
    rax_result = sub_7FF62DB440EC(); // 0x7ff62db440ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41C04;
    } else {
        goto loc_7FF62DB41BF7;
    }

loc_7FF62DB41BF7:
    // --- Basic Block 36 (0x00007FF62DB41BF7 -> 0x00007FF62DB41C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41C04:
    // --- Basic Block 37 (0x00007FF62DB41C04 -> 0x00007FF62DB41C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41C12:
    // --- Basic Block 38 (0x00007FF62DB41C12 -> 0x00007FF62DB41C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x18], rbx; // mov
    qword ptr [rsp + 0x20], rbp; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    rbx, rdx; // mov
    rdi, rcx; // mov
    ebp = 0;
    dword ptr [rsp + 0x20], ebp; // mov
    // asm: xorps xmm0, xmm0
    // asm: movups xmmword ptr [rcx], xmm0
    qword ptr [rcx + 0x10], rbp; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    byte ptr [rcx], bpl; // mov
    dword ptr [rsp + 0x20], 1; // mov
    rsi, qword ptr [rip + 0x73a9]; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41C78;
    }

loc_7FF62DB41C78:
    // --- Basic Block 39 (0x00007FF62DB41C78 -> 0x00007FF62DB41C80) ---

loc_7FF62DB41C80:
    // --- Basic Block 40 (0x00007FF62DB41C80 -> 0x00007FF62DB41C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB41C8D;
    } else {
        goto loc_7FF62DB41C8A;
    }

loc_7FF62DB41C8A:
    // --- Basic Block 41 (0x00007FF62DB41C8A -> 0x00007FF62DB41C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF62DB41C8D:
    // --- Basic Block 42 (0x00007FF62DB41C8D -> 0x00007FF62DB41CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB431D0(); // 0x7ff62db431d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF62DB420C0(); // 0x7ff62db420c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41CDA;
    }

loc_7FF62DB41CDA:
    // --- Basic Block 43 (0x00007FF62DB41CDA -> 0x00007FF62DB41CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF62DB41C80;

loc_7FF62DB41CE3:
    // --- Basic Block 44 (0x00007FF62DB41CE3 -> 0x00007FF62DB41CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF62DB41810` (0x7FF62DB41810)
- **Size**: `1257 bytes` | **Complexity V(G)**: `6` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB41810 | Address: 0x00007FF62DB41810
// Size: 1257 bytes | Basic Blocks: 44 | Complexity V(G): 6
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB41810(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB41810:
    // --- Basic Block 0 (0x00007FF62DB41810 -> 0x00007FF62DB4184C) ---
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d05]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB4184C:
    // --- Basic Block 1 (0x00007FF62DB4184C -> 0x00007FF62DB41871) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 2 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB418B2:
    // --- Basic Block 3 (0x00007FF62DB418B2 -> 0x00007FF62DB418C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF62DB42020;

loc_7FF62DB418C5:
    // --- Basic Block 4 (0x00007FF62DB418C5 -> 0x00007FF62DB418F2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x30
    // asm: test byte ptr [rcx + 0x70], 1
    rax, [rip + 0x3cc6]; // lea
    qword ptr [rcx], rax; // mov
    rbx, rcx; // mov
    if (je_condition) {
        goto loc_7FF62DB41955;
    } else {
        goto loc_7FF62DB418F2;
    }

loc_7FF62DB418F2:
    // --- Basic Block 5 (0x00007FF62DB418F2 -> 0x00007FF62DB41900) ---
    rax_result = sub_7FF62DB450B8(); // qword ptr [rip + 0x37c0]
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41908;
    } else {
        goto loc_7FF62DB41900;
    }

loc_7FF62DB41900:
    // --- Basic Block 6 (0x00007FF62DB41900 -> 0x00007FF62DB41908) ---
    rax_result = sub_7FF62DB450D8(); // qword ptr [rip + 0x37d2]
    goto loc_7FF62DB4190E;

loc_7FF62DB41908:
    // --- Basic Block 7 (0x00007FF62DB41908 -> 0x00007FF62DB4190E) ---
    rax_result = sub_7FF62DB450C0(); // qword ptr [rip + 0x37b2]

loc_7FF62DB4190E:
    // --- Basic Block 8 (0x00007FF62DB4190E -> 0x00007FF62DB41932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x3786]
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x377a]
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB4194A;
    } else {
        goto loc_7FF62DB41932;
    }

loc_7FF62DB41932:
    // --- Basic Block 9 (0x00007FF62DB41932 -> 0x00007FF62DB41947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF62DB41999;
    } else {
        goto loc_7FF62DB41947;
    }

loc_7FF62DB41947:
    // --- Basic Block 10 (0x00007FF62DB41947 -> 0x00007FF62DB4194A) ---
    rdi, rax; // mov

loc_7FF62DB4194A:
    // --- Basic Block 11 (0x00007FF62DB4194A -> 0x00007FF62DB41955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41955:
    // --- Basic Block 12 (0x00007FF62DB41955 -> 0x00007FF62DB41999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450D0(); // qword ptr [rip + 0x376a]
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450E0(); // qword ptr [rip + 0x376c]
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_7FF62DB45200;

loc_7FF62DB41999:
    // --- Basic Block 13 (0x00007FF62DB41999 -> 0x00007FF62DB419DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x39ce]
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3739]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB419E9;
    } else {
        goto loc_7FF62DB419DC;
    }

loc_7FF62DB419DC:
    // --- Basic Block 14 (0x00007FF62DB419DC -> 0x00007FF62DB419E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB419E9:
    // --- Basic Block 15 (0x00007FF62DB419E9 -> 0x00007FF62DB419EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB419EE:
    // --- Basic Block 16 (0x00007FF62DB419EE -> 0x00007FF62DB41A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF62DB440EC;

loc_7FF62DB41A03:
    // --- Basic Block 17 (0x00007FF62DB41A03 -> 0x00007FF62DB41A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36e9]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A39;
    } else {
        goto loc_7FF62DB41A2C;
    }

loc_7FF62DB41A2C:
    // --- Basic Block 18 (0x00007FF62DB41A2C -> 0x00007FF62DB41A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A39:
    // --- Basic Block 19 (0x00007FF62DB41A39 -> 0x00007FF62DB41A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB41A3E:
    // --- Basic Block 20 (0x00007FF62DB41A3E -> 0x00007FF62DB41A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41A5C;
    } else {
        goto loc_7FF62DB41A52;
    }

loc_7FF62DB41A52:
    // --- Basic Block 21 (0x00007FF62DB41A52 -> 0x00007FF62DB41A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x36ed]

loc_7FF62DB41A5C:
    // --- Basic Block 22 (0x00007FF62DB41A5C -> 0x00007FF62DB41A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36a1]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A81;
    } else {
        goto loc_7FF62DB41A74;
    }

loc_7FF62DB41A74:
    // --- Basic Block 23 (0x00007FF62DB41A74 -> 0x00007FF62DB41A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A81:
    // --- Basic Block 24 (0x00007FF62DB41A81 -> 0x00007FF62DB41A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41A87:
    // --- Basic Block 25 (0x00007FF62DB41A87 -> 0x00007FF62DB41AEB) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rax, qword ptr [rcx]; // mov
    rbx, [rcx + 0x88]; // lea
    // asm: movsxd rdx, dword ptr [rax + 4]
    rax, [rip + 0x3b85]; // lea
    qword ptr [rdx + rbx - 0x88], rax; // mov
    rax, qword ptr [rcx]; // mov
    // asm: add rcx, 8
    // asm: movsxd rdx, dword ptr [rax + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rdx + rbx - 0x8c], r8d; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x377c]
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_7FF62DB450F8;

loc_7FF62DB41AEB:
    // --- Basic Block 26 (0x00007FF62DB41AEB -> 0x00007FF62DB41AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF62DB41B00;

loc_7FF62DB41AF8:
    // --- Basic Block 27 (0x00007FF62DB41AF8 -> 0x00007FF62DB41B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF62DB41B00:
    // --- Basic Block 28 (0x00007FF62DB41B00 -> 0x00007FF62DB41B69) ---
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x20
    rsi, [rcx - 0x88]; // lea
    rbx, rcx; // mov
    rax, qword ptr [rsi]; // mov
    edi, edx; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    rax, [rip + 0x3b07]; // lea
    qword ptr [r8 + rcx - 0x88], rax; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    r9d, [r8 - 0x88]; // lea
    dword ptr [r8 + rcx - 0x8c], r9d; // mov
    rcx, [rsi + 8]; // lea
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x36fe]
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450F8(); // qword ptr [rip + 0x3595]
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF62DB41B76;
    } else {
        goto loc_7FF62DB41B69;
    }

loc_7FF62DB41B69:
    // --- Basic Block 29 (0x00007FF62DB41B69 -> 0x00007FF62DB41B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41B76:
    // --- Basic Block 30 (0x00007FF62DB41B76 -> 0x00007FF62DB41B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41B89:
    // --- Basic Block 31 (0x00007FF62DB41B89 -> 0x00007FF62DB41BA9) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41BB6;
    } else {
        goto loc_7FF62DB41BA9;
    }

loc_7FF62DB41BA9:
    // --- Basic Block 32 (0x00007FF62DB41BA9 -> 0x00007FF62DB41BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41BB6:
    // --- Basic Block 33 (0x00007FF62DB41BB6 -> 0x00007FF62DB41BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41BC4:
    // --- Basic Block 34 (0x00007FF62DB41BC4 -> 0x00007FF62DB41BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    rax, [rip + 0x3947]; // lea
    rdi, rcx; // mov
    qword ptr [rcx], rax; // mov
    ebx, edx; // mov
    // asm: add rcx, 8
    rax_result = sub_7FF62DB440EC(); // 0x7ff62db440ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41C04;
    } else {
        goto loc_7FF62DB41BF7;
    }

loc_7FF62DB41BF7:
    // --- Basic Block 35 (0x00007FF62DB41BF7 -> 0x00007FF62DB41C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41C04:
    // --- Basic Block 36 (0x00007FF62DB41C04 -> 0x00007FF62DB41C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41C12:
    // --- Basic Block 37 (0x00007FF62DB41C12 -> 0x00007FF62DB41C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x18], rbx; // mov
    qword ptr [rsp + 0x20], rbp; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    rbx, rdx; // mov
    rdi, rcx; // mov
    ebp = 0;
    dword ptr [rsp + 0x20], ebp; // mov
    // asm: xorps xmm0, xmm0
    // asm: movups xmmword ptr [rcx], xmm0
    qword ptr [rcx + 0x10], rbp; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    byte ptr [rcx], bpl; // mov
    dword ptr [rsp + 0x20], 1; // mov
    rsi, qword ptr [rip + 0x73a9]; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41C78;
    }

loc_7FF62DB41C78:
    // --- Basic Block 38 (0x00007FF62DB41C78 -> 0x00007FF62DB41C80) ---

loc_7FF62DB41C80:
    // --- Basic Block 39 (0x00007FF62DB41C80 -> 0x00007FF62DB41C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB41C8D;
    } else {
        goto loc_7FF62DB41C8A;
    }

loc_7FF62DB41C8A:
    // --- Basic Block 40 (0x00007FF62DB41C8A -> 0x00007FF62DB41C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF62DB41C8D:
    // --- Basic Block 41 (0x00007FF62DB41C8D -> 0x00007FF62DB41CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB431D0(); // 0x7ff62db431d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF62DB420C0(); // 0x7ff62db420c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41CDA;
    }

loc_7FF62DB41CDA:
    // --- Basic Block 42 (0x00007FF62DB41CDA -> 0x00007FF62DB41CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF62DB41C80;

loc_7FF62DB41CE3:
    // --- Basic Block 43 (0x00007FF62DB41CE3 -> 0x00007FF62DB41CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF62DB41850` (0x7FF62DB41850)
- **Size**: `1193 bytes` | **Complexity V(G)**: `7` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB41850 | Address: 0x00007FF62DB41850
// Size: 1193 bytes | Basic Blocks: 43 | Complexity V(G): 7
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB41850(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB41850:
    // --- Basic Block 0 (0x00007FF62DB41850 -> 0x00007FF62DB41871) ---
    rax, [rip + 0x3d29]; // lea
    qword ptr [rcx + 0x10], 0; // mov
    qword ptr [rcx + 8], rax; // mov
    rax, [rip + 0x3d06]; // lea
    qword ptr [rcx], rax; // mov
    rax, rcx; // mov
    return rax_result;

loc_7FF62DB41871:
    // --- Basic Block 1 (0x00007FF62DB41871 -> 0x00007FF62DB418B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB418B2:
    // --- Basic Block 2 (0x00007FF62DB418B2 -> 0x00007FF62DB418C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF62DB42020;

loc_7FF62DB418C5:
    // --- Basic Block 3 (0x00007FF62DB418C5 -> 0x00007FF62DB418F2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x30
    // asm: test byte ptr [rcx + 0x70], 1
    rax, [rip + 0x3cc6]; // lea
    qword ptr [rcx], rax; // mov
    rbx, rcx; // mov
    if (je_condition) {
        goto loc_7FF62DB41955;
    } else {
        goto loc_7FF62DB418F2;
    }

loc_7FF62DB418F2:
    // --- Basic Block 4 (0x00007FF62DB418F2 -> 0x00007FF62DB41900) ---
    rax_result = sub_7FF62DB450B8(); // qword ptr [rip + 0x37c0]
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41908;
    } else {
        goto loc_7FF62DB41900;
    }

loc_7FF62DB41900:
    // --- Basic Block 5 (0x00007FF62DB41900 -> 0x00007FF62DB41908) ---
    rax_result = sub_7FF62DB450D8(); // qword ptr [rip + 0x37d2]
    goto loc_7FF62DB4190E;

loc_7FF62DB41908:
    // --- Basic Block 6 (0x00007FF62DB41908 -> 0x00007FF62DB4190E) ---
    rax_result = sub_7FF62DB450C0(); // qword ptr [rip + 0x37b2]

loc_7FF62DB4190E:
    // --- Basic Block 7 (0x00007FF62DB4190E -> 0x00007FF62DB41932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x3786]
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x377a]
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB4194A;
    } else {
        goto loc_7FF62DB41932;
    }

loc_7FF62DB41932:
    // --- Basic Block 8 (0x00007FF62DB41932 -> 0x00007FF62DB41947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF62DB41999;
    } else {
        goto loc_7FF62DB41947;
    }

loc_7FF62DB41947:
    // --- Basic Block 9 (0x00007FF62DB41947 -> 0x00007FF62DB4194A) ---
    rdi, rax; // mov

loc_7FF62DB4194A:
    // --- Basic Block 10 (0x00007FF62DB4194A -> 0x00007FF62DB41955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41955:
    // --- Basic Block 11 (0x00007FF62DB41955 -> 0x00007FF62DB41999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450D0(); // qword ptr [rip + 0x376a]
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450E0(); // qword ptr [rip + 0x376c]
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_7FF62DB45200;

loc_7FF62DB41999:
    // --- Basic Block 12 (0x00007FF62DB41999 -> 0x00007FF62DB419DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x39ce]
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3739]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB419E9;
    } else {
        goto loc_7FF62DB419DC;
    }

loc_7FF62DB419DC:
    // --- Basic Block 13 (0x00007FF62DB419DC -> 0x00007FF62DB419E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB419E9:
    // --- Basic Block 14 (0x00007FF62DB419E9 -> 0x00007FF62DB419EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB419EE:
    // --- Basic Block 15 (0x00007FF62DB419EE -> 0x00007FF62DB41A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF62DB440EC;

loc_7FF62DB41A03:
    // --- Basic Block 16 (0x00007FF62DB41A03 -> 0x00007FF62DB41A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36e9]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A39;
    } else {
        goto loc_7FF62DB41A2C;
    }

loc_7FF62DB41A2C:
    // --- Basic Block 17 (0x00007FF62DB41A2C -> 0x00007FF62DB41A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A39:
    // --- Basic Block 18 (0x00007FF62DB41A39 -> 0x00007FF62DB41A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB41A3E:
    // --- Basic Block 19 (0x00007FF62DB41A3E -> 0x00007FF62DB41A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41A5C;
    } else {
        goto loc_7FF62DB41A52;
    }

loc_7FF62DB41A52:
    // --- Basic Block 20 (0x00007FF62DB41A52 -> 0x00007FF62DB41A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x36ed]

loc_7FF62DB41A5C:
    // --- Basic Block 21 (0x00007FF62DB41A5C -> 0x00007FF62DB41A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36a1]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A81;
    } else {
        goto loc_7FF62DB41A74;
    }

loc_7FF62DB41A74:
    // --- Basic Block 22 (0x00007FF62DB41A74 -> 0x00007FF62DB41A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A81:
    // --- Basic Block 23 (0x00007FF62DB41A81 -> 0x00007FF62DB41A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41A87:
    // --- Basic Block 24 (0x00007FF62DB41A87 -> 0x00007FF62DB41AEB) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rax, qword ptr [rcx]; // mov
    rbx, [rcx + 0x88]; // lea
    // asm: movsxd rdx, dword ptr [rax + 4]
    rax, [rip + 0x3b85]; // lea
    qword ptr [rdx + rbx - 0x88], rax; // mov
    rax, qword ptr [rcx]; // mov
    // asm: add rcx, 8
    // asm: movsxd rdx, dword ptr [rax + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rdx + rbx - 0x8c], r8d; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x377c]
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_7FF62DB450F8;

loc_7FF62DB41AEB:
    // --- Basic Block 25 (0x00007FF62DB41AEB -> 0x00007FF62DB41AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF62DB41B00;

loc_7FF62DB41AF8:
    // --- Basic Block 26 (0x00007FF62DB41AF8 -> 0x00007FF62DB41B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF62DB41B00:
    // --- Basic Block 27 (0x00007FF62DB41B00 -> 0x00007FF62DB41B69) ---
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x20
    rsi, [rcx - 0x88]; // lea
    rbx, rcx; // mov
    rax, qword ptr [rsi]; // mov
    edi, edx; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    rax, [rip + 0x3b07]; // lea
    qword ptr [r8 + rcx - 0x88], rax; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    r9d, [r8 - 0x88]; // lea
    dword ptr [r8 + rcx - 0x8c], r9d; // mov
    rcx, [rsi + 8]; // lea
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x36fe]
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450F8(); // qword ptr [rip + 0x3595]
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF62DB41B76;
    } else {
        goto loc_7FF62DB41B69;
    }

loc_7FF62DB41B69:
    // --- Basic Block 28 (0x00007FF62DB41B69 -> 0x00007FF62DB41B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41B76:
    // --- Basic Block 29 (0x00007FF62DB41B76 -> 0x00007FF62DB41B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41B89:
    // --- Basic Block 30 (0x00007FF62DB41B89 -> 0x00007FF62DB41BA9) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41BB6;
    } else {
        goto loc_7FF62DB41BA9;
    }

loc_7FF62DB41BA9:
    // --- Basic Block 31 (0x00007FF62DB41BA9 -> 0x00007FF62DB41BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41BB6:
    // --- Basic Block 32 (0x00007FF62DB41BB6 -> 0x00007FF62DB41BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41BC4:
    // --- Basic Block 33 (0x00007FF62DB41BC4 -> 0x00007FF62DB41BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    rax, [rip + 0x3947]; // lea
    rdi, rcx; // mov
    qword ptr [rcx], rax; // mov
    ebx, edx; // mov
    // asm: add rcx, 8
    rax_result = sub_7FF62DB440EC(); // 0x7ff62db440ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41C04;
    } else {
        goto loc_7FF62DB41BF7;
    }

loc_7FF62DB41BF7:
    // --- Basic Block 34 (0x00007FF62DB41BF7 -> 0x00007FF62DB41C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41C04:
    // --- Basic Block 35 (0x00007FF62DB41C04 -> 0x00007FF62DB41C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41C12:
    // --- Basic Block 36 (0x00007FF62DB41C12 -> 0x00007FF62DB41C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x18], rbx; // mov
    qword ptr [rsp + 0x20], rbp; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    rbx, rdx; // mov
    rdi, rcx; // mov
    ebp = 0;
    dword ptr [rsp + 0x20], ebp; // mov
    // asm: xorps xmm0, xmm0
    // asm: movups xmmword ptr [rcx], xmm0
    qword ptr [rcx + 0x10], rbp; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    byte ptr [rcx], bpl; // mov
    dword ptr [rsp + 0x20], 1; // mov
    rsi, qword ptr [rip + 0x73a9]; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41C78;
    }

loc_7FF62DB41C78:
    // --- Basic Block 37 (0x00007FF62DB41C78 -> 0x00007FF62DB41C80) ---

loc_7FF62DB41C80:
    // --- Basic Block 38 (0x00007FF62DB41C80 -> 0x00007FF62DB41C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB41C8D;
    } else {
        goto loc_7FF62DB41C8A;
    }

loc_7FF62DB41C8A:
    // --- Basic Block 39 (0x00007FF62DB41C8A -> 0x00007FF62DB41C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF62DB41C8D:
    // --- Basic Block 40 (0x00007FF62DB41C8D -> 0x00007FF62DB41CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB431D0(); // 0x7ff62db431d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF62DB420C0(); // 0x7ff62db420c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41CDA;
    }

loc_7FF62DB41CDA:
    // --- Basic Block 41 (0x00007FF62DB41CDA -> 0x00007FF62DB41CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF62DB41C80;

loc_7FF62DB41CE3:
    // --- Basic Block 42 (0x00007FF62DB41CE3 -> 0x00007FF62DB41CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF62DB41880` (0x7FF62DB41880)
- **Size**: `1145 bytes` | **Complexity V(G)**: `8` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB41880 | Address: 0x00007FF62DB41880
// Size: 1145 bytes | Basic Blocks: 42 | Complexity V(G): 8
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB41880(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB41880:
    // --- Basic Block 0 (0x00007FF62DB41880 -> 0x00007FF62DB418B2) ---
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF62DB440E6(); // 0x7ff62db440e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB418B2:
    // --- Basic Block 1 (0x00007FF62DB418B2 -> 0x00007FF62DB418C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF62DB42020;

loc_7FF62DB418C5:
    // --- Basic Block 2 (0x00007FF62DB418C5 -> 0x00007FF62DB418F2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x30
    // asm: test byte ptr [rcx + 0x70], 1
    rax, [rip + 0x3cc6]; // lea
    qword ptr [rcx], rax; // mov
    rbx, rcx; // mov
    if (je_condition) {
        goto loc_7FF62DB41955;
    } else {
        goto loc_7FF62DB418F2;
    }

loc_7FF62DB418F2:
    // --- Basic Block 3 (0x00007FF62DB418F2 -> 0x00007FF62DB41900) ---
    rax_result = sub_7FF62DB450B8(); // qword ptr [rip + 0x37c0]
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41908;
    } else {
        goto loc_7FF62DB41900;
    }

loc_7FF62DB41900:
    // --- Basic Block 4 (0x00007FF62DB41900 -> 0x00007FF62DB41908) ---
    rax_result = sub_7FF62DB450D8(); // qword ptr [rip + 0x37d2]
    goto loc_7FF62DB4190E;

loc_7FF62DB41908:
    // --- Basic Block 5 (0x00007FF62DB41908 -> 0x00007FF62DB4190E) ---
    rax_result = sub_7FF62DB450C0(); // qword ptr [rip + 0x37b2]

loc_7FF62DB4190E:
    // --- Basic Block 6 (0x00007FF62DB4190E -> 0x00007FF62DB41932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x3786]
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x377a]
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB4194A;
    } else {
        goto loc_7FF62DB41932;
    }

loc_7FF62DB41932:
    // --- Basic Block 7 (0x00007FF62DB41932 -> 0x00007FF62DB41947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF62DB41999;
    } else {
        goto loc_7FF62DB41947;
    }

loc_7FF62DB41947:
    // --- Basic Block 8 (0x00007FF62DB41947 -> 0x00007FF62DB4194A) ---
    rdi, rax; // mov

loc_7FF62DB4194A:
    // --- Basic Block 9 (0x00007FF62DB4194A -> 0x00007FF62DB41955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41955:
    // --- Basic Block 10 (0x00007FF62DB41955 -> 0x00007FF62DB41999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450D0(); // qword ptr [rip + 0x376a]
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450E0(); // qword ptr [rip + 0x376c]
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_7FF62DB45200;

loc_7FF62DB41999:
    // --- Basic Block 11 (0x00007FF62DB41999 -> 0x00007FF62DB419DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x39ce]
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3739]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB419E9;
    } else {
        goto loc_7FF62DB419DC;
    }

loc_7FF62DB419DC:
    // --- Basic Block 12 (0x00007FF62DB419DC -> 0x00007FF62DB419E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB419E9:
    // --- Basic Block 13 (0x00007FF62DB419E9 -> 0x00007FF62DB419EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB419EE:
    // --- Basic Block 14 (0x00007FF62DB419EE -> 0x00007FF62DB41A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF62DB440EC;

loc_7FF62DB41A03:
    // --- Basic Block 15 (0x00007FF62DB41A03 -> 0x00007FF62DB41A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36e9]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A39;
    } else {
        goto loc_7FF62DB41A2C;
    }

loc_7FF62DB41A2C:
    // --- Basic Block 16 (0x00007FF62DB41A2C -> 0x00007FF62DB41A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A39:
    // --- Basic Block 17 (0x00007FF62DB41A39 -> 0x00007FF62DB41A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB41A3E:
    // --- Basic Block 18 (0x00007FF62DB41A3E -> 0x00007FF62DB41A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41A5C;
    } else {
        goto loc_7FF62DB41A52;
    }

loc_7FF62DB41A52:
    // --- Basic Block 19 (0x00007FF62DB41A52 -> 0x00007FF62DB41A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x36ed]

loc_7FF62DB41A5C:
    // --- Basic Block 20 (0x00007FF62DB41A5C -> 0x00007FF62DB41A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36a1]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A81;
    } else {
        goto loc_7FF62DB41A74;
    }

loc_7FF62DB41A74:
    // --- Basic Block 21 (0x00007FF62DB41A74 -> 0x00007FF62DB41A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A81:
    // --- Basic Block 22 (0x00007FF62DB41A81 -> 0x00007FF62DB41A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41A87:
    // --- Basic Block 23 (0x00007FF62DB41A87 -> 0x00007FF62DB41AEB) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rax, qword ptr [rcx]; // mov
    rbx, [rcx + 0x88]; // lea
    // asm: movsxd rdx, dword ptr [rax + 4]
    rax, [rip + 0x3b85]; // lea
    qword ptr [rdx + rbx - 0x88], rax; // mov
    rax, qword ptr [rcx]; // mov
    // asm: add rcx, 8
    // asm: movsxd rdx, dword ptr [rax + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rdx + rbx - 0x8c], r8d; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x377c]
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_7FF62DB450F8;

loc_7FF62DB41AEB:
    // --- Basic Block 24 (0x00007FF62DB41AEB -> 0x00007FF62DB41AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF62DB41B00;

loc_7FF62DB41AF8:
    // --- Basic Block 25 (0x00007FF62DB41AF8 -> 0x00007FF62DB41B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF62DB41B00:
    // --- Basic Block 26 (0x00007FF62DB41B00 -> 0x00007FF62DB41B69) ---
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x20
    rsi, [rcx - 0x88]; // lea
    rbx, rcx; // mov
    rax, qword ptr [rsi]; // mov
    edi, edx; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    rax, [rip + 0x3b07]; // lea
    qword ptr [r8 + rcx - 0x88], rax; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    r9d, [r8 - 0x88]; // lea
    dword ptr [r8 + rcx - 0x8c], r9d; // mov
    rcx, [rsi + 8]; // lea
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x36fe]
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450F8(); // qword ptr [rip + 0x3595]
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF62DB41B76;
    } else {
        goto loc_7FF62DB41B69;
    }

loc_7FF62DB41B69:
    // --- Basic Block 27 (0x00007FF62DB41B69 -> 0x00007FF62DB41B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41B76:
    // --- Basic Block 28 (0x00007FF62DB41B76 -> 0x00007FF62DB41B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41B89:
    // --- Basic Block 29 (0x00007FF62DB41B89 -> 0x00007FF62DB41BA9) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41BB6;
    } else {
        goto loc_7FF62DB41BA9;
    }

loc_7FF62DB41BA9:
    // --- Basic Block 30 (0x00007FF62DB41BA9 -> 0x00007FF62DB41BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41BB6:
    // --- Basic Block 31 (0x00007FF62DB41BB6 -> 0x00007FF62DB41BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41BC4:
    // --- Basic Block 32 (0x00007FF62DB41BC4 -> 0x00007FF62DB41BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    rax, [rip + 0x3947]; // lea
    rdi, rcx; // mov
    qword ptr [rcx], rax; // mov
    ebx, edx; // mov
    // asm: add rcx, 8
    rax_result = sub_7FF62DB440EC(); // 0x7ff62db440ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41C04;
    } else {
        goto loc_7FF62DB41BF7;
    }

loc_7FF62DB41BF7:
    // --- Basic Block 33 (0x00007FF62DB41BF7 -> 0x00007FF62DB41C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41C04:
    // --- Basic Block 34 (0x00007FF62DB41C04 -> 0x00007FF62DB41C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41C12:
    // --- Basic Block 35 (0x00007FF62DB41C12 -> 0x00007FF62DB41C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x18], rbx; // mov
    qword ptr [rsp + 0x20], rbp; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    rbx, rdx; // mov
    rdi, rcx; // mov
    ebp = 0;
    dword ptr [rsp + 0x20], ebp; // mov
    // asm: xorps xmm0, xmm0
    // asm: movups xmmword ptr [rcx], xmm0
    qword ptr [rcx + 0x10], rbp; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    byte ptr [rcx], bpl; // mov
    dword ptr [rsp + 0x20], 1; // mov
    rsi, qword ptr [rip + 0x73a9]; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41C78;
    }

loc_7FF62DB41C78:
    // --- Basic Block 36 (0x00007FF62DB41C78 -> 0x00007FF62DB41C80) ---

loc_7FF62DB41C80:
    // --- Basic Block 37 (0x00007FF62DB41C80 -> 0x00007FF62DB41C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB41C8D;
    } else {
        goto loc_7FF62DB41C8A;
    }

loc_7FF62DB41C8A:
    // --- Basic Block 38 (0x00007FF62DB41C8A -> 0x00007FF62DB41C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF62DB41C8D:
    // --- Basic Block 39 (0x00007FF62DB41C8D -> 0x00007FF62DB41CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB431D0(); // 0x7ff62db431d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF62DB420C0(); // 0x7ff62db420c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41CDA;
    }

loc_7FF62DB41CDA:
    // --- Basic Block 40 (0x00007FF62DB41CDA -> 0x00007FF62DB41CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF62DB41C80;

loc_7FF62DB41CE3:
    // --- Basic Block 41 (0x00007FF62DB41CE3 -> 0x00007FF62DB41CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF62DB418C0` (0x7FF62DB418C0)
- **Size**: `1640 bytes` | **Complexity V(G)**: `10` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF62DB418C0 | Address: 0x00007FF62DB418C0
// Size: 1640 bytes | Basic Blocks: 45 | Complexity V(G): 10
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF62DB418C0(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF62DB418C0:
    // --- Basic Block 0 (0x00007FF62DB418C0 -> 0x00007FF62DB418C5) ---
    goto loc_7FF62DB42020;

loc_7FF62DB418C5:
    // --- Basic Block 1 (0x00007FF62DB418C5 -> 0x00007FF62DB418F2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x30
    // asm: test byte ptr [rcx + 0x70], 1
    rax, [rip + 0x3cc6]; // lea
    qword ptr [rcx], rax; // mov
    rbx, rcx; // mov
    if (je_condition) {
        goto loc_7FF62DB41955;
    } else {
        goto loc_7FF62DB418F2;
    }

loc_7FF62DB418F2:
    // --- Basic Block 2 (0x00007FF62DB418F2 -> 0x00007FF62DB41900) ---
    rax_result = sub_7FF62DB450B8(); // qword ptr [rip + 0x37c0]
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41908;
    } else {
        goto loc_7FF62DB41900;
    }

loc_7FF62DB41900:
    // --- Basic Block 3 (0x00007FF62DB41900 -> 0x00007FF62DB41908) ---
    rax_result = sub_7FF62DB450D8(); // qword ptr [rip + 0x37d2]
    goto loc_7FF62DB4190E;

loc_7FF62DB41908:
    // --- Basic Block 4 (0x00007FF62DB41908 -> 0x00007FF62DB4190E) ---
    rax_result = sub_7FF62DB450C0(); // qword ptr [rip + 0x37b2]

loc_7FF62DB4190E:
    // --- Basic Block 5 (0x00007FF62DB4190E -> 0x00007FF62DB41932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x3786]
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = sub_7FF62DB450A0(); // qword ptr [rip + 0x377a]
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF62DB4194A;
    } else {
        goto loc_7FF62DB41932;
    }

loc_7FF62DB41932:
    // --- Basic Block 6 (0x00007FF62DB41932 -> 0x00007FF62DB41947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF62DB41999;
    } else {
        goto loc_7FF62DB41947;
    }

loc_7FF62DB41947:
    // --- Basic Block 7 (0x00007FF62DB41947 -> 0x00007FF62DB4194A) ---
    rdi, rax; // mov

loc_7FF62DB4194A:
    // --- Basic Block 8 (0x00007FF62DB4194A -> 0x00007FF62DB41955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41955:
    // --- Basic Block 9 (0x00007FF62DB41955 -> 0x00007FF62DB41999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450D0(); // qword ptr [rip + 0x376a]
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450E0(); // qword ptr [rip + 0x376c]
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_7FF62DB45200;

loc_7FF62DB41999:
    // --- Basic Block 10 (0x00007FF62DB41999 -> 0x00007FF62DB419DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = sub_7FF62DB45380(); // qword ptr [rip + 0x39ce]
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x3739]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB419E9;
    } else {
        goto loc_7FF62DB419DC;
    }

loc_7FF62DB419DC:
    // --- Basic Block 11 (0x00007FF62DB419DC -> 0x00007FF62DB419E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB419E9:
    // --- Basic Block 12 (0x00007FF62DB419E9 -> 0x00007FF62DB419EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB419EE:
    // --- Basic Block 13 (0x00007FF62DB419EE -> 0x00007FF62DB41A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF62DB440EC;

loc_7FF62DB41A03:
    // --- Basic Block 14 (0x00007FF62DB41A03 -> 0x00007FF62DB41A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36e9]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A39;
    } else {
        goto loc_7FF62DB41A2C;
    }

loc_7FF62DB41A2C:
    // --- Basic Block 15 (0x00007FF62DB41A2C -> 0x00007FF62DB41A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A39:
    // --- Basic Block 16 (0x00007FF62DB41A39 -> 0x00007FF62DB41A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF62DB41A3E:
    // --- Basic Block 17 (0x00007FF62DB41A3E -> 0x00007FF62DB41A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF62DB43232(); // 0x7ff62db43232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF62DB41A5C;
    } else {
        goto loc_7FF62DB41A52;
    }

loc_7FF62DB41A52:
    // --- Basic Block 18 (0x00007FF62DB41A52 -> 0x00007FF62DB41A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = sub_7FF62DB45148(); // qword ptr [rip + 0x36ed]

loc_7FF62DB41A5C:
    // --- Basic Block 19 (0x00007FF62DB41A5C -> 0x00007FF62DB41A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = sub_7FF62DB45110(); // qword ptr [rip + 0x36a1]
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41A81;
    } else {
        goto loc_7FF62DB41A74;
    }

loc_7FF62DB41A74:
    // --- Basic Block 20 (0x00007FF62DB41A74 -> 0x00007FF62DB41A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF62DB41A81:
    // --- Basic Block 21 (0x00007FF62DB41A81 -> 0x00007FF62DB41A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41A87:
    // --- Basic Block 22 (0x00007FF62DB41A87 -> 0x00007FF62DB41AEB) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rax, qword ptr [rcx]; // mov
    rbx, [rcx + 0x88]; // lea
    // asm: movsxd rdx, dword ptr [rax + 4]
    rax, [rip + 0x3b85]; // lea
    qword ptr [rdx + rbx - 0x88], rax; // mov
    rax, qword ptr [rcx]; // mov
    // asm: add rcx, 8
    // asm: movsxd rdx, dword ptr [rax + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rdx + rbx - 0x8c], r8d; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x377c]
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_7FF62DB450F8;

loc_7FF62DB41AEB:
    // --- Basic Block 23 (0x00007FF62DB41AEB -> 0x00007FF62DB41AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF62DB41B00;

loc_7FF62DB41AF8:
    // --- Basic Block 24 (0x00007FF62DB41AF8 -> 0x00007FF62DB41B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF62DB41B00:
    // --- Basic Block 25 (0x00007FF62DB41B00 -> 0x00007FF62DB41B69) ---
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x20
    rsi, [rcx - 0x88]; // lea
    rbx, rcx; // mov
    rax, qword ptr [rsi]; // mov
    edi, edx; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    rax, [rip + 0x3b07]; // lea
    qword ptr [r8 + rcx - 0x88], rax; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd r8, dword ptr [rax + 4]
    r9d, [r8 - 0x88]; // lea
    dword ptr [r8 + rcx - 0x8c], r9d; // mov
    rcx, [rsi + 8]; // lea
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rbx - 0x78]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x36fe]
    rcx, rbx; // mov
    rax_result = sub_7FF62DB450F8(); // qword ptr [rip + 0x3595]
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF62DB41B76;
    } else {
        goto loc_7FF62DB41B69;
    }

loc_7FF62DB41B69:
    // --- Basic Block 26 (0x00007FF62DB41B69 -> 0x00007FF62DB41B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41B76:
    // --- Basic Block 27 (0x00007FF62DB41B76 -> 0x00007FF62DB41B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41B89:
    // --- Basic Block 28 (0x00007FF62DB41B89 -> 0x00007FF62DB41BA9) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41BB6;
    } else {
        goto loc_7FF62DB41BA9;
    }

loc_7FF62DB41BA9:
    // --- Basic Block 29 (0x00007FF62DB41BA9 -> 0x00007FF62DB41BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41BB6:
    // --- Basic Block 30 (0x00007FF62DB41BB6 -> 0x00007FF62DB41BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41BC4:
    // --- Basic Block 31 (0x00007FF62DB41BC4 -> 0x00007FF62DB41BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    rax, [rip + 0x3947]; // lea
    rdi, rcx; // mov
    qword ptr [rcx], rax; // mov
    ebx, edx; // mov
    // asm: add rcx, 8
    rax_result = sub_7FF62DB440EC(); // 0x7ff62db440ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF62DB41C04;
    } else {
        goto loc_7FF62DB41BF7;
    }

loc_7FF62DB41BF7:
    // --- Basic Block 32 (0x00007FF62DB41BF7 -> 0x00007FF62DB41C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB432B0(); // 0x7ff62db432b0

loc_7FF62DB41C04:
    // --- Basic Block 33 (0x00007FF62DB41C04 -> 0x00007FF62DB41C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF62DB41C12:
    // --- Basic Block 34 (0x00007FF62DB41C12 -> 0x00007FF62DB41C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x18], rbx; // mov
    qword ptr [rsp + 0x20], rbp; // mov
    qword ptr [rsp + 8], rcx; // mov
    // asm: sub rsp, 0x30
    rbx, rdx; // mov
    rdi, rcx; // mov
    ebp = 0;
    dword ptr [rsp + 0x20], ebp; // mov
    // asm: xorps xmm0, xmm0
    // asm: movups xmmword ptr [rcx], xmm0
    qword ptr [rcx + 0x10], rbp; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    byte ptr [rcx], bpl; // mov
    dword ptr [rsp + 0x20], 1; // mov
    rsi, qword ptr [rip + 0x73a9]; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41C78;
    }

loc_7FF62DB41C78:
    // --- Basic Block 35 (0x00007FF62DB41C78 -> 0x00007FF62DB41C80) ---

loc_7FF62DB41C80:
    // --- Basic Block 36 (0x00007FF62DB41C80 -> 0x00007FF62DB41C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF62DB41C8D;
    } else {
        goto loc_7FF62DB41C8A;
    }

loc_7FF62DB41C8A:
    // --- Basic Block 37 (0x00007FF62DB41C8A -> 0x00007FF62DB41C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF62DB41C8D:
    // --- Basic Block 38 (0x00007FF62DB41C8D -> 0x00007FF62DB41CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB431D0(); // 0x7ff62db431d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF62DB420C0(); // 0x7ff62db420c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF62DB41CE3;
    } else {
        goto loc_7FF62DB41CDA;
    }

loc_7FF62DB41CDA:
    // --- Basic Block 39 (0x00007FF62DB41CDA -> 0x00007FF62DB41CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF62DB41C80;

loc_7FF62DB41CE3:
    // --- Basic Block 40 (0x00007FF62DB41CE3 -> 0x00007FF62DB41CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF62DB41CF9:
    // --- Basic Block 41 (0x00007FF62DB41CF9 -> 0x00007FF62DB41D9D) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x10], rbx; // mov
    qword ptr [rsp + 0x18], rsi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    rbp, [rsp - 0x70]; // lea
    // asm: sub rsp, 0x170
    rax, qword ptr [rip + 0x7319]; // mov
    // asm: xor rax, rsp
    qword ptr [rbp + 0x60], rax; // mov
    r14, rcx; // mov
    qword ptr [rsp + 0x48], rcx; // mov
    edi = 0;
    dword ptr [rsp + 0x44], edi; // mov
    // asm: xorps xmm0, xmm0
    // asm: movups xmmword ptr [rbp + 0x50], xmm0
    dword ptr [rsp + 0x48], 0x10; // mov
    rdx, [rsp + 0x48]; // lea
    rcx, [rbp + 0x50]; // lea
    rax_result = sub_7FF62DB45070(); // qword ptr [rip + 0x3316]
    dword ptr [rsp + 0x40], edi; // mov
    dword ptr [rsp + 0x38], edi; // mov
    qword ptr [rsp + 0x30], rdi; // mov
    qword ptr [rsp + 0x28], rdi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    r9, [rsp + 0x40]; // lea
    r8d = 0;
    edx = 0;
    rcx, [rip + 0x38be]; // lea
    rax_result = sub_7FF62DB45088(); // qword ptr [rip + 0x3300]
    esi, 0x539; // mov
    ebx, edi; // mov
    rcx, [rbp + 0x50]; // lea
    rax_result = sub_7FF62DB44122(); // 0x7ff62db44122
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF62DB41DB2;
    } else {
        goto loc_7FF62DB41D9D;
    }

loc_7FF62DB41D9D:
    // --- Basic Block 42 (0x00007FF62DB41D9D -> 0x00007FF62DB41DA0) ---

loc_7FF62DB41DA0:
    // --- Basic Block 43 (0x00007FF62DB41DA0 -> 0x00007FF62DB41DB2) ---
    // asm: movsx ecx, byte ptr [rbp + rbx + 0x50]
    // asm: imul esi, esi, 0x21
    // asm: xor esi, ecx
    // asm: inc rbx
    // asm: cmp rbx, rax
    if (jb_condition) {
        goto loc_7FF62DB41DA0;
    } else {
        goto loc_7FF62DB41DB2;
    }

loc_7FF62DB41DB2:
    // --- Basic Block 44 (0x00007FF62DB41DB2 -> 0x00007FF62DB41F28) ---
    // asm: xor esi, dword ptr [rsp + 0x40]
    rax, [rip + 0x387b]; // lea
    qword ptr [rsp + 0x60], rax; // mov
    rcx, [rbp - 0x18]; // lea
    rax_result = sub_7FF62DB45130(); // qword ptr [rip + 0x3364]
    dword ptr [rsp + 0x44], 2; // mov
    r9d = 0;
    r8d = 0;
    rdx, [rsp + 0x68]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = sub_7FF62DB45138(); // qword ptr [rip + 0x334d]
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    r15, [rip + 0x3834]; // lea
    qword ptr [rsp + rcx + 0x60], r15; // mov
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    edx, [rcx - 0x88]; // lea
    dword ptr [rsp + rcx + 0x5c], edx; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF62DB45208(); // qword ptr [rip + 0x33e9]
    rax, [rip + 0x378a]; // lea
    qword ptr [rsp + 0x68], rax; // mov
    qword ptr [rbp - 0x30], rdi; // mov
    dword ptr [rbp - 0x28], 4; // mov
    edx, 8; // mov
    rcx, [rsp + 0x50]; // lea
    rax_result = sub_7FF62DB43238(); // 0x7ff62db43238
    rbx, rax; // mov
    rdx, [rip + 0x37f5]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = sub_7FF62DB41000(); // 0x7ff62db41000
    rcx, rax; // mov
    rdx, [rip + 0xdbd]; // lea
    rax_result = sub_7FF62DB45150(); // qword ptr [rip + 0x32e7]
    rcx, rax; // mov
    rdx, [rip + 0x42d]; // lea
    rax_result = sub_7FF62DB45150(); // qword ptr [rip + 0x32d7]
    rdi, rax; // mov
    rax, qword ptr [rax]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax, qword ptr [rbx]; // mov
    rdx, qword ptr [rbx + 8]; // mov
    rax_result = indirect_call(rax);
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    dl, 0x30; // mov
    rax_result = sub_7FF62DB45120(); // qword ptr [rip + 0x327f]
    edx, esi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF62DB45158(); // qword ptr [rip + 0x32ac]
    rdx, r14; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF62DB42920(); // 0x7ff62db42920
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    qword ptr [rsp + rdx + 0x60], r15; // mov
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rsp + rdx + 0x5c], r8d; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF62DB418D0(); // 0x7ff62db418d0
    rcx, [rsp + 0x70]; // lea
    rax_result = sub_7FF62DB45258(); // qword ptr [rip + 0x3366]
    rcx, [rbp - 0x18]; // lea
    rax_result = sub_7FF62DB450F8(); // qword ptr [rip + 0x31fc]
    rax, r14; // mov
    rcx, qword ptr [rbp + 0x60]; // mov
    // asm: xor rcx, rsp
    rax_result = sub_7FF62DB433B0(); // 0x7ff62db433b0
    r11, [rsp + 0x170]; // lea
    rbx, qword ptr [r11 + 0x28]; // mov
    rsi, qword ptr [r11 + 0x30]; // mov
    rdi, qword ptr [r11 + 0x38]; // mov
    rsp, r11; // mov
    return rax_result;

}
```

