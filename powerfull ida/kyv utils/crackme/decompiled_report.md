# KYV Automated Decompilation & Reverse Engineering Report

- **Target Process**: `hwid_crackme.exe` (PID: `3168`)
- **Base Address**: `0x7FF71C110000`
- **Functions Discovered**: `43`
- **Cross-References (XREFs)**: `0`
- **Strings Discovered**: `386`

## [ALERT] Command & Control (C2) URLs Detected
- `http://c2.kyv-security.local/verify_hwid_license`

## [ALERT] Sensitive Registry Paths Detected
- `Software\KYV\License\ActivationKey`

## Decompiled Hex-Rays C Pseudocode (Key Functions)

### Function `sub_00007FF71C111015` (0x7FF71C111015)
- **Size**: `1549 bytes` | **Complexity V(G)**: `34` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111015 | Address: 0x00007FF71C111015
// Size: 1549 bytes | Basic Blocks: 81 | Complexity V(G): 34
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111015(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111015:
    // --- Basic Block 0 (0x00007FF71C111015 -> 0x00007FF71C11104A) ---
    // asm: sub rsp, 0x30
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r15d, r15d
    dword ptr [rsp + 0x80], r15d; // mov
    rcx, rdx; // mov
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r13, rax; // mov
    r8, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [r8 + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x41d3]);
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF71C111077;
    } else {
        goto loc_7FF71C11104A;
    }

loc_7FF71C11104A:
    // --- Basic Block 1 (0x00007FF71C11104A -> 0x00007FF71C11105F) ---
    rcx, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rcx + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x41be]);
    // asm: cmp rax, r13
    if (jle_condition) {
        goto loc_7FF71C111077;
    } else {
        goto loc_7FF71C11105F;
    }

loc_7FF71C11105F:
    // --- Basic Block 2 (0x00007FF71C11105F -> 0x00007FF71C111077) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x41a9]);
    r14, rax; // mov
    // asm: sub r14, r13
    goto loc_7FF71C11107A;

loc_7FF71C111077:
    // --- Basic Block 3 (0x00007FF71C111077 -> 0x00007FF71C11107A) ---
    r14, r15; // mov

loc_7FF71C11107A:
    // --- Basic Block 4 (0x00007FF71C11107A -> 0x00007FF71C111097) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x407e]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1110A4;
    } else {
        goto loc_7FF71C111097;
    }

loc_7FF71C111097:
    // --- Basic Block 5 (0x00007FF71C111097 -> 0x00007FF71C1110A4) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1110A4:
    // --- Basic Block 6 (0x00007FF71C1110A4 -> 0x00007FF71C1110B8) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x4184]);
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C1110BE;
    } else {
        goto loc_7FF71C1110B8;
    }

loc_7FF71C1110B8:
    // --- Basic Block 7 (0x00007FF71C1110B8 -> 0x00007FF71C1110BE) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C1110FE;

loc_7FF71C1110BE:
    // --- Basic Block 8 (0x00007FF71C1110BE -> 0x00007FF71C1110D3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x403a]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1110F7;
    } else {
        goto loc_7FF71C1110D3;
    }

loc_7FF71C1110D3:
    // --- Basic Block 9 (0x00007FF71C1110D3 -> 0x00007FF71C1110D8) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF71C1110F7;
    } else {
        goto loc_7FF71C1110D8;
    }

loc_7FF71C1110D8:
    // --- Basic Block 10 (0x00007FF71C1110D8 -> 0x00007FF71C1110F7) ---
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x4087]);
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x4147]);
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C1110FE;

loc_7FF71C1110F7:
    // --- Basic Block 11 (0x00007FF71C1110F7 -> 0x00007FF71C1110FE) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF71C1110FE:
    // --- Basic Block 12 (0x00007FF71C1110FE -> 0x00007FF71C111102) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C11110D;
    } else {
        goto loc_7FF71C111102;
    }

loc_7FF71C111102:
    // --- Basic Block 13 (0x00007FF71C111102 -> 0x00007FF71C11110D) ---
    r15d, 4; // mov
    goto loc_7FF71C111204;

loc_7FF71C11110D:
    // --- Basic Block 14 (0x00007FF71C11110D -> 0x00007FF71C111127) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x4113]);
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF71C11116B;
    } else {
        goto loc_7FF71C111127;
    }

loc_7FF71C111127:
    // --- Basic Block 15 (0x00007FF71C111127 -> 0x00007FF71C11112C) ---
    // asm: test r14, r14
    if (jle_condition) {
        goto loc_7FF71C111166;
    } else {
        goto loc_7FF71C11112C;
    }

loc_7FF71C11112C:
    // --- Basic Block 16 (0x00007FF71C11112C -> 0x00007FF71C111161) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3fd5]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3fc1]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3fe4]);
    // asm: cmp eax, -1
    if (je_condition) {
        goto loc_7FF71C1111CF;
    } else {
        goto loc_7FF71C111161;
    }

loc_7FF71C111161:
    // --- Basic Block 17 (0x00007FF71C111161 -> 0x00007FF71C111166) ---
    // asm: dec r14
    goto loc_7FF71C111127;

loc_7FF71C111166:
    // --- Basic Block 18 (0x00007FF71C111166 -> 0x00007FF71C11116B) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF71C11116B:
    // --- Basic Block 19 (0x00007FF71C11116B -> 0x00007FF71C11118F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3f95]);
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x4056]);
    // asm: cmp rax, r13
    if (jne_condition) {
        goto loc_7FF71C1111CF;
    } else {
        goto loc_7FF71C11118F;
    }

loc_7FF71C11118F:
    // --- Basic Block 20 (0x00007FF71C11118F -> 0x00007FF71C111190) ---

loc_7FF71C111190:
    // --- Basic Block 21 (0x00007FF71C111190 -> 0x00007FF71C111195) ---
    // asm: test r14, r14
    if (jle_condition) {
        goto loc_7FF71C1111DD;
    } else {
        goto loc_7FF71C111195;
    }

loc_7FF71C111195:
    // --- Basic Block 22 (0x00007FF71C111195 -> 0x00007FF71C1111CA) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3f6c]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3f58]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3f7b]);
    // asm: cmp eax, -1
    if (je_condition) {
        goto loc_7FF71C1111CF;
    } else {
        goto loc_7FF71C1111CA;
    }

loc_7FF71C1111CA:
    // --- Basic Block 23 (0x00007FF71C1111CA -> 0x00007FF71C1111CF) ---
    // asm: dec r14
    goto loc_7FF71C111190;

loc_7FF71C1111CF:
    // --- Basic Block 24 (0x00007FF71C1111CF -> 0x00007FF71C1111DD) ---
    r15d, 4; // mov
    dword ptr [rsp + 0x80], r15d; // mov

loc_7FF71C1111DD:
    // --- Basic Block 25 (0x00007FF71C1111DD -> 0x00007FF71C1111F2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x4021]);
    goto loc_7FF71C111204;

loc_7FF71C1111F2:
    // --- Basic Block 26 (0x00007FF71C1111F2 -> 0x00007FF71C111204) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r15d, dword ptr [rsp + 0x80]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF71C111204:
    // --- Basic Block 27 (0x00007FF71C111204 -> 0x00007FF71C111224) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r15d; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3ee6]);
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C11122E;
    } else {
        goto loc_7FF71C111224;
    }

loc_7FF71C111224:
    // --- Basic Block 28 (0x00007FF71C111224 -> 0x00007FF71C11122E) ---
    rcx, r12; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3f1b]);

loc_7FF71C11122E:
    // --- Basic Block 29 (0x00007FF71C11122E -> 0x00007FF71C111244) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = indirect_call(qword ptr [rip + 0x3ed1]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111251;
    } else {
        goto loc_7FF71C111244;
    }

loc_7FF71C111244:
    // --- Basic Block 30 (0x00007FF71C111244 -> 0x00007FF71C111251) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111251:
    // --- Basic Block 31 (0x00007FF71C111251 -> 0x00007FF71C111264) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C111264:
    // --- Basic Block 32 (0x00007FF71C111264 -> 0x00007FF71C111279) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
        goto loc_7FF71C111280;
    } else {
        goto loc_7FF71C111279;
    }

loc_7FF71C111279:
    // --- Basic Block 33 (0x00007FF71C111279 -> 0x00007FF71C111280) ---
    eax = 0;
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF71C111280:
    // --- Basic Block 34 (0x00007FF71C111280 -> 0x00007FF71C111289) ---
    // asm: cmp rcx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C1112C7;
    } else {
        goto loc_7FF71C111289;
    }

loc_7FF71C111289:
    // --- Basic Block 35 (0x00007FF71C111289 -> 0x00007FF71C111292) ---
    rax, [rcx + 0x27]; // lea
    // asm: cmp rax, rcx
    if (jbe_condition) {
        goto loc_7FF71C1112D0;
    } else {
        goto loc_7FF71C111292;
    }

loc_7FF71C111292:
    // --- Basic Block 36 (0x00007FF71C111292 -> 0x00007FF71C1112A2) ---
    rcx, rax; // mov
    rax_result = sub_7FF71C113274(); // 0x7ff71c113274
    rcx, rax; // mov
    // asm: test rax, rax
    if (jne_condition) {
        goto loc_7FF71C1112B6;
    } else {
        goto loc_7FF71C1112A2;
    }

loc_7FF71C1112A2:
    // --- Basic Block 37 (0x00007FF71C1112A2 -> 0x00007FF71C1112B6) ---
    r9d = 0;
    qword ptr [rsp + 0x20], rax; // mov
    r8d = 0;
    edx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x40cb]);
    // asm: int3 

loc_7FF71C1112B6:
    // --- Basic Block 38 (0x00007FF71C1112B6 -> 0x00007FF71C1112C7) ---
    // asm: add rax, 0x27
    // asm: and rax, 0xffffffffffffffe0
    qword ptr [rax - 8], rcx; // mov
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF71C1112C7:
    // --- Basic Block 39 (0x00007FF71C1112C7 -> 0x00007FF71C1112D0) ---
    // asm: add rsp, 0x38
    goto loc_7FF71C113274;

loc_7FF71C1112D0:
    // --- Basic Block 40 (0x00007FF71C1112D0 -> 0x00007FF71C111311) ---
    rax_result = sub_7FF71C112000(); // 0x7ff71c112000
    // asm: int3 
    // asm: int3 
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
        goto loc_7FF71C111392;
    } else {
        goto loc_7FF71C111311;
    }

loc_7FF71C111311:
    // --- Basic Block 41 (0x00007FF71C111311 -> 0x00007FF71C111317) ---
    // asm: cmp r8, 0xf
    if (ja_condition) {
        goto loc_7FF71C11132E;
    } else {
        goto loc_7FF71C111317;
    }

loc_7FF71C111317:
    // --- Basic Block 42 (0x00007FF71C111317 -> 0x00007FF71C11132E) ---
    qword ptr [rcx + 0x10], r8; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [rdi + rsi], 0; // mov
    goto loc_7FF71C11137C;

loc_7FF71C11132E:
    // --- Basic Block 43 (0x00007FF71C11132E -> 0x00007FF71C11133F) ---
    rax, rdi; // mov
    qword ptr [rsp + 0x30], rbx; // mov
    // asm: or rax, 0xf
    // asm: cmp rax, rbp
    if (ja_condition) {
        goto loc_7FF71C11134E;
    } else {
        goto loc_7FF71C11133F;
    }

loc_7FF71C11133F:
    // --- Basic Block 44 (0x00007FF71C11133F -> 0x00007FF71C11134E) ---
    ecx, 0x16; // mov
    rbp, rax; // mov
    // asm: cmp rax, rcx
    // asm: cmovb rbp, rcx

loc_7FF71C11134E:
    // --- Basic Block 45 (0x00007FF71C11134E -> 0x00007FF71C11137C) ---
    rcx, [rbp + 1]; // lea
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    r8, rdi; // mov
    qword ptr [rsi], rax; // mov
    rdx, r14; // mov
    qword ptr [rsi + 0x10], rdi; // mov
    rcx, rax; // mov
    qword ptr [rsi + 0x18], rbp; // mov
    rbx, rax; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [rbx + rdi], 0; // mov
    rbx, qword ptr [rsp + 0x30]; // mov

loc_7FF71C11137C:
    // --- Basic Block 46 (0x00007FF71C11137C -> 0x00007FF71C111392) ---
    rbp, qword ptr [rsp + 0x38]; // mov
    rsi, qword ptr [rsp + 0x40]; // mov
    rdi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111392:
    // --- Basic Block 47 (0x00007FF71C111392 -> 0x00007FF71C1113E2) ---
    rax_result = sub_7FF71C1120A0(); // 0x7ff71c1120a0
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
    rax_result = indirect_call(qword ptr [rip + 0x3e3b]);
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF71C11140F;
    } else {
        goto loc_7FF71C1113E2;
    }

loc_7FF71C1113E2:
    // --- Basic Block 48 (0x00007FF71C1113E2 -> 0x00007FF71C1113F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3e26]);
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF71C11140F;
    } else {
        goto loc_7FF71C1113F7;
    }

loc_7FF71C1113F7:
    // --- Basic Block 49 (0x00007FF71C1113F7 -> 0x00007FF71C11140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3e11]);
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF71C111412;

loc_7FF71C11140F:
    // --- Basic Block 50 (0x00007FF71C11140F -> 0x00007FF71C111412) ---
    r15, r14; // mov

loc_7FF71C111412:
    // --- Basic Block 51 (0x00007FF71C111412 -> 0x00007FF71C11142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3ce6]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11143C;
    } else {
        goto loc_7FF71C11142F;
    }

loc_7FF71C11142F:
    // --- Basic Block 52 (0x00007FF71C11142F -> 0x00007FF71C11143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C11143C:
    // --- Basic Block 53 (0x00007FF71C11143C -> 0x00007FF71C111450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3dec]);
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C111456;
    } else {
        goto loc_7FF71C111450;
    }

loc_7FF71C111450:
    // --- Basic Block 54 (0x00007FF71C111450 -> 0x00007FF71C111456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C111496;

loc_7FF71C111456:
    // --- Basic Block 55 (0x00007FF71C111456 -> 0x00007FF71C11146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3ca2]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11148F;
    } else {
        goto loc_7FF71C11146B;
    }

loc_7FF71C11146B:
    // --- Basic Block 56 (0x00007FF71C11146B -> 0x00007FF71C111470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF71C11148F;
    } else {
        goto loc_7FF71C111470;
    }

loc_7FF71C111470:
    // --- Basic Block 57 (0x00007FF71C111470 -> 0x00007FF71C11148F) ---
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3cef]);
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3daf]);
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C111496;

loc_7FF71C11148F:
    // --- Basic Block 58 (0x00007FF71C11148F -> 0x00007FF71C111496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF71C111496:
    // --- Basic Block 59 (0x00007FF71C111496 -> 0x00007FF71C11149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C1114A5;
    } else {
        goto loc_7FF71C11149A;
    }

loc_7FF71C11149A:
    // --- Basic Block 60 (0x00007FF71C11149A -> 0x00007FF71C1114A5) ---
    r14d, 4; // mov
    goto loc_7FF71C1115C2;

loc_7FF71C1114A5:
    // --- Basic Block 61 (0x00007FF71C1114A5 -> 0x00007FF71C1114C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3d7b]);
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF71C111578;
    } else {
        goto loc_7FF71C1114C3;
    }

loc_7FF71C1114C3:
    // --- Basic Block 62 (0x00007FF71C1114C3 -> 0x00007FF71C1114CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF71C111573;
    } else {
        goto loc_7FF71C1114CC;
    }

loc_7FF71C1114CC:
    // --- Basic Block 63 (0x00007FF71C1114CC -> 0x00007FF71C111501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3c35]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3c21]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3c44]);
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C11156B;
    } else {
        goto loc_7FF71C111501;
    }

loc_7FF71C111501:
    // --- Basic Block 64 (0x00007FF71C111501 -> 0x00007FF71C111510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF71C111510:
    // --- Basic Block 65 (0x00007FF71C111510 -> 0x00007FF71C111515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF71C111556;
    } else {
        goto loc_7FF71C111515;
    }

loc_7FF71C111515:
    // --- Basic Block 66 (0x00007FF71C111515 -> 0x00007FF71C11154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3bec]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3bd8]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3bfb]);
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C1115A8;
    } else {
        goto loc_7FF71C11154A;
    }

loc_7FF71C11154A:
    // --- Basic Block 67 (0x00007FF71C11154A -> 0x00007FF71C11154E) ---
    // asm: or r14d, 4

loc_7FF71C11154E:
    // --- Basic Block 68 (0x00007FF71C11154E -> 0x00007FF71C111556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF71C111556:
    // --- Basic Block 69 (0x00007FF71C111556 -> 0x00007FF71C11156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x3ca8]);
    goto loc_7FF71C1115C2;

loc_7FF71C11156B:
    // --- Basic Block 70 (0x00007FF71C11156B -> 0x00007FF71C111573) ---
    // asm: dec r15
    goto loc_7FF71C1114C3;

loc_7FF71C111573:
    // --- Basic Block 71 (0x00007FF71C111573 -> 0x00007FF71C111578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF71C111578:
    // --- Basic Block 72 (0x00007FF71C111578 -> 0x00007FF71C1115A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3b88]);
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3c49]);
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF71C111510;
    } else {
        goto loc_7FF71C1115A0;
    }

loc_7FF71C1115A0:
    // --- Basic Block 73 (0x00007FF71C1115A0 -> 0x00007FF71C1115A8) ---
    r14d, 4; // mov
    goto loc_7FF71C11154E;

loc_7FF71C1115A8:
    // --- Basic Block 74 (0x00007FF71C1115A8 -> 0x00007FF71C1115B0) ---
    // asm: dec r15
    goto loc_7FF71C111510;

loc_7FF71C1115B0:
    // --- Basic Block 75 (0x00007FF71C1115B0 -> 0x00007FF71C1115C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF71C1115C2:
    // --- Basic Block 76 (0x00007FF71C1115C2 -> 0x00007FF71C1115E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b28]);
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C1115EC;
    } else {
        goto loc_7FF71C1115E2;
    }

loc_7FF71C1115E2:
    // --- Basic Block 77 (0x00007FF71C1115E2 -> 0x00007FF71C1115EC) ---
    rcx, r12; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b5d]);

loc_7FF71C1115EC:
    // --- Basic Block 78 (0x00007FF71C1115EC -> 0x00007FF71C111602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = indirect_call(qword ptr [rip + 0x3b13]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11160F;
    } else {
        goto loc_7FF71C111602;
    }

loc_7FF71C111602:
    // --- Basic Block 79 (0x00007FF71C111602 -> 0x00007FF71C11160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C11160F:
    // --- Basic Block 80 (0x00007FF71C11160F -> 0x00007FF71C111622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF71C111270` (0x7FF71C111270)
- **Size**: `1602 bytes` | **Complexity V(G)**: `23` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111270 | Address: 0x00007FF71C111270
// Size: 1602 bytes | Basic Blocks: 74 | Complexity V(G): 23
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111270(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111270:
    // --- Basic Block 0 (0x00007FF71C111270 -> 0x00007FF71C111279) ---
    // asm: sub rsp, 0x38
    // asm: test rcx, rcx
    if (jne_condition) {
        goto loc_7FF71C111280;
    } else {
        goto loc_7FF71C111279;
    }

loc_7FF71C111279:
    // --- Basic Block 1 (0x00007FF71C111279 -> 0x00007FF71C111280) ---
    eax = 0;
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF71C111280:
    // --- Basic Block 2 (0x00007FF71C111280 -> 0x00007FF71C111289) ---
    // asm: cmp rcx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C1112C7;
    } else {
        goto loc_7FF71C111289;
    }

loc_7FF71C111289:
    // --- Basic Block 3 (0x00007FF71C111289 -> 0x00007FF71C111292) ---
    rax, [rcx + 0x27]; // lea
    // asm: cmp rax, rcx
    if (jbe_condition) {
        goto loc_7FF71C1112D0;
    } else {
        goto loc_7FF71C111292;
    }

loc_7FF71C111292:
    // --- Basic Block 4 (0x00007FF71C111292 -> 0x00007FF71C1112A2) ---
    rcx, rax; // mov
    rax_result = sub_7FF71C113274(); // 0x7ff71c113274
    rcx, rax; // mov
    // asm: test rax, rax
    if (jne_condition) {
        goto loc_7FF71C1112B6;
    } else {
        goto loc_7FF71C1112A2;
    }

loc_7FF71C1112A2:
    // --- Basic Block 5 (0x00007FF71C1112A2 -> 0x00007FF71C1112B6) ---
    r9d = 0;
    qword ptr [rsp + 0x20], rax; // mov
    r8d = 0;
    edx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x40cb]);
    // asm: int3 

loc_7FF71C1112B6:
    // --- Basic Block 6 (0x00007FF71C1112B6 -> 0x00007FF71C1112C7) ---
    // asm: add rax, 0x27
    // asm: and rax, 0xffffffffffffffe0
    qword ptr [rax - 8], rcx; // mov
    // asm: add rsp, 0x38
    return rax_result;

loc_7FF71C1112C7:
    // --- Basic Block 7 (0x00007FF71C1112C7 -> 0x00007FF71C1112D0) ---
    // asm: add rsp, 0x38
    goto loc_7FF71C113274;

loc_7FF71C1112D0:
    // --- Basic Block 8 (0x00007FF71C1112D0 -> 0x00007FF71C111311) ---
    rax_result = sub_7FF71C112000(); // 0x7ff71c112000
    // asm: int3 
    // asm: int3 
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
        goto loc_7FF71C111392;
    } else {
        goto loc_7FF71C111311;
    }

loc_7FF71C111311:
    // --- Basic Block 9 (0x00007FF71C111311 -> 0x00007FF71C111317) ---
    // asm: cmp r8, 0xf
    if (ja_condition) {
        goto loc_7FF71C11132E;
    } else {
        goto loc_7FF71C111317;
    }

loc_7FF71C111317:
    // --- Basic Block 10 (0x00007FF71C111317 -> 0x00007FF71C11132E) ---
    qword ptr [rcx + 0x10], r8; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [rdi + rsi], 0; // mov
    goto loc_7FF71C11137C;

loc_7FF71C11132E:
    // --- Basic Block 11 (0x00007FF71C11132E -> 0x00007FF71C11133F) ---
    rax, rdi; // mov
    qword ptr [rsp + 0x30], rbx; // mov
    // asm: or rax, 0xf
    // asm: cmp rax, rbp
    if (ja_condition) {
        goto loc_7FF71C11134E;
    } else {
        goto loc_7FF71C11133F;
    }

loc_7FF71C11133F:
    // --- Basic Block 12 (0x00007FF71C11133F -> 0x00007FF71C11134E) ---
    ecx, 0x16; // mov
    rbp, rax; // mov
    // asm: cmp rax, rcx
    // asm: cmovb rbp, rcx

loc_7FF71C11134E:
    // --- Basic Block 13 (0x00007FF71C11134E -> 0x00007FF71C11137C) ---
    rcx, [rbp + 1]; // lea
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    r8, rdi; // mov
    qword ptr [rsi], rax; // mov
    rdx, r14; // mov
    qword ptr [rsi + 0x10], rdi; // mov
    rcx, rax; // mov
    qword ptr [rsi + 0x18], rbp; // mov
    rbx, rax; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [rbx + rdi], 0; // mov
    rbx, qword ptr [rsp + 0x30]; // mov

loc_7FF71C11137C:
    // --- Basic Block 14 (0x00007FF71C11137C -> 0x00007FF71C111392) ---
    rbp, qword ptr [rsp + 0x38]; // mov
    rsi, qword ptr [rsp + 0x40]; // mov
    rdi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111392:
    // --- Basic Block 15 (0x00007FF71C111392 -> 0x00007FF71C1113E2) ---
    rax_result = sub_7FF71C1120A0(); // 0x7ff71c1120a0
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
    rax_result = indirect_call(qword ptr [rip + 0x3e3b]);
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF71C11140F;
    } else {
        goto loc_7FF71C1113E2;
    }

loc_7FF71C1113E2:
    // --- Basic Block 16 (0x00007FF71C1113E2 -> 0x00007FF71C1113F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3e26]);
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF71C11140F;
    } else {
        goto loc_7FF71C1113F7;
    }

loc_7FF71C1113F7:
    // --- Basic Block 17 (0x00007FF71C1113F7 -> 0x00007FF71C11140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3e11]);
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF71C111412;

loc_7FF71C11140F:
    // --- Basic Block 18 (0x00007FF71C11140F -> 0x00007FF71C111412) ---
    r15, r14; // mov

loc_7FF71C111412:
    // --- Basic Block 19 (0x00007FF71C111412 -> 0x00007FF71C11142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3ce6]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11143C;
    } else {
        goto loc_7FF71C11142F;
    }

loc_7FF71C11142F:
    // --- Basic Block 20 (0x00007FF71C11142F -> 0x00007FF71C11143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C11143C:
    // --- Basic Block 21 (0x00007FF71C11143C -> 0x00007FF71C111450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3dec]);
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C111456;
    } else {
        goto loc_7FF71C111450;
    }

loc_7FF71C111450:
    // --- Basic Block 22 (0x00007FF71C111450 -> 0x00007FF71C111456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C111496;

loc_7FF71C111456:
    // --- Basic Block 23 (0x00007FF71C111456 -> 0x00007FF71C11146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3ca2]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11148F;
    } else {
        goto loc_7FF71C11146B;
    }

loc_7FF71C11146B:
    // --- Basic Block 24 (0x00007FF71C11146B -> 0x00007FF71C111470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF71C11148F;
    } else {
        goto loc_7FF71C111470;
    }

loc_7FF71C111470:
    // --- Basic Block 25 (0x00007FF71C111470 -> 0x00007FF71C11148F) ---
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3cef]);
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3daf]);
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C111496;

loc_7FF71C11148F:
    // --- Basic Block 26 (0x00007FF71C11148F -> 0x00007FF71C111496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF71C111496:
    // --- Basic Block 27 (0x00007FF71C111496 -> 0x00007FF71C11149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C1114A5;
    } else {
        goto loc_7FF71C11149A;
    }

loc_7FF71C11149A:
    // --- Basic Block 28 (0x00007FF71C11149A -> 0x00007FF71C1114A5) ---
    r14d, 4; // mov
    goto loc_7FF71C1115C2;

loc_7FF71C1114A5:
    // --- Basic Block 29 (0x00007FF71C1114A5 -> 0x00007FF71C1114C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3d7b]);
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF71C111578;
    } else {
        goto loc_7FF71C1114C3;
    }

loc_7FF71C1114C3:
    // --- Basic Block 30 (0x00007FF71C1114C3 -> 0x00007FF71C1114CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF71C111573;
    } else {
        goto loc_7FF71C1114CC;
    }

loc_7FF71C1114CC:
    // --- Basic Block 31 (0x00007FF71C1114CC -> 0x00007FF71C111501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3c35]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3c21]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3c44]);
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C11156B;
    } else {
        goto loc_7FF71C111501;
    }

loc_7FF71C111501:
    // --- Basic Block 32 (0x00007FF71C111501 -> 0x00007FF71C111510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF71C111510:
    // --- Basic Block 33 (0x00007FF71C111510 -> 0x00007FF71C111515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF71C111556;
    } else {
        goto loc_7FF71C111515;
    }

loc_7FF71C111515:
    // --- Basic Block 34 (0x00007FF71C111515 -> 0x00007FF71C11154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3bec]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3bd8]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3bfb]);
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C1115A8;
    } else {
        goto loc_7FF71C11154A;
    }

loc_7FF71C11154A:
    // --- Basic Block 35 (0x00007FF71C11154A -> 0x00007FF71C11154E) ---
    // asm: or r14d, 4

loc_7FF71C11154E:
    // --- Basic Block 36 (0x00007FF71C11154E -> 0x00007FF71C111556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF71C111556:
    // --- Basic Block 37 (0x00007FF71C111556 -> 0x00007FF71C11156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x3ca8]);
    goto loc_7FF71C1115C2;

loc_7FF71C11156B:
    // --- Basic Block 38 (0x00007FF71C11156B -> 0x00007FF71C111573) ---
    // asm: dec r15
    goto loc_7FF71C1114C3;

loc_7FF71C111573:
    // --- Basic Block 39 (0x00007FF71C111573 -> 0x00007FF71C111578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF71C111578:
    // --- Basic Block 40 (0x00007FF71C111578 -> 0x00007FF71C1115A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3b88]);
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3c49]);
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF71C111510;
    } else {
        goto loc_7FF71C1115A0;
    }

loc_7FF71C1115A0:
    // --- Basic Block 41 (0x00007FF71C1115A0 -> 0x00007FF71C1115A8) ---
    r14d, 4; // mov
    goto loc_7FF71C11154E;

loc_7FF71C1115A8:
    // --- Basic Block 42 (0x00007FF71C1115A8 -> 0x00007FF71C1115B0) ---
    // asm: dec r15
    goto loc_7FF71C111510;

loc_7FF71C1115B0:
    // --- Basic Block 43 (0x00007FF71C1115B0 -> 0x00007FF71C1115C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF71C1115C2:
    // --- Basic Block 44 (0x00007FF71C1115C2 -> 0x00007FF71C1115E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b28]);
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C1115EC;
    } else {
        goto loc_7FF71C1115E2;
    }

loc_7FF71C1115E2:
    // --- Basic Block 45 (0x00007FF71C1115E2 -> 0x00007FF71C1115EC) ---
    rcx, r12; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b5d]);

loc_7FF71C1115EC:
    // --- Basic Block 46 (0x00007FF71C1115EC -> 0x00007FF71C111602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = indirect_call(qword ptr [rip + 0x3b13]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11160F;
    } else {
        goto loc_7FF71C111602;
    }

loc_7FF71C111602:
    // --- Basic Block 47 (0x00007FF71C111602 -> 0x00007FF71C11160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C11160F:
    // --- Basic Block 48 (0x00007FF71C11160F -> 0x00007FF71C111622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C111622:
    // --- Basic Block 49 (0x00007FF71C111622 -> 0x00007FF71C111684) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x3a91]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111691;
    } else {
        goto loc_7FF71C111684;
    }

loc_7FF71C111684:
    // --- Basic Block 50 (0x00007FF71C111684 -> 0x00007FF71C111691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111691:
    // --- Basic Block 51 (0x00007FF71C111691 -> 0x00007FF71C1116A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3ad4]);
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF71C111774;
    } else {
        goto loc_7FF71C1116A8;
    }

loc_7FF71C1116A8:
    // --- Basic Block 52 (0x00007FF71C1116A8 -> 0x00007FF71C1116B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C1116B9;
    } else {
        goto loc_7FF71C1116B6;
    }

loc_7FF71C1116B6:
    // --- Basic Block 53 (0x00007FF71C1116B6 -> 0x00007FF71C1116B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF71C1116B9:
    // --- Basic Block 54 (0x00007FF71C1116B9 -> 0x00007FF71C1116E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x3a44]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b1b]);
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF71C1116E0:
    // --- Basic Block 55 (0x00007FF71C1116E0 -> 0x00007FF71C1116E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C1116EC;
    } else {
        goto loc_7FF71C1116E5;
    }

loc_7FF71C1116E5:
    // --- Basic Block 56 (0x00007FF71C1116E5 -> 0x00007FF71C1116EC) ---
    ebx, 1; // mov
    goto loc_7FF71C111722;

loc_7FF71C1116EC:
    // --- Basic Block 57 (0x00007FF71C1116EC -> 0x00007FF71C1116F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF71C111717;
    } else {
        goto loc_7FF71C1116F1;
    }

loc_7FF71C1116F1:
    // --- Basic Block 58 (0x00007FF71C1116F1 -> 0x00007FF71C111717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x3a04]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3ae3]);
    goto loc_7FF71C111726;

loc_7FF71C111717:
    // --- Basic Block 59 (0x00007FF71C111717 -> 0x00007FF71C11171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF71C111728;
    } else {
        goto loc_7FF71C11171D;
    }

loc_7FF71C11171D:
    // --- Basic Block 60 (0x00007FF71C11171D -> 0x00007FF71C111722) ---
    ebx, 2; // mov

loc_7FF71C111722:
    // --- Basic Block 61 (0x00007FF71C111722 -> 0x00007FF71C111726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF71C111726:
    // --- Basic Block 62 (0x00007FF71C111726 -> 0x00007FF71C111728) ---
    goto loc_7FF71C11176F;

loc_7FF71C111728:
    // --- Basic Block 63 (0x00007FF71C111728 -> 0x00007FF71C111759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF71C1124C0(); // 0x7ff71c1124c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x39c2]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3a91]);
    goto loc_7FF71C1116E0;

loc_7FF71C111759:
    // --- Basic Block 64 (0x00007FF71C111759 -> 0x00007FF71C11176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF71C11176F:
    // --- Basic Block 65 (0x00007FF71C11176F -> 0x00007FF71C111774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF71C111777;
    } else {
        goto loc_7FF71C111774;
    }

loc_7FF71C111774:
    // --- Basic Block 66 (0x00007FF71C111774 -> 0x00007FF71C111777) ---
    // asm: or ebx, 2

loc_7FF71C111777:
    // --- Basic Block 67 (0x00007FF71C111777 -> 0x00007FF71C1117A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3974]);
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = indirect_call(qword ptr [rip + 0x3972]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1117B0;
    } else {
        goto loc_7FF71C1117A3;
    }

loc_7FF71C1117A3:
    // --- Basic Block 68 (0x00007FF71C1117A3 -> 0x00007FF71C1117B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1117B0:
    // --- Basic Block 69 (0x00007FF71C1117B0 -> 0x00007FF71C1117CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF71C1117CE:
    // --- Basic Block 70 (0x00007FF71C1117CE -> 0x00007FF71C11180C) ---
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11180C:
    // --- Basic Block 71 (0x00007FF71C11180C -> 0x00007FF71C11184C) ---
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11184C:
    // --- Basic Block 72 (0x00007FF71C11184C -> 0x00007FF71C111871) ---
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

loc_7FF71C111871:
    // --- Basic Block 73 (0x00007FF71C111871 -> 0x00007FF71C1118B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF71C1112F1` (0x7FF71C1112F1)
- **Size**: `1473 bytes` | **Complexity V(G)**: `21` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C1112F1 | Address: 0x00007FF71C1112F1
// Size: 1473 bytes | Basic Blocks: 66 | Complexity V(G): 21
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C1112F1(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C1112F1:
    // --- Basic Block 0 (0x00007FF71C1112F1 -> 0x00007FF71C111311) ---
    // asm: sub rsp, 0x20
    // asm: movabs rbp, 0x7fffffffffffffff
    rdi, r8; // mov
    r14, rdx; // mov
    rsi, rcx; // mov
    // asm: cmp r8, rbp
    if (ja_condition) {
        goto loc_7FF71C111392;
    } else {
        goto loc_7FF71C111311;
    }

loc_7FF71C111311:
    // --- Basic Block 1 (0x00007FF71C111311 -> 0x00007FF71C111317) ---
    // asm: cmp r8, 0xf
    if (ja_condition) {
        goto loc_7FF71C11132E;
    } else {
        goto loc_7FF71C111317;
    }

loc_7FF71C111317:
    // --- Basic Block 2 (0x00007FF71C111317 -> 0x00007FF71C11132E) ---
    qword ptr [rcx + 0x10], r8; // mov
    qword ptr [rcx + 0x18], 0xf; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [rdi + rsi], 0; // mov
    goto loc_7FF71C11137C;

loc_7FF71C11132E:
    // --- Basic Block 3 (0x00007FF71C11132E -> 0x00007FF71C11133F) ---
    rax, rdi; // mov
    qword ptr [rsp + 0x30], rbx; // mov
    // asm: or rax, 0xf
    // asm: cmp rax, rbp
    if (ja_condition) {
        goto loc_7FF71C11134E;
    } else {
        goto loc_7FF71C11133F;
    }

loc_7FF71C11133F:
    // --- Basic Block 4 (0x00007FF71C11133F -> 0x00007FF71C11134E) ---
    ecx, 0x16; // mov
    rbp, rax; // mov
    // asm: cmp rax, rcx
    // asm: cmovb rbp, rcx

loc_7FF71C11134E:
    // --- Basic Block 5 (0x00007FF71C11134E -> 0x00007FF71C11137C) ---
    rcx, [rbp + 1]; // lea
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    r8, rdi; // mov
    qword ptr [rsi], rax; // mov
    rdx, r14; // mov
    qword ptr [rsi + 0x10], rdi; // mov
    rcx, rax; // mov
    qword ptr [rsi + 0x18], rbp; // mov
    rbx, rax; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [rbx + rdi], 0; // mov
    rbx, qword ptr [rsp + 0x30]; // mov

loc_7FF71C11137C:
    // --- Basic Block 6 (0x00007FF71C11137C -> 0x00007FF71C111392) ---
    rbp, qword ptr [rsp + 0x38]; // mov
    rsi, qword ptr [rsp + 0x40]; // mov
    rdi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111392:
    // --- Basic Block 7 (0x00007FF71C111392 -> 0x00007FF71C1113E2) ---
    rax_result = sub_7FF71C1120A0(); // 0x7ff71c1120a0
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
    rax_result = indirect_call(qword ptr [rip + 0x3e3b]);
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF71C11140F;
    } else {
        goto loc_7FF71C1113E2;
    }

loc_7FF71C1113E2:
    // --- Basic Block 8 (0x00007FF71C1113E2 -> 0x00007FF71C1113F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3e26]);
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF71C11140F;
    } else {
        goto loc_7FF71C1113F7;
    }

loc_7FF71C1113F7:
    // --- Basic Block 9 (0x00007FF71C1113F7 -> 0x00007FF71C11140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3e11]);
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF71C111412;

loc_7FF71C11140F:
    // --- Basic Block 10 (0x00007FF71C11140F -> 0x00007FF71C111412) ---
    r15, r14; // mov

loc_7FF71C111412:
    // --- Basic Block 11 (0x00007FF71C111412 -> 0x00007FF71C11142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3ce6]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11143C;
    } else {
        goto loc_7FF71C11142F;
    }

loc_7FF71C11142F:
    // --- Basic Block 12 (0x00007FF71C11142F -> 0x00007FF71C11143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C11143C:
    // --- Basic Block 13 (0x00007FF71C11143C -> 0x00007FF71C111450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3dec]);
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C111456;
    } else {
        goto loc_7FF71C111450;
    }

loc_7FF71C111450:
    // --- Basic Block 14 (0x00007FF71C111450 -> 0x00007FF71C111456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C111496;

loc_7FF71C111456:
    // --- Basic Block 15 (0x00007FF71C111456 -> 0x00007FF71C11146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3ca2]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11148F;
    } else {
        goto loc_7FF71C11146B;
    }

loc_7FF71C11146B:
    // --- Basic Block 16 (0x00007FF71C11146B -> 0x00007FF71C111470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF71C11148F;
    } else {
        goto loc_7FF71C111470;
    }

loc_7FF71C111470:
    // --- Basic Block 17 (0x00007FF71C111470 -> 0x00007FF71C11148F) ---
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3cef]);
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3daf]);
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C111496;

loc_7FF71C11148F:
    // --- Basic Block 18 (0x00007FF71C11148F -> 0x00007FF71C111496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF71C111496:
    // --- Basic Block 19 (0x00007FF71C111496 -> 0x00007FF71C11149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C1114A5;
    } else {
        goto loc_7FF71C11149A;
    }

loc_7FF71C11149A:
    // --- Basic Block 20 (0x00007FF71C11149A -> 0x00007FF71C1114A5) ---
    r14d, 4; // mov
    goto loc_7FF71C1115C2;

loc_7FF71C1114A5:
    // --- Basic Block 21 (0x00007FF71C1114A5 -> 0x00007FF71C1114C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3d7b]);
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF71C111578;
    } else {
        goto loc_7FF71C1114C3;
    }

loc_7FF71C1114C3:
    // --- Basic Block 22 (0x00007FF71C1114C3 -> 0x00007FF71C1114CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF71C111573;
    } else {
        goto loc_7FF71C1114CC;
    }

loc_7FF71C1114CC:
    // --- Basic Block 23 (0x00007FF71C1114CC -> 0x00007FF71C111501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3c35]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3c21]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3c44]);
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C11156B;
    } else {
        goto loc_7FF71C111501;
    }

loc_7FF71C111501:
    // --- Basic Block 24 (0x00007FF71C111501 -> 0x00007FF71C111510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF71C111510:
    // --- Basic Block 25 (0x00007FF71C111510 -> 0x00007FF71C111515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF71C111556;
    } else {
        goto loc_7FF71C111515;
    }

loc_7FF71C111515:
    // --- Basic Block 26 (0x00007FF71C111515 -> 0x00007FF71C11154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3bec]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3bd8]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3bfb]);
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C1115A8;
    } else {
        goto loc_7FF71C11154A;
    }

loc_7FF71C11154A:
    // --- Basic Block 27 (0x00007FF71C11154A -> 0x00007FF71C11154E) ---
    // asm: or r14d, 4

loc_7FF71C11154E:
    // --- Basic Block 28 (0x00007FF71C11154E -> 0x00007FF71C111556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF71C111556:
    // --- Basic Block 29 (0x00007FF71C111556 -> 0x00007FF71C11156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x3ca8]);
    goto loc_7FF71C1115C2;

loc_7FF71C11156B:
    // --- Basic Block 30 (0x00007FF71C11156B -> 0x00007FF71C111573) ---
    // asm: dec r15
    goto loc_7FF71C1114C3;

loc_7FF71C111573:
    // --- Basic Block 31 (0x00007FF71C111573 -> 0x00007FF71C111578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF71C111578:
    // --- Basic Block 32 (0x00007FF71C111578 -> 0x00007FF71C1115A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3b88]);
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3c49]);
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF71C111510;
    } else {
        goto loc_7FF71C1115A0;
    }

loc_7FF71C1115A0:
    // --- Basic Block 33 (0x00007FF71C1115A0 -> 0x00007FF71C1115A8) ---
    r14d, 4; // mov
    goto loc_7FF71C11154E;

loc_7FF71C1115A8:
    // --- Basic Block 34 (0x00007FF71C1115A8 -> 0x00007FF71C1115B0) ---
    // asm: dec r15
    goto loc_7FF71C111510;

loc_7FF71C1115B0:
    // --- Basic Block 35 (0x00007FF71C1115B0 -> 0x00007FF71C1115C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF71C1115C2:
    // --- Basic Block 36 (0x00007FF71C1115C2 -> 0x00007FF71C1115E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b28]);
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C1115EC;
    } else {
        goto loc_7FF71C1115E2;
    }

loc_7FF71C1115E2:
    // --- Basic Block 37 (0x00007FF71C1115E2 -> 0x00007FF71C1115EC) ---
    rcx, r12; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b5d]);

loc_7FF71C1115EC:
    // --- Basic Block 38 (0x00007FF71C1115EC -> 0x00007FF71C111602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = indirect_call(qword ptr [rip + 0x3b13]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11160F;
    } else {
        goto loc_7FF71C111602;
    }

loc_7FF71C111602:
    // --- Basic Block 39 (0x00007FF71C111602 -> 0x00007FF71C11160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C11160F:
    // --- Basic Block 40 (0x00007FF71C11160F -> 0x00007FF71C111622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C111622:
    // --- Basic Block 41 (0x00007FF71C111622 -> 0x00007FF71C111684) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x3a91]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111691;
    } else {
        goto loc_7FF71C111684;
    }

loc_7FF71C111684:
    // --- Basic Block 42 (0x00007FF71C111684 -> 0x00007FF71C111691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111691:
    // --- Basic Block 43 (0x00007FF71C111691 -> 0x00007FF71C1116A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3ad4]);
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF71C111774;
    } else {
        goto loc_7FF71C1116A8;
    }

loc_7FF71C1116A8:
    // --- Basic Block 44 (0x00007FF71C1116A8 -> 0x00007FF71C1116B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C1116B9;
    } else {
        goto loc_7FF71C1116B6;
    }

loc_7FF71C1116B6:
    // --- Basic Block 45 (0x00007FF71C1116B6 -> 0x00007FF71C1116B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF71C1116B9:
    // --- Basic Block 46 (0x00007FF71C1116B9 -> 0x00007FF71C1116E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x3a44]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b1b]);
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF71C1116E0:
    // --- Basic Block 47 (0x00007FF71C1116E0 -> 0x00007FF71C1116E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C1116EC;
    } else {
        goto loc_7FF71C1116E5;
    }

loc_7FF71C1116E5:
    // --- Basic Block 48 (0x00007FF71C1116E5 -> 0x00007FF71C1116EC) ---
    ebx, 1; // mov
    goto loc_7FF71C111722;

loc_7FF71C1116EC:
    // --- Basic Block 49 (0x00007FF71C1116EC -> 0x00007FF71C1116F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF71C111717;
    } else {
        goto loc_7FF71C1116F1;
    }

loc_7FF71C1116F1:
    // --- Basic Block 50 (0x00007FF71C1116F1 -> 0x00007FF71C111717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x3a04]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3ae3]);
    goto loc_7FF71C111726;

loc_7FF71C111717:
    // --- Basic Block 51 (0x00007FF71C111717 -> 0x00007FF71C11171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF71C111728;
    } else {
        goto loc_7FF71C11171D;
    }

loc_7FF71C11171D:
    // --- Basic Block 52 (0x00007FF71C11171D -> 0x00007FF71C111722) ---
    ebx, 2; // mov

loc_7FF71C111722:
    // --- Basic Block 53 (0x00007FF71C111722 -> 0x00007FF71C111726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF71C111726:
    // --- Basic Block 54 (0x00007FF71C111726 -> 0x00007FF71C111728) ---
    goto loc_7FF71C11176F;

loc_7FF71C111728:
    // --- Basic Block 55 (0x00007FF71C111728 -> 0x00007FF71C111759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF71C1124C0(); // 0x7ff71c1124c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x39c2]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3a91]);
    goto loc_7FF71C1116E0;

loc_7FF71C111759:
    // --- Basic Block 56 (0x00007FF71C111759 -> 0x00007FF71C11176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF71C11176F:
    // --- Basic Block 57 (0x00007FF71C11176F -> 0x00007FF71C111774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF71C111777;
    } else {
        goto loc_7FF71C111774;
    }

loc_7FF71C111774:
    // --- Basic Block 58 (0x00007FF71C111774 -> 0x00007FF71C111777) ---
    // asm: or ebx, 2

loc_7FF71C111777:
    // --- Basic Block 59 (0x00007FF71C111777 -> 0x00007FF71C1117A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3974]);
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = indirect_call(qword ptr [rip + 0x3972]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1117B0;
    } else {
        goto loc_7FF71C1117A3;
    }

loc_7FF71C1117A3:
    // --- Basic Block 60 (0x00007FF71C1117A3 -> 0x00007FF71C1117B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1117B0:
    // --- Basic Block 61 (0x00007FF71C1117B0 -> 0x00007FF71C1117CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF71C1117CE:
    // --- Basic Block 62 (0x00007FF71C1117CE -> 0x00007FF71C11180C) ---
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11180C:
    // --- Basic Block 63 (0x00007FF71C11180C -> 0x00007FF71C11184C) ---
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11184C:
    // --- Basic Block 64 (0x00007FF71C11184C -> 0x00007FF71C111871) ---
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

loc_7FF71C111871:
    // --- Basic Block 65 (0x00007FF71C111871 -> 0x00007FF71C1118B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF71C1113B5` (0x7FF71C1113B5)
- **Size**: `1593 bytes` | **Complexity V(G)**: `23` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C1113B5 | Address: 0x00007FF71C1113B5
// Size: 1593 bytes | Basic Blocks: 72 | Complexity V(G): 23
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C1113B5(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C1113B5:
    // --- Basic Block 0 (0x00007FF71C1113B5 -> 0x00007FF71C1113E2) ---
    // asm: sub rsp, 0x30
    r13, r8; // mov
    rbx, rdx; // mov
    rsi, rcx; // mov
    // asm: xor r14d, r14d
    dword ptr [rsp + 0x88], r14d; // mov
    rax, qword ptr [rcx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3e3b]);
    // asm: test rax, rax
    if (jle_condition) {
        goto loc_7FF71C11140F;
    } else {
        goto loc_7FF71C1113E2;
    }

loc_7FF71C1113E2:
    // --- Basic Block 1 (0x00007FF71C1113E2 -> 0x00007FF71C1113F7) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3e26]);
    // asm: cmp rax, r13
    if (jbe_condition) {
        goto loc_7FF71C11140F;
    } else {
        goto loc_7FF71C1113F7;
    }

loc_7FF71C1113F7:
    // --- Basic Block 2 (0x00007FF71C1113F7 -> 0x00007FF71C11140F) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3e11]);
    r15, rax; // mov
    // asm: sub r15, r13
    goto loc_7FF71C111412;

loc_7FF71C11140F:
    // --- Basic Block 3 (0x00007FF71C11140F -> 0x00007FF71C111412) ---
    r15, r14; // mov

loc_7FF71C111412:
    // --- Basic Block 4 (0x00007FF71C111412 -> 0x00007FF71C11142F) ---
    r12, rsi; // mov
    qword ptr [rsp + 0x20], rsi; // mov
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3ce6]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11143C;
    } else {
        goto loc_7FF71C11142F;
    }

loc_7FF71C11142F:
    // --- Basic Block 5 (0x00007FF71C11142F -> 0x00007FF71C11143C) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C11143C:
    // --- Basic Block 6 (0x00007FF71C11143C -> 0x00007FF71C111450) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3dec]);
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C111456;
    } else {
        goto loc_7FF71C111450;
    }

loc_7FF71C111450:
    // --- Basic Block 7 (0x00007FF71C111450 -> 0x00007FF71C111456) ---
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C111496;

loc_7FF71C111456:
    // --- Basic Block 8 (0x00007FF71C111456 -> 0x00007FF71C11146B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3ca2]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11148F;
    } else {
        goto loc_7FF71C11146B;
    }

loc_7FF71C11146B:
    // --- Basic Block 9 (0x00007FF71C11146B -> 0x00007FF71C111470) ---
    // asm: cmp rax, rsi
    if (je_condition) {
        goto loc_7FF71C11148F;
    } else {
        goto loc_7FF71C111470;
    }

loc_7FF71C111470:
    // --- Basic Block 10 (0x00007FF71C111470 -> 0x00007FF71C11148F) ---
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3cef]);
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3daf]);
    byte ptr [rsp + 0x28], al; // mov
    goto loc_7FF71C111496;

loc_7FF71C11148F:
    // --- Basic Block 11 (0x00007FF71C11148F -> 0x00007FF71C111496) ---
    byte ptr [rsp + 0x28], 1; // mov
    al, 1; // mov

loc_7FF71C111496:
    // --- Basic Block 12 (0x00007FF71C111496 -> 0x00007FF71C11149A) ---
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C1114A5;
    } else {
        goto loc_7FF71C11149A;
    }

loc_7FF71C11149A:
    // --- Basic Block 13 (0x00007FF71C11149A -> 0x00007FF71C1114A5) ---
    r14d, 4; // mov
    goto loc_7FF71C1115C2;

loc_7FF71C1114A5:
    // --- Basic Block 14 (0x00007FF71C1114A5 -> 0x00007FF71C1114C3) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3d7b]);
    // asm: and eax, 0x1c0
    // asm: cmp eax, 0x40
    if (je_condition) {
        goto loc_7FF71C111578;
    } else {
        goto loc_7FF71C1114C3;
    }

loc_7FF71C1114C3:
    // --- Basic Block 15 (0x00007FF71C1114C3 -> 0x00007FF71C1114CC) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF71C111573;
    } else {
        goto loc_7FF71C1114CC;
    }

loc_7FF71C1114CC:
    // --- Basic Block 16 (0x00007FF71C1114CC -> 0x00007FF71C111501) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3c35]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3c21]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3c44]);
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C11156B;
    } else {
        goto loc_7FF71C111501;
    }

loc_7FF71C111501:
    // --- Basic Block 17 (0x00007FF71C111501 -> 0x00007FF71C111510) ---
    r14d, 4; // mov
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF71C111510:
    // --- Basic Block 18 (0x00007FF71C111510 -> 0x00007FF71C111515) ---
    // asm: test r15, r15
    if (je_condition) {
        goto loc_7FF71C111556;
    } else {
        goto loc_7FF71C111515;
    }

loc_7FF71C111515:
    // --- Basic Block 19 (0x00007FF71C111515 -> 0x00007FF71C11154A) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    // asm: movsxd rbx, dword ptr [rax + 4]
    // asm: add rbx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3bec]);
    // asm: movzx edi, al
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3bd8]);
    rcx, rax; // mov
    // asm: movzx edx, dil
    rax_result = indirect_call(qword ptr [rip + 0x3bfb]);
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C1115A8;
    } else {
        goto loc_7FF71C11154A;
    }

loc_7FF71C11154A:
    // --- Basic Block 20 (0x00007FF71C11154A -> 0x00007FF71C11154E) ---
    // asm: or r14d, 4

loc_7FF71C11154E:
    // --- Basic Block 21 (0x00007FF71C11154E -> 0x00007FF71C111556) ---
    dword ptr [rsp + 0x88], r14d; // mov

loc_7FF71C111556:
    // --- Basic Block 22 (0x00007FF71C111556 -> 0x00007FF71C11156B) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    edx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x3ca8]);
    goto loc_7FF71C1115C2;

loc_7FF71C11156B:
    // --- Basic Block 23 (0x00007FF71C11156B -> 0x00007FF71C111573) ---
    // asm: dec r15
    goto loc_7FF71C1114C3;

loc_7FF71C111573:
    // --- Basic Block 24 (0x00007FF71C111573 -> 0x00007FF71C111578) ---
    rbx, qword ptr [rsp + 0x78]; // mov

loc_7FF71C111578:
    // --- Basic Block 25 (0x00007FF71C111578 -> 0x00007FF71C1115A0) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    rax_result = indirect_call(qword ptr [rip + 0x3b88]);
    rcx, rax; // mov
    r8, r13; // mov
    rdx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3c49]);
    // asm: cmp rax, r13
    if (je_condition) {
        goto loc_7FF71C111510;
    } else {
        goto loc_7FF71C1115A0;
    }

loc_7FF71C1115A0:
    // --- Basic Block 26 (0x00007FF71C1115A0 -> 0x00007FF71C1115A8) ---
    r14d, 4; // mov
    goto loc_7FF71C11154E;

loc_7FF71C1115A8:
    // --- Basic Block 27 (0x00007FF71C1115A8 -> 0x00007FF71C1115B0) ---
    // asm: dec r15
    goto loc_7FF71C111510;

loc_7FF71C1115B0:
    // --- Basic Block 28 (0x00007FF71C1115B0 -> 0x00007FF71C1115C2) ---
    rsi, qword ptr [rsp + 0x70]; // mov
    r14d, dword ptr [rsp + 0x88]; // mov
    r12, qword ptr [rsp + 0x20]; // mov

loc_7FF71C1115C2:
    // --- Basic Block 29 (0x00007FF71C1115C2 -> 0x00007FF71C1115E2) ---
    rax, qword ptr [rsi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rsi
    r8d = 0;
    edx, r14d; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b28]);
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C1115EC;
    } else {
        goto loc_7FF71C1115E2;
    }

loc_7FF71C1115E2:
    // --- Basic Block 30 (0x00007FF71C1115E2 -> 0x00007FF71C1115EC) ---
    rcx, r12; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b5d]);

loc_7FF71C1115EC:
    // --- Basic Block 31 (0x00007FF71C1115EC -> 0x00007FF71C111602) ---
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = indirect_call(qword ptr [rip + 0x3b13]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C11160F;
    } else {
        goto loc_7FF71C111602;
    }

loc_7FF71C111602:
    // --- Basic Block 32 (0x00007FF71C111602 -> 0x00007FF71C11160F) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C11160F:
    // --- Basic Block 33 (0x00007FF71C11160F -> 0x00007FF71C111622) ---
    rax, rsi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C111622:
    // --- Basic Block 34 (0x00007FF71C111622 -> 0x00007FF71C111684) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x3a91]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111691;
    } else {
        goto loc_7FF71C111684;
    }

loc_7FF71C111684:
    // --- Basic Block 35 (0x00007FF71C111684 -> 0x00007FF71C111691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111691:
    // --- Basic Block 36 (0x00007FF71C111691 -> 0x00007FF71C1116A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3ad4]);
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF71C111774;
    } else {
        goto loc_7FF71C1116A8;
    }

loc_7FF71C1116A8:
    // --- Basic Block 37 (0x00007FF71C1116A8 -> 0x00007FF71C1116B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C1116B9;
    } else {
        goto loc_7FF71C1116B6;
    }

loc_7FF71C1116B6:
    // --- Basic Block 38 (0x00007FF71C1116B6 -> 0x00007FF71C1116B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF71C1116B9:
    // --- Basic Block 39 (0x00007FF71C1116B9 -> 0x00007FF71C1116E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x3a44]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b1b]);
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF71C1116E0:
    // --- Basic Block 40 (0x00007FF71C1116E0 -> 0x00007FF71C1116E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C1116EC;
    } else {
        goto loc_7FF71C1116E5;
    }

loc_7FF71C1116E5:
    // --- Basic Block 41 (0x00007FF71C1116E5 -> 0x00007FF71C1116EC) ---
    ebx, 1; // mov
    goto loc_7FF71C111722;

loc_7FF71C1116EC:
    // --- Basic Block 42 (0x00007FF71C1116EC -> 0x00007FF71C1116F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF71C111717;
    } else {
        goto loc_7FF71C1116F1;
    }

loc_7FF71C1116F1:
    // --- Basic Block 43 (0x00007FF71C1116F1 -> 0x00007FF71C111717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x3a04]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3ae3]);
    goto loc_7FF71C111726;

loc_7FF71C111717:
    // --- Basic Block 44 (0x00007FF71C111717 -> 0x00007FF71C11171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF71C111728;
    } else {
        goto loc_7FF71C11171D;
    }

loc_7FF71C11171D:
    // --- Basic Block 45 (0x00007FF71C11171D -> 0x00007FF71C111722) ---
    ebx, 2; // mov

loc_7FF71C111722:
    // --- Basic Block 46 (0x00007FF71C111722 -> 0x00007FF71C111726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF71C111726:
    // --- Basic Block 47 (0x00007FF71C111726 -> 0x00007FF71C111728) ---
    goto loc_7FF71C11176F;

loc_7FF71C111728:
    // --- Basic Block 48 (0x00007FF71C111728 -> 0x00007FF71C111759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF71C1124C0(); // 0x7ff71c1124c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x39c2]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3a91]);
    goto loc_7FF71C1116E0;

loc_7FF71C111759:
    // --- Basic Block 49 (0x00007FF71C111759 -> 0x00007FF71C11176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF71C11176F:
    // --- Basic Block 50 (0x00007FF71C11176F -> 0x00007FF71C111774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF71C111777;
    } else {
        goto loc_7FF71C111774;
    }

loc_7FF71C111774:
    // --- Basic Block 51 (0x00007FF71C111774 -> 0x00007FF71C111777) ---
    // asm: or ebx, 2

loc_7FF71C111777:
    // --- Basic Block 52 (0x00007FF71C111777 -> 0x00007FF71C1117A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3974]);
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = indirect_call(qword ptr [rip + 0x3972]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1117B0;
    } else {
        goto loc_7FF71C1117A3;
    }

loc_7FF71C1117A3:
    // --- Basic Block 53 (0x00007FF71C1117A3 -> 0x00007FF71C1117B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1117B0:
    // --- Basic Block 54 (0x00007FF71C1117B0 -> 0x00007FF71C1117CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF71C1117CE:
    // --- Basic Block 55 (0x00007FF71C1117CE -> 0x00007FF71C11180C) ---
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11180C:
    // --- Basic Block 56 (0x00007FF71C11180C -> 0x00007FF71C11184C) ---
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11184C:
    // --- Basic Block 57 (0x00007FF71C11184C -> 0x00007FF71C111871) ---
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

loc_7FF71C111871:
    // --- Basic Block 58 (0x00007FF71C111871 -> 0x00007FF71C1118B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1118B2:
    // --- Basic Block 59 (0x00007FF71C1118B2 -> 0x00007FF71C1118C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF71C112020;

loc_7FF71C1118C5:
    // --- Basic Block 60 (0x00007FF71C1118C5 -> 0x00007FF71C1118F2) ---
    // asm: int3 
    // asm: int3 
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
        goto loc_7FF71C111955;
    } else {
        goto loc_7FF71C1118F2;
    }

loc_7FF71C1118F2:
    // --- Basic Block 61 (0x00007FF71C1118F2 -> 0x00007FF71C111900) ---
    rax_result = indirect_call(qword ptr [rip + 0x37c0]);
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111908;
    } else {
        goto loc_7FF71C111900;
    }

loc_7FF71C111900:
    // --- Basic Block 62 (0x00007FF71C111900 -> 0x00007FF71C111908) ---
    rax_result = indirect_call(qword ptr [rip + 0x37d2]);
    goto loc_7FF71C11190E;

loc_7FF71C111908:
    // --- Basic Block 63 (0x00007FF71C111908 -> 0x00007FF71C11190E) ---
    rax_result = indirect_call(qword ptr [rip + 0x37b2]);

loc_7FF71C11190E:
    // --- Basic Block 64 (0x00007FF71C11190E -> 0x00007FF71C111932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3786]);
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x377a]);
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11194A;
    } else {
        goto loc_7FF71C111932;
    }

loc_7FF71C111932:
    // --- Basic Block 65 (0x00007FF71C111932 -> 0x00007FF71C111947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF71C111999;
    } else {
        goto loc_7FF71C111947;
    }

loc_7FF71C111947:
    // --- Basic Block 66 (0x00007FF71C111947 -> 0x00007FF71C11194A) ---
    rdi, rax; // mov

loc_7FF71C11194A:
    // --- Basic Block 67 (0x00007FF71C11194A -> 0x00007FF71C111955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111955:
    // --- Basic Block 68 (0x00007FF71C111955 -> 0x00007FF71C111999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x376a]);
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x376c]);
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_0;

loc_7FF71C111999:
    // --- Basic Block 69 (0x00007FF71C111999 -> 0x00007FF71C1119DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x39ce]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x3739]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1119E9;
    } else {
        goto loc_7FF71C1119DC;
    }

loc_7FF71C1119DC:
    // --- Basic Block 70 (0x00007FF71C1119DC -> 0x00007FF71C1119E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1119E9:
    // --- Basic Block 71 (0x00007FF71C1119E9 -> 0x00007FF71C1119EE) ---
    // asm: add rsp, 0x28
    return rax_result;

}
```

### Function `sub_00007FF71C111630` (0x7FF71C111630)
- **Size**: `1506 bytes` | **Complexity V(G)**: `10` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111630 | Address: 0x00007FF71C111630
// Size: 1506 bytes | Basic Blocks: 59 | Complexity V(G): 10
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111630(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111630:
    // --- Basic Block 0 (0x00007FF71C111630 -> 0x00007FF71C111684) ---
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
    rax_result = indirect_call(qword ptr [rip + 0x3a91]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111691;
    } else {
        goto loc_7FF71C111684;
    }

loc_7FF71C111684:
    // --- Basic Block 1 (0x00007FF71C111684 -> 0x00007FF71C111691) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 8]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111691:
    // --- Basic Block 2 (0x00007FF71C111691 -> 0x00007FF71C1116A8) ---
    dl, 1; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3ad4]);
    byte ptr [rsp + 0x30], al; // mov
    // asm: test al, al
    if (je_condition) {
        goto loc_7FF71C111774;
    } else {
        goto loc_7FF71C1116A8;
    }

loc_7FF71C1116A8:
    // --- Basic Block 3 (0x00007FF71C1116A8 -> 0x00007FF71C1116B6) ---
    qword ptr [r14 + 0x10], rbx; // mov
    rax, r14; // mov
    // asm: cmp qword ptr [r14 + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C1116B9;
    } else {
        goto loc_7FF71C1116B6;
    }

loc_7FF71C1116B6:
    // --- Basic Block 4 (0x00007FF71C1116B6 -> 0x00007FF71C1116B9) ---
    rax, qword ptr [r14]; // mov

loc_7FF71C1116B9:
    // --- Basic Block 5 (0x00007FF71C1116B9 -> 0x00007FF71C1116E0) ---
    byte ptr [rax], 0; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x3a44]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3b1b]);
    // asm: movabs r13, 0x7fffffffffffffff

loc_7FF71C1116E0:
    // --- Basic Block 6 (0x00007FF71C1116E0 -> 0x00007FF71C1116E5) ---
    // asm: cmp eax, -1
    if (jne_condition) {
        goto loc_7FF71C1116EC;
    } else {
        goto loc_7FF71C1116E5;
    }

loc_7FF71C1116E5:
    // --- Basic Block 7 (0x00007FF71C1116E5 -> 0x00007FF71C1116EC) ---
    ebx, 1; // mov
    goto loc_7FF71C111722;

loc_7FF71C1116EC:
    // --- Basic Block 8 (0x00007FF71C1116EC -> 0x00007FF71C1116F1) ---
    // asm: cmp eax, r15d
    if (jne_condition) {
        goto loc_7FF71C111717;
    } else {
        goto loc_7FF71C1116F1;
    }

loc_7FF71C1116F1:
    // --- Basic Block 9 (0x00007FF71C1116F1 -> 0x00007FF71C111717) ---
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x3a04]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3ae3]);
    goto loc_7FF71C111726;

loc_7FF71C111717:
    // --- Basic Block 10 (0x00007FF71C111717 -> 0x00007FF71C11171D) ---
    // asm: cmp qword ptr [r14 + 0x10], r13
    if (jb_condition) {
        goto loc_7FF71C111728;
    } else {
        goto loc_7FF71C11171D;
    }

loc_7FF71C11171D:
    // --- Basic Block 11 (0x00007FF71C11171D -> 0x00007FF71C111722) ---
    ebx, 2; // mov

loc_7FF71C111722:
    // --- Basic Block 12 (0x00007FF71C111722 -> 0x00007FF71C111726) ---
    dword ptr [rsp + 0x20], ebx; // mov

loc_7FF71C111726:
    // --- Basic Block 13 (0x00007FF71C111726 -> 0x00007FF71C111728) ---
    goto loc_7FF71C11176F;

loc_7FF71C111728:
    // --- Basic Block 14 (0x00007FF71C111728 -> 0x00007FF71C111759) ---
    // asm: movzx edx, al
    rcx, r14; // mov
    rax_result = sub_7FF71C1124C0(); // 0x7ff71c1124c0
    sil, 1; // mov
    byte ptr [rsp + 0x88], sil; // mov
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    rax_result = indirect_call(qword ptr [rip + 0x39c2]);
    rcx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3a91]);
    goto loc_7FF71C1116E0;

loc_7FF71C111759:
    // --- Basic Block 15 (0x00007FF71C111759 -> 0x00007FF71C11176F) ---
    rdi, qword ptr [rsp + 0x70]; // mov
    ebx, dword ptr [rsp + 0x20]; // mov
    // asm: movzx esi, byte ptr [rsp + 0x88]
    r12, qword ptr [rsp + 0x28]; // mov

loc_7FF71C11176F:
    // --- Basic Block 16 (0x00007FF71C11176F -> 0x00007FF71C111774) ---
    // asm: test sil, sil
    if (jne_condition) {
        goto loc_7FF71C111777;
    } else {
        goto loc_7FF71C111774;
    }

loc_7FF71C111774:
    // --- Basic Block 17 (0x00007FF71C111774 -> 0x00007FF71C111777) ---
    // asm: or ebx, 2

loc_7FF71C111777:
    // --- Basic Block 18 (0x00007FF71C111777 -> 0x00007FF71C1117A3) ---
    rax, qword ptr [rdi]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdi
    r8d = 0;
    edx, ebx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3974]);
    rax, qword ptr [r12]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, r12
    rax_result = indirect_call(qword ptr [rip + 0x3972]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1117B0;
    } else {
        goto loc_7FF71C1117A3;
    }

loc_7FF71C1117A3:
    // --- Basic Block 19 (0x00007FF71C1117A3 -> 0x00007FF71C1117B0) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1117B0:
    // --- Basic Block 20 (0x00007FF71C1117B0 -> 0x00007FF71C1117CE) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x78]; // mov
    rsi, qword ptr [rsp + 0x80]; // mov
    // asm: add rsp, 0x40
    return rax_result;

loc_7FF71C1117CE:
    // --- Basic Block 21 (0x00007FF71C1117CE -> 0x00007FF71C11180C) ---
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11180C:
    // --- Basic Block 22 (0x00007FF71C11180C -> 0x00007FF71C11184C) ---
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11184C:
    // --- Basic Block 23 (0x00007FF71C11184C -> 0x00007FF71C111871) ---
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

loc_7FF71C111871:
    // --- Basic Block 24 (0x00007FF71C111871 -> 0x00007FF71C1118B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1118B2:
    // --- Basic Block 25 (0x00007FF71C1118B2 -> 0x00007FF71C1118C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF71C112020;

loc_7FF71C1118C5:
    // --- Basic Block 26 (0x00007FF71C1118C5 -> 0x00007FF71C1118F2) ---
    // asm: int3 
    // asm: int3 
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
        goto loc_7FF71C111955;
    } else {
        goto loc_7FF71C1118F2;
    }

loc_7FF71C1118F2:
    // --- Basic Block 27 (0x00007FF71C1118F2 -> 0x00007FF71C111900) ---
    rax_result = indirect_call(qword ptr [rip + 0x37c0]);
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111908;
    } else {
        goto loc_7FF71C111900;
    }

loc_7FF71C111900:
    // --- Basic Block 28 (0x00007FF71C111900 -> 0x00007FF71C111908) ---
    rax_result = indirect_call(qword ptr [rip + 0x37d2]);
    goto loc_7FF71C11190E;

loc_7FF71C111908:
    // --- Basic Block 29 (0x00007FF71C111908 -> 0x00007FF71C11190E) ---
    rax_result = indirect_call(qword ptr [rip + 0x37b2]);

loc_7FF71C11190E:
    // --- Basic Block 30 (0x00007FF71C11190E -> 0x00007FF71C111932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3786]);
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x377a]);
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11194A;
    } else {
        goto loc_7FF71C111932;
    }

loc_7FF71C111932:
    // --- Basic Block 31 (0x00007FF71C111932 -> 0x00007FF71C111947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF71C111999;
    } else {
        goto loc_7FF71C111947;
    }

loc_7FF71C111947:
    // --- Basic Block 32 (0x00007FF71C111947 -> 0x00007FF71C11194A) ---
    rdi, rax; // mov

loc_7FF71C11194A:
    // --- Basic Block 33 (0x00007FF71C11194A -> 0x00007FF71C111955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111955:
    // --- Basic Block 34 (0x00007FF71C111955 -> 0x00007FF71C111999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x376a]);
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x376c]);
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_0;

loc_7FF71C111999:
    // --- Basic Block 35 (0x00007FF71C111999 -> 0x00007FF71C1119DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x39ce]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x3739]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1119E9;
    } else {
        goto loc_7FF71C1119DC;
    }

loc_7FF71C1119DC:
    // --- Basic Block 36 (0x00007FF71C1119DC -> 0x00007FF71C1119E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1119E9:
    // --- Basic Block 37 (0x00007FF71C1119E9 -> 0x00007FF71C1119EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF71C1119EE:
    // --- Basic Block 38 (0x00007FF71C1119EE -> 0x00007FF71C111A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF71C1140EC;

loc_7FF71C111A03:
    // --- Basic Block 39 (0x00007FF71C111A03 -> 0x00007FF71C111A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x36e9]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111A39;
    } else {
        goto loc_7FF71C111A2C;
    }

loc_7FF71C111A2C:
    // --- Basic Block 40 (0x00007FF71C111A2C -> 0x00007FF71C111A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111A39:
    // --- Basic Block 41 (0x00007FF71C111A39 -> 0x00007FF71C111A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF71C111A3E:
    // --- Basic Block 42 (0x00007FF71C111A3E -> 0x00007FF71C111A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C111A5C;
    } else {
        goto loc_7FF71C111A52;
    }

loc_7FF71C111A52:
    // --- Basic Block 43 (0x00007FF71C111A52 -> 0x00007FF71C111A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = indirect_call(qword ptr [rip + 0x36ed]);

loc_7FF71C111A5C:
    // --- Basic Block 44 (0x00007FF71C111A5C -> 0x00007FF71C111A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = indirect_call(qword ptr [rip + 0x36a1]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111A81;
    } else {
        goto loc_7FF71C111A74;
    }

loc_7FF71C111A74:
    // --- Basic Block 45 (0x00007FF71C111A74 -> 0x00007FF71C111A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111A81:
    // --- Basic Block 46 (0x00007FF71C111A81 -> 0x00007FF71C111A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111A87:
    // --- Basic Block 47 (0x00007FF71C111A87 -> 0x00007FF71C111AEB) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x377c]);
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_0;

loc_7FF71C111AEB:
    // --- Basic Block 48 (0x00007FF71C111AEB -> 0x00007FF71C111AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF71C111B00;

loc_7FF71C111AF8:
    // --- Basic Block 49 (0x00007FF71C111AF8 -> 0x00007FF71C111B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF71C111B00:
    // --- Basic Block 50 (0x00007FF71C111B00 -> 0x00007FF71C111B69) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x36fe]);
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3595]);
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF71C111B76;
    } else {
        goto loc_7FF71C111B69;
    }

loc_7FF71C111B69:
    // --- Basic Block 51 (0x00007FF71C111B69 -> 0x00007FF71C111B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111B76:
    // --- Basic Block 52 (0x00007FF71C111B76 -> 0x00007FF71C111B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111B89:
    // --- Basic Block 53 (0x00007FF71C111B89 -> 0x00007FF71C111BA9) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111BB6;
    } else {
        goto loc_7FF71C111BA9;
    }

loc_7FF71C111BA9:
    // --- Basic Block 54 (0x00007FF71C111BA9 -> 0x00007FF71C111BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111BB6:
    // --- Basic Block 55 (0x00007FF71C111BB6 -> 0x00007FF71C111BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111BC4:
    // --- Basic Block 56 (0x00007FF71C111BC4 -> 0x00007FF71C111BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140EC(); // 0x7ff71c1140ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111C04;
    } else {
        goto loc_7FF71C111BF7;
    }

loc_7FF71C111BF7:
    // --- Basic Block 57 (0x00007FF71C111BF7 -> 0x00007FF71C111C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111C04:
    // --- Basic Block 58 (0x00007FF71C111C04 -> 0x00007FF71C111C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF71C1117D0` (0x7FF71C1117D0)
- **Size**: `1321 bytes` | **Complexity V(G)**: `5` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C1117D0 | Address: 0x00007FF71C1117D0
// Size: 1321 bytes | Basic Blocks: 45 | Complexity V(G): 5
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C1117D0(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C1117D0:
    // --- Basic Block 0 (0x00007FF71C1117D0 -> 0x00007FF71C11180C) ---
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3d45]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d58]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11180C:
    // --- Basic Block 1 (0x00007FF71C11180C -> 0x00007FF71C11184C) ---
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, [rip + 0x3d30]; // lea
    qword ptr [rbx], rax; // mov
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11184C:
    // --- Basic Block 2 (0x00007FF71C11184C -> 0x00007FF71C111871) ---
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

loc_7FF71C111871:
    // --- Basic Block 3 (0x00007FF71C111871 -> 0x00007FF71C1118B2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1118B2:
    // --- Basic Block 4 (0x00007FF71C1118B2 -> 0x00007FF71C1118C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF71C112020;

loc_7FF71C1118C5:
    // --- Basic Block 5 (0x00007FF71C1118C5 -> 0x00007FF71C1118F2) ---
    // asm: int3 
    // asm: int3 
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
        goto loc_7FF71C111955;
    } else {
        goto loc_7FF71C1118F2;
    }

loc_7FF71C1118F2:
    // --- Basic Block 6 (0x00007FF71C1118F2 -> 0x00007FF71C111900) ---
    rax_result = indirect_call(qword ptr [rip + 0x37c0]);
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111908;
    } else {
        goto loc_7FF71C111900;
    }

loc_7FF71C111900:
    // --- Basic Block 7 (0x00007FF71C111900 -> 0x00007FF71C111908) ---
    rax_result = indirect_call(qword ptr [rip + 0x37d2]);
    goto loc_7FF71C11190E;

loc_7FF71C111908:
    // --- Basic Block 8 (0x00007FF71C111908 -> 0x00007FF71C11190E) ---
    rax_result = indirect_call(qword ptr [rip + 0x37b2]);

loc_7FF71C11190E:
    // --- Basic Block 9 (0x00007FF71C11190E -> 0x00007FF71C111932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3786]);
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x377a]);
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11194A;
    } else {
        goto loc_7FF71C111932;
    }

loc_7FF71C111932:
    // --- Basic Block 10 (0x00007FF71C111932 -> 0x00007FF71C111947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF71C111999;
    } else {
        goto loc_7FF71C111947;
    }

loc_7FF71C111947:
    // --- Basic Block 11 (0x00007FF71C111947 -> 0x00007FF71C11194A) ---
    rdi, rax; // mov

loc_7FF71C11194A:
    // --- Basic Block 12 (0x00007FF71C11194A -> 0x00007FF71C111955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111955:
    // --- Basic Block 13 (0x00007FF71C111955 -> 0x00007FF71C111999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x376a]);
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x376c]);
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_0;

loc_7FF71C111999:
    // --- Basic Block 14 (0x00007FF71C111999 -> 0x00007FF71C1119DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x39ce]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x3739]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1119E9;
    } else {
        goto loc_7FF71C1119DC;
    }

loc_7FF71C1119DC:
    // --- Basic Block 15 (0x00007FF71C1119DC -> 0x00007FF71C1119E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1119E9:
    // --- Basic Block 16 (0x00007FF71C1119E9 -> 0x00007FF71C1119EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF71C1119EE:
    // --- Basic Block 17 (0x00007FF71C1119EE -> 0x00007FF71C111A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF71C1140EC;

loc_7FF71C111A03:
    // --- Basic Block 18 (0x00007FF71C111A03 -> 0x00007FF71C111A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x36e9]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111A39;
    } else {
        goto loc_7FF71C111A2C;
    }

loc_7FF71C111A2C:
    // --- Basic Block 19 (0x00007FF71C111A2C -> 0x00007FF71C111A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111A39:
    // --- Basic Block 20 (0x00007FF71C111A39 -> 0x00007FF71C111A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF71C111A3E:
    // --- Basic Block 21 (0x00007FF71C111A3E -> 0x00007FF71C111A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C111A5C;
    } else {
        goto loc_7FF71C111A52;
    }

loc_7FF71C111A52:
    // --- Basic Block 22 (0x00007FF71C111A52 -> 0x00007FF71C111A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = indirect_call(qword ptr [rip + 0x36ed]);

loc_7FF71C111A5C:
    // --- Basic Block 23 (0x00007FF71C111A5C -> 0x00007FF71C111A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = indirect_call(qword ptr [rip + 0x36a1]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111A81;
    } else {
        goto loc_7FF71C111A74;
    }

loc_7FF71C111A74:
    // --- Basic Block 24 (0x00007FF71C111A74 -> 0x00007FF71C111A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111A81:
    // --- Basic Block 25 (0x00007FF71C111A81 -> 0x00007FF71C111A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111A87:
    // --- Basic Block 26 (0x00007FF71C111A87 -> 0x00007FF71C111AEB) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x377c]);
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_0;

loc_7FF71C111AEB:
    // --- Basic Block 27 (0x00007FF71C111AEB -> 0x00007FF71C111AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF71C111B00;

loc_7FF71C111AF8:
    // --- Basic Block 28 (0x00007FF71C111AF8 -> 0x00007FF71C111B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF71C111B00:
    // --- Basic Block 29 (0x00007FF71C111B00 -> 0x00007FF71C111B69) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x36fe]);
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3595]);
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF71C111B76;
    } else {
        goto loc_7FF71C111B69;
    }

loc_7FF71C111B69:
    // --- Basic Block 30 (0x00007FF71C111B69 -> 0x00007FF71C111B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111B76:
    // --- Basic Block 31 (0x00007FF71C111B76 -> 0x00007FF71C111B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111B89:
    // --- Basic Block 32 (0x00007FF71C111B89 -> 0x00007FF71C111BA9) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111BB6;
    } else {
        goto loc_7FF71C111BA9;
    }

loc_7FF71C111BA9:
    // --- Basic Block 33 (0x00007FF71C111BA9 -> 0x00007FF71C111BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111BB6:
    // --- Basic Block 34 (0x00007FF71C111BB6 -> 0x00007FF71C111BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111BC4:
    // --- Basic Block 35 (0x00007FF71C111BC4 -> 0x00007FF71C111BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140EC(); // 0x7ff71c1140ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111C04;
    } else {
        goto loc_7FF71C111BF7;
    }

loc_7FF71C111BF7:
    // --- Basic Block 36 (0x00007FF71C111BF7 -> 0x00007FF71C111C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111C04:
    // --- Basic Block 37 (0x00007FF71C111C04 -> 0x00007FF71C111C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111C12:
    // --- Basic Block 38 (0x00007FF71C111C12 -> 0x00007FF71C111C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111C78;
    }

loc_7FF71C111C78:
    // --- Basic Block 39 (0x00007FF71C111C78 -> 0x00007FF71C111C80) ---

loc_7FF71C111C80:
    // --- Basic Block 40 (0x00007FF71C111C80 -> 0x00007FF71C111C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C111C8D;
    } else {
        goto loc_7FF71C111C8A;
    }

loc_7FF71C111C8A:
    // --- Basic Block 41 (0x00007FF71C111C8A -> 0x00007FF71C111C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF71C111C8D:
    // --- Basic Block 42 (0x00007FF71C111C8D -> 0x00007FF71C111CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C1131D0(); // 0x7ff71c1131d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF71C1120C0(); // 0x7ff71c1120c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111CDA;
    }

loc_7FF71C111CDA:
    // --- Basic Block 43 (0x00007FF71C111CDA -> 0x00007FF71C111CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF71C111C80;

loc_7FF71C111CE3:
    // --- Basic Block 44 (0x00007FF71C111CE3 -> 0x00007FF71C111CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF71C111880` (0x7FF71C111880)
- **Size**: `1145 bytes` | **Complexity V(G)**: `8` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111880 | Address: 0x00007FF71C111880
// Size: 1145 bytes | Basic Blocks: 42 | Complexity V(G): 8
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111880(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111880:
    // --- Basic Block 0 (0x00007FF71C111880 -> 0x00007FF71C1118B2) ---
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax, rdx; // mov
    rcx, [rip + 0x3c95]; // lea
    // asm: xorps xmm0, xmm0
    rdx, [rbx + 8]; // lea
    qword ptr [rbx], rcx; // mov
    rcx, [rax + 8]; // lea
    // asm: movups xmmword ptr [rdx], xmm0
    rax_result = sub_7FF71C1140E6(); // 0x7ff71c1140e6
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1118B2:
    // --- Basic Block 1 (0x00007FF71C1118B2 -> 0x00007FF71C1118C5) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    goto loc_7FF71C112020;

loc_7FF71C1118C5:
    // --- Basic Block 2 (0x00007FF71C1118C5 -> 0x00007FF71C1118F2) ---
    // asm: int3 
    // asm: int3 
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
        goto loc_7FF71C111955;
    } else {
        goto loc_7FF71C1118F2;
    }

loc_7FF71C1118F2:
    // --- Basic Block 3 (0x00007FF71C1118F2 -> 0x00007FF71C111900) ---
    rax_result = indirect_call(qword ptr [rip + 0x37c0]);
    rcx, rbx; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111908;
    } else {
        goto loc_7FF71C111900;
    }

loc_7FF71C111900:
    // --- Basic Block 4 (0x00007FF71C111900 -> 0x00007FF71C111908) ---
    rax_result = indirect_call(qword ptr [rip + 0x37d2]);
    goto loc_7FF71C11190E;

loc_7FF71C111908:
    // --- Basic Block 5 (0x00007FF71C111908 -> 0x00007FF71C11190E) ---
    rax_result = indirect_call(qword ptr [rip + 0x37b2]);

loc_7FF71C11190E:
    // --- Basic Block 6 (0x00007FF71C11190E -> 0x00007FF71C111932) ---
    rcx, rbx; // mov
    rsi, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3786]);
    rcx, rbx; // mov
    rdi, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x377a]);
    // asm: sub rsi, rax
    // asm: cmp rsi, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11194A;
    } else {
        goto loc_7FF71C111932;
    }

loc_7FF71C111932:
    // --- Basic Block 7 (0x00007FF71C111932 -> 0x00007FF71C111947) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rsi, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF71C111999;
    } else {
        goto loc_7FF71C111947;
    }

loc_7FF71C111947:
    // --- Basic Block 8 (0x00007FF71C111947 -> 0x00007FF71C11194A) ---
    rdi, rax; // mov

loc_7FF71C11194A:
    // --- Basic Block 9 (0x00007FF71C11194A -> 0x00007FF71C111955) ---
    rdx, rsi; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111955:
    // --- Basic Block 10 (0x00007FF71C111955 -> 0x00007FF71C111999) ---
    r9d = 0;
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x376a]);
    r8d = 0;
    edx = 0;
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x376c]);
    // asm: and dword ptr [rbx + 0x70], 0xfffffffe
    rcx, rbx; // mov
    qword ptr [rbx + 0x68], 0; // mov
    rbx, qword ptr [rsp + 0x40]; // mov
    rsi, qword ptr [rsp + 0x48]; // mov
    // asm: add rsp, 0x30
    goto loc_0;

loc_7FF71C111999:
    // --- Basic Block 11 (0x00007FF71C111999 -> 0x00007FF71C1119DC) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x39ce]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x3739]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1119E9;
    } else {
        goto loc_7FF71C1119DC;
    }

loc_7FF71C1119DC:
    // --- Basic Block 12 (0x00007FF71C1119DC -> 0x00007FF71C1119E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1119E9:
    // --- Basic Block 13 (0x00007FF71C1119E9 -> 0x00007FF71C1119EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF71C1119EE:
    // --- Basic Block 14 (0x00007FF71C1119EE -> 0x00007FF71C111A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF71C1140EC;

loc_7FF71C111A03:
    // --- Basic Block 15 (0x00007FF71C111A03 -> 0x00007FF71C111A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x36e9]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111A39;
    } else {
        goto loc_7FF71C111A2C;
    }

loc_7FF71C111A2C:
    // --- Basic Block 16 (0x00007FF71C111A2C -> 0x00007FF71C111A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111A39:
    // --- Basic Block 17 (0x00007FF71C111A39 -> 0x00007FF71C111A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF71C111A3E:
    // --- Basic Block 18 (0x00007FF71C111A3E -> 0x00007FF71C111A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C111A5C;
    } else {
        goto loc_7FF71C111A52;
    }

loc_7FF71C111A52:
    // --- Basic Block 19 (0x00007FF71C111A52 -> 0x00007FF71C111A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = indirect_call(qword ptr [rip + 0x36ed]);

loc_7FF71C111A5C:
    // --- Basic Block 20 (0x00007FF71C111A5C -> 0x00007FF71C111A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = indirect_call(qword ptr [rip + 0x36a1]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111A81;
    } else {
        goto loc_7FF71C111A74;
    }

loc_7FF71C111A74:
    // --- Basic Block 21 (0x00007FF71C111A74 -> 0x00007FF71C111A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111A81:
    // --- Basic Block 22 (0x00007FF71C111A81 -> 0x00007FF71C111A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111A87:
    // --- Basic Block 23 (0x00007FF71C111A87 -> 0x00007FF71C111AEB) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x377c]);
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_0;

loc_7FF71C111AEB:
    // --- Basic Block 24 (0x00007FF71C111AEB -> 0x00007FF71C111AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF71C111B00;

loc_7FF71C111AF8:
    // --- Basic Block 25 (0x00007FF71C111AF8 -> 0x00007FF71C111B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF71C111B00:
    // --- Basic Block 26 (0x00007FF71C111B00 -> 0x00007FF71C111B69) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x36fe]);
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3595]);
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF71C111B76;
    } else {
        goto loc_7FF71C111B69;
    }

loc_7FF71C111B69:
    // --- Basic Block 27 (0x00007FF71C111B69 -> 0x00007FF71C111B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111B76:
    // --- Basic Block 28 (0x00007FF71C111B76 -> 0x00007FF71C111B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111B89:
    // --- Basic Block 29 (0x00007FF71C111B89 -> 0x00007FF71C111BA9) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111BB6;
    } else {
        goto loc_7FF71C111BA9;
    }

loc_7FF71C111BA9:
    // --- Basic Block 30 (0x00007FF71C111BA9 -> 0x00007FF71C111BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111BB6:
    // --- Basic Block 31 (0x00007FF71C111BB6 -> 0x00007FF71C111BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111BC4:
    // --- Basic Block 32 (0x00007FF71C111BC4 -> 0x00007FF71C111BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140EC(); // 0x7ff71c1140ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111C04;
    } else {
        goto loc_7FF71C111BF7;
    }

loc_7FF71C111BF7:
    // --- Basic Block 33 (0x00007FF71C111BF7 -> 0x00007FF71C111C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111C04:
    // --- Basic Block 34 (0x00007FF71C111C04 -> 0x00007FF71C111C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111C12:
    // --- Basic Block 35 (0x00007FF71C111C12 -> 0x00007FF71C111C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111C78;
    }

loc_7FF71C111C78:
    // --- Basic Block 36 (0x00007FF71C111C78 -> 0x00007FF71C111C80) ---

loc_7FF71C111C80:
    // --- Basic Block 37 (0x00007FF71C111C80 -> 0x00007FF71C111C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C111C8D;
    } else {
        goto loc_7FF71C111C8A;
    }

loc_7FF71C111C8A:
    // --- Basic Block 38 (0x00007FF71C111C8A -> 0x00007FF71C111C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF71C111C8D:
    // --- Basic Block 39 (0x00007FF71C111C8D -> 0x00007FF71C111CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C1131D0(); // 0x7ff71c1131d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF71C1120C0(); // 0x7ff71c1120c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111CDA;
    }

loc_7FF71C111CDA:
    // --- Basic Block 40 (0x00007FF71C111CDA -> 0x00007FF71C111CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF71C111C80;

loc_7FF71C111CE3:
    // --- Basic Block 41 (0x00007FF71C111CE3 -> 0x00007FF71C111CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF71C1119C0` (0x7FF71C1119C0)
- **Size**: `1720 bytes` | **Complexity V(G)**: `12` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C1119C0 | Address: 0x00007FF71C1119C0
// Size: 1720 bytes | Basic Blocks: 53 | Complexity V(G): 12
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C1119C0(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C1119C0:
    // --- Basic Block 0 (0x00007FF71C1119C0 -> 0x00007FF71C1119DC) ---
    // asm: sub rsp, 0x28
    rdx, qword ptr [rcx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = indirect_call(qword ptr [rip + 0x3739]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1119E9;
    } else {
        goto loc_7FF71C1119DC;
    }

loc_7FF71C1119DC:
    // --- Basic Block 1 (0x00007FF71C1119DC -> 0x00007FF71C1119E9) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C1119E9:
    // --- Basic Block 2 (0x00007FF71C1119E9 -> 0x00007FF71C1119EE) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF71C1119EE:
    // --- Basic Block 3 (0x00007FF71C1119EE -> 0x00007FF71C111A03) ---
    // asm: int3 
    // asm: int3 
    rax, [rip + 0x3b31]; // lea
    qword ptr [rcx], rax; // mov
    // asm: add rcx, 8
    goto loc_7FF71C1140EC;

loc_7FF71C111A03:
    // --- Basic Block 4 (0x00007FF71C111A03 -> 0x00007FF71C111A2C) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = indirect_call(qword ptr [rip + 0x36e9]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111A39;
    } else {
        goto loc_7FF71C111A2C;
    }

loc_7FF71C111A2C:
    // --- Basic Block 5 (0x00007FF71C111A2C -> 0x00007FF71C111A39) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111A39:
    // --- Basic Block 6 (0x00007FF71C111A39 -> 0x00007FF71C111A3E) ---
    // asm: add rsp, 0x28
    return rax_result;

loc_7FF71C111A3E:
    // --- Basic Block 7 (0x00007FF71C111A3E -> 0x00007FF71C111A52) ---
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C111A5C;
    } else {
        goto loc_7FF71C111A52;
    }

loc_7FF71C111A52:
    // --- Basic Block 8 (0x00007FF71C111A52 -> 0x00007FF71C111A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = indirect_call(qword ptr [rip + 0x36ed]);

loc_7FF71C111A5C:
    // --- Basic Block 9 (0x00007FF71C111A5C -> 0x00007FF71C111A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = indirect_call(qword ptr [rip + 0x36a1]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111A81;
    } else {
        goto loc_7FF71C111A74;
    }

loc_7FF71C111A74:
    // --- Basic Block 10 (0x00007FF71C111A74 -> 0x00007FF71C111A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111A81:
    // --- Basic Block 11 (0x00007FF71C111A81 -> 0x00007FF71C111A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111A87:
    // --- Basic Block 12 (0x00007FF71C111A87 -> 0x00007FF71C111AEB) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x377c]);
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_0;

loc_7FF71C111AEB:
    // --- Basic Block 13 (0x00007FF71C111AEB -> 0x00007FF71C111AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF71C111B00;

loc_7FF71C111AF8:
    // --- Basic Block 14 (0x00007FF71C111AF8 -> 0x00007FF71C111B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF71C111B00:
    // --- Basic Block 15 (0x00007FF71C111B00 -> 0x00007FF71C111B69) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x36fe]);
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3595]);
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF71C111B76;
    } else {
        goto loc_7FF71C111B69;
    }

loc_7FF71C111B69:
    // --- Basic Block 16 (0x00007FF71C111B69 -> 0x00007FF71C111B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111B76:
    // --- Basic Block 17 (0x00007FF71C111B76 -> 0x00007FF71C111B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111B89:
    // --- Basic Block 18 (0x00007FF71C111B89 -> 0x00007FF71C111BA9) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111BB6;
    } else {
        goto loc_7FF71C111BA9;
    }

loc_7FF71C111BA9:
    // --- Basic Block 19 (0x00007FF71C111BA9 -> 0x00007FF71C111BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111BB6:
    // --- Basic Block 20 (0x00007FF71C111BB6 -> 0x00007FF71C111BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111BC4:
    // --- Basic Block 21 (0x00007FF71C111BC4 -> 0x00007FF71C111BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140EC(); // 0x7ff71c1140ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111C04;
    } else {
        goto loc_7FF71C111BF7;
    }

loc_7FF71C111BF7:
    // --- Basic Block 22 (0x00007FF71C111BF7 -> 0x00007FF71C111C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111C04:
    // --- Basic Block 23 (0x00007FF71C111C04 -> 0x00007FF71C111C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111C12:
    // --- Basic Block 24 (0x00007FF71C111C12 -> 0x00007FF71C111C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111C78;
    }

loc_7FF71C111C78:
    // --- Basic Block 25 (0x00007FF71C111C78 -> 0x00007FF71C111C80) ---

loc_7FF71C111C80:
    // --- Basic Block 26 (0x00007FF71C111C80 -> 0x00007FF71C111C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C111C8D;
    } else {
        goto loc_7FF71C111C8A;
    }

loc_7FF71C111C8A:
    // --- Basic Block 27 (0x00007FF71C111C8A -> 0x00007FF71C111C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF71C111C8D:
    // --- Basic Block 28 (0x00007FF71C111C8D -> 0x00007FF71C111CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C1131D0(); // 0x7ff71c1131d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF71C1120C0(); // 0x7ff71c1120c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111CDA;
    }

loc_7FF71C111CDA:
    // --- Basic Block 29 (0x00007FF71C111CDA -> 0x00007FF71C111CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF71C111C80;

loc_7FF71C111CE3:
    // --- Basic Block 30 (0x00007FF71C111CE3 -> 0x00007FF71C111CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C111CF9:
    // --- Basic Block 31 (0x00007FF71C111CF9 -> 0x00007FF71C111D9D) ---
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
    rax_result = indirect_call(qword ptr [rip + 0x3316]);
    dword ptr [rsp + 0x40], edi; // mov
    dword ptr [rsp + 0x38], edi; // mov
    qword ptr [rsp + 0x30], rdi; // mov
    qword ptr [rsp + 0x28], rdi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    r9, [rsp + 0x40]; // lea
    r8d = 0;
    edx = 0;
    rcx, [rip + 0x38be]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3300]);
    esi, 0x539; // mov
    ebx, edi; // mov
    rcx, [rbp + 0x50]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111DB2;
    } else {
        goto loc_7FF71C111D9D;
    }

loc_7FF71C111D9D:
    // --- Basic Block 32 (0x00007FF71C111D9D -> 0x00007FF71C111DA0) ---

loc_7FF71C111DA0:
    // --- Basic Block 33 (0x00007FF71C111DA0 -> 0x00007FF71C111DB2) ---
    // asm: movsx ecx, byte ptr [rbp + rbx + 0x50]
    // asm: imul esi, esi, 0x21
    // asm: xor esi, ecx
    // asm: inc rbx
    // asm: cmp rbx, rax
    if (jb_condition) {
        goto loc_7FF71C111DA0;
    } else {
        goto loc_7FF71C111DB2;
    }

loc_7FF71C111DB2:
    // --- Basic Block 34 (0x00007FF71C111DB2 -> 0x00007FF71C111F28) ---
    // asm: xor esi, dword ptr [rsp + 0x40]
    rax, [rip + 0x387b]; // lea
    qword ptr [rsp + 0x60], rax; // mov
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3364]);
    dword ptr [rsp + 0x44], 2; // mov
    r9d = 0;
    r8d = 0;
    rdx, [rsp + 0x68]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x334d]);
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    r15, [rip + 0x3834]; // lea
    qword ptr [rsp + rcx + 0x60], r15; // mov
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    edx, [rcx - 0x88]; // lea
    dword ptr [rsp + rcx + 0x5c], edx; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x33e9]);
    rax, [rip + 0x378a]; // lea
    qword ptr [rsp + 0x68], rax; // mov
    qword ptr [rbp - 0x30], rdi; // mov
    dword ptr [rbp - 0x28], 4; // mov
    edx, 8; // mov
    rcx, [rsp + 0x50]; // lea
    rax_result = sub_7FF71C113238(); // 0x7ff71c113238
    rbx, rax; // mov
    rdx, [rip + 0x37f5]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, rax; // mov
    rdx, [rip + 0xdbd]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32e7]);
    rcx, rax; // mov
    rdx, [rip + 0x42d]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32d7]);
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
    rax_result = indirect_call(qword ptr [rip + 0x327f]);
    edx, esi; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x32ac]);
    rdx, r14; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C112920(); // 0x7ff71c112920
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    qword ptr [rsp + rdx + 0x60], r15; // mov
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rsp + rdx + 0x5c], r8d; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rsp + 0x70]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3366]);
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x31fc]);
    rax, r14; // mov
    rcx, qword ptr [rbp + 0x60]; // mov
    // asm: xor rcx, rsp
    rax_result = sub_7FF71C1133B0(); // 0x7ff71c1133b0
    r11, [rsp + 0x170]; // lea
    rbx, qword ptr [r11 + 0x28]; // mov
    rsi, qword ptr [r11 + 0x30]; // mov
    rdi, qword ptr [r11 + 0x38]; // mov
    rsp, r11; // mov
    return rax_result;

loc_7FF71C111F28:
    // --- Basic Block 35 (0x00007FF71C111F28 -> 0x00007FF71C111F97) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rcx, qword ptr [rip + 0x329d]; // mov
    rdx, [rip + 0x3716]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x328a]; // mov
    rdx, [rip + 0x3743]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3277]; // mov
    rdx, [rip + 0x3760]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3264]; // mov
    rdx, [rip + 0x3795]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3251]; // mov
    rdx, [rip + 0x37c2]; // lea
    // asm: add rsp, 0x28
    goto loc_7FF71C111000;

loc_7FF71C111F97:
    // --- Basic Block 36 (0x00007FF71C111F97 -> 0x00007FF71C111FB5) ---
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
    r10, qword ptr [rcx + 0x10]; // mov
    r9, rdx; // mov
    r8, rcx; // mov
    // asm: cmp r10, qword ptr [rdx + 0x10]
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FB5;
    }

loc_7FF71C111FB5:
    // --- Basic Block 37 (0x00007FF71C111FB5 -> 0x00007FF71C111FBC) ---
    eax = 0;
    // asm: test r10, r10
    if (je_condition) {
        goto loc_7FF71C111FED;
    } else {
        goto loc_7FF71C111FBC;
    }

loc_7FF71C111FBC:
    // --- Basic Block 38 (0x00007FF71C111FBC -> 0x00007FF71C111FC4) ---
    rbx, qword ptr [rdx + 0x18]; // mov
    r11, qword ptr [rcx + 0x18]; // mov

loc_7FF71C111FC4:
    // --- Basic Block 39 (0x00007FF71C111FC4 -> 0x00007FF71C111FCD) ---
    rdx, r8; // mov
    // asm: cmp r11, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FD0;
    } else {
        goto loc_7FF71C111FCD;
    }

loc_7FF71C111FCD:
    // --- Basic Block 40 (0x00007FF71C111FCD -> 0x00007FF71C111FD0) ---
    rdx, qword ptr [r8]; // mov

loc_7FF71C111FD0:
    // --- Basic Block 41 (0x00007FF71C111FD0 -> 0x00007FF71C111FD9) ---
    rcx, r9; // mov
    // asm: cmp rbx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FDC;
    } else {
        goto loc_7FF71C111FD9;
    }

loc_7FF71C111FD9:
    // --- Basic Block 42 (0x00007FF71C111FD9 -> 0x00007FF71C111FDC) ---
    rcx, qword ptr [r9]; // mov

loc_7FF71C111FDC:
    // --- Basic Block 43 (0x00007FF71C111FDC -> 0x00007FF71C111FE5) ---
    // asm: movzx ecx, byte ptr [rcx + rax]
    // asm: cmp byte ptr [rdx + rax], cl
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FE5;
    }

loc_7FF71C111FE5:
    // --- Basic Block 44 (0x00007FF71C111FE5 -> 0x00007FF71C111FED) ---
    // asm: inc rax
    // asm: cmp rax, r10
    if (jb_condition) {
        goto loc_7FF71C111FC4;
    } else {
        goto loc_7FF71C111FED;
    }

loc_7FF71C111FED:
    // --- Basic Block 45 (0x00007FF71C111FED -> 0x00007FF71C111FF5) ---
    al, 1; // mov
    rbx, qword ptr [rsp + 8]; // mov
    return rax_result;

loc_7FF71C111FF5:
    // --- Basic Block 46 (0x00007FF71C111FF5 -> 0x00007FF71C111FFD) ---
    rbx, qword ptr [rsp + 8]; // mov
    // asm: xor al, al
    return rax_result;

loc_7FF71C111FFD:
    // --- Basic Block 47 (0x00007FF71C111FFD -> 0x00007FF71C112033) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x48
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C111850(); // 0x7ff71c111850
    rdx, [rip + 0x497b]; // lea
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C1140F2(); // 0x7ff71c1140f2
    // asm: int3 
    // asm: sub rsp, 0x30
    rdx, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rdx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C11205F;
    } else {
        goto loc_7FF71C112033;
    }

loc_7FF71C112033:
    // --- Basic Block 48 (0x00007FF71C112033 -> 0x00007FF71C112042) ---
    rcx, qword ptr [rcx]; // mov
    // asm: inc rdx
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11205A;
    } else {
        goto loc_7FF71C112042;
    }

loc_7FF71C112042:
    // --- Basic Block 49 (0x00007FF71C112042 -> 0x00007FF71C112057) ---
    rax, qword ptr [rcx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rcx, rax
    // asm: sub rcx, 8
    // asm: cmp rcx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112078;
    } else {
        goto loc_7FF71C112057;
    }

loc_7FF71C112057:
    // --- Basic Block 50 (0x00007FF71C112057 -> 0x00007FF71C11205A) ---
    rcx, rax; // mov

loc_7FF71C11205A:
    // --- Basic Block 51 (0x00007FF71C11205A -> 0x00007FF71C11205F) ---
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C11205F:
    // --- Basic Block 52 (0x00007FF71C11205F -> 0x00007FF71C112078) ---
    qword ptr [rbx + 0x10], 0; // mov
    qword ptr [rbx + 0x18], 0xf; // mov
    byte ptr [rbx], 0; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF71C111A40` (0x7FF71C111A40)
- **Size**: `1592 bytes` | **Complexity V(G)**: `12` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111A40 | Address: 0x00007FF71C111A40
// Size: 1592 bytes | Basic Blocks: 46 | Complexity V(G): 12
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111A40(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111A40:
    // --- Basic Block 0 (0x00007FF71C111A40 -> 0x00007FF71C111A52) ---
    // asm: sub rsp, 0x20
    rbx, rcx; // mov
    rax_result = sub_7FF71C113232(); // 0x7ff71c113232
    // asm: test al, al
    if (jne_condition) {
        goto loc_7FF71C111A5C;
    } else {
        goto loc_7FF71C111A52;
    }

loc_7FF71C111A52:
    // --- Basic Block 1 (0x00007FF71C111A52 -> 0x00007FF71C111A5C) ---
    rcx, qword ptr [rbx]; // mov
    rax_result = indirect_call(qword ptr [rip + 0x36ed]);

loc_7FF71C111A5C:
    // --- Basic Block 2 (0x00007FF71C111A5C -> 0x00007FF71C111A74) ---
    rdx, qword ptr [rbx]; // mov
    rax, qword ptr [rdx]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    // asm: add rcx, rdx
    rax_result = indirect_call(qword ptr [rip + 0x36a1]);
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111A81;
    } else {
        goto loc_7FF71C111A74;
    }

loc_7FF71C111A74:
    // --- Basic Block 3 (0x00007FF71C111A74 -> 0x00007FF71C111A81) ---
    rcx, qword ptr [rax]; // mov
    rdx, qword ptr [rcx + 0x10]; // mov
    rcx, rax; // mov
    rax_result = indirect_call(rdx);

loc_7FF71C111A81:
    // --- Basic Block 4 (0x00007FF71C111A81 -> 0x00007FF71C111A87) ---
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111A87:
    // --- Basic Block 5 (0x00007FF71C111A87 -> 0x00007FF71C111AEB) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x377c]);
    rcx, rbx; // mov
    // asm: add rsp, 0x20
    goto loc_0;

loc_7FF71C111AEB:
    // --- Basic Block 6 (0x00007FF71C111AEB -> 0x00007FF71C111AF8) ---
    // asm: int3 
    // asm: movsxd rax, dword ptr [rcx - 4]
    // asm: sub rcx, rax
    goto loc_7FF71C111B00;

loc_7FF71C111AF8:
    // --- Basic Block 7 (0x00007FF71C111AF8 -> 0x00007FF71C111B00) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 

loc_7FF71C111B00:
    // --- Basic Block 8 (0x00007FF71C111B00 -> 0x00007FF71C111B69) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x36fe]);
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3595]);
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF71C111B76;
    } else {
        goto loc_7FF71C111B69;
    }

loc_7FF71C111B69:
    // --- Basic Block 9 (0x00007FF71C111B69 -> 0x00007FF71C111B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111B76:
    // --- Basic Block 10 (0x00007FF71C111B76 -> 0x00007FF71C111B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111B89:
    // --- Basic Block 11 (0x00007FF71C111B89 -> 0x00007FF71C111BA9) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111BB6;
    } else {
        goto loc_7FF71C111BA9;
    }

loc_7FF71C111BA9:
    // --- Basic Block 12 (0x00007FF71C111BA9 -> 0x00007FF71C111BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111BB6:
    // --- Basic Block 13 (0x00007FF71C111BB6 -> 0x00007FF71C111BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111BC4:
    // --- Basic Block 14 (0x00007FF71C111BC4 -> 0x00007FF71C111BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140EC(); // 0x7ff71c1140ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111C04;
    } else {
        goto loc_7FF71C111BF7;
    }

loc_7FF71C111BF7:
    // --- Basic Block 15 (0x00007FF71C111BF7 -> 0x00007FF71C111C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111C04:
    // --- Basic Block 16 (0x00007FF71C111C04 -> 0x00007FF71C111C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111C12:
    // --- Basic Block 17 (0x00007FF71C111C12 -> 0x00007FF71C111C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111C78;
    }

loc_7FF71C111C78:
    // --- Basic Block 18 (0x00007FF71C111C78 -> 0x00007FF71C111C80) ---

loc_7FF71C111C80:
    // --- Basic Block 19 (0x00007FF71C111C80 -> 0x00007FF71C111C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C111C8D;
    } else {
        goto loc_7FF71C111C8A;
    }

loc_7FF71C111C8A:
    // --- Basic Block 20 (0x00007FF71C111C8A -> 0x00007FF71C111C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF71C111C8D:
    // --- Basic Block 21 (0x00007FF71C111C8D -> 0x00007FF71C111CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C1131D0(); // 0x7ff71c1131d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF71C1120C0(); // 0x7ff71c1120c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111CDA;
    }

loc_7FF71C111CDA:
    // --- Basic Block 22 (0x00007FF71C111CDA -> 0x00007FF71C111CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF71C111C80;

loc_7FF71C111CE3:
    // --- Basic Block 23 (0x00007FF71C111CE3 -> 0x00007FF71C111CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C111CF9:
    // --- Basic Block 24 (0x00007FF71C111CF9 -> 0x00007FF71C111D9D) ---
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
    rax_result = indirect_call(qword ptr [rip + 0x3316]);
    dword ptr [rsp + 0x40], edi; // mov
    dword ptr [rsp + 0x38], edi; // mov
    qword ptr [rsp + 0x30], rdi; // mov
    qword ptr [rsp + 0x28], rdi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    r9, [rsp + 0x40]; // lea
    r8d = 0;
    edx = 0;
    rcx, [rip + 0x38be]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3300]);
    esi, 0x539; // mov
    ebx, edi; // mov
    rcx, [rbp + 0x50]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111DB2;
    } else {
        goto loc_7FF71C111D9D;
    }

loc_7FF71C111D9D:
    // --- Basic Block 25 (0x00007FF71C111D9D -> 0x00007FF71C111DA0) ---

loc_7FF71C111DA0:
    // --- Basic Block 26 (0x00007FF71C111DA0 -> 0x00007FF71C111DB2) ---
    // asm: movsx ecx, byte ptr [rbp + rbx + 0x50]
    // asm: imul esi, esi, 0x21
    // asm: xor esi, ecx
    // asm: inc rbx
    // asm: cmp rbx, rax
    if (jb_condition) {
        goto loc_7FF71C111DA0;
    } else {
        goto loc_7FF71C111DB2;
    }

loc_7FF71C111DB2:
    // --- Basic Block 27 (0x00007FF71C111DB2 -> 0x00007FF71C111F28) ---
    // asm: xor esi, dword ptr [rsp + 0x40]
    rax, [rip + 0x387b]; // lea
    qword ptr [rsp + 0x60], rax; // mov
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3364]);
    dword ptr [rsp + 0x44], 2; // mov
    r9d = 0;
    r8d = 0;
    rdx, [rsp + 0x68]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x334d]);
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    r15, [rip + 0x3834]; // lea
    qword ptr [rsp + rcx + 0x60], r15; // mov
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    edx, [rcx - 0x88]; // lea
    dword ptr [rsp + rcx + 0x5c], edx; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x33e9]);
    rax, [rip + 0x378a]; // lea
    qword ptr [rsp + 0x68], rax; // mov
    qword ptr [rbp - 0x30], rdi; // mov
    dword ptr [rbp - 0x28], 4; // mov
    edx, 8; // mov
    rcx, [rsp + 0x50]; // lea
    rax_result = sub_7FF71C113238(); // 0x7ff71c113238
    rbx, rax; // mov
    rdx, [rip + 0x37f5]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, rax; // mov
    rdx, [rip + 0xdbd]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32e7]);
    rcx, rax; // mov
    rdx, [rip + 0x42d]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32d7]);
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
    rax_result = indirect_call(qword ptr [rip + 0x327f]);
    edx, esi; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x32ac]);
    rdx, r14; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C112920(); // 0x7ff71c112920
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    qword ptr [rsp + rdx + 0x60], r15; // mov
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rsp + rdx + 0x5c], r8d; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rsp + 0x70]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3366]);
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x31fc]);
    rax, r14; // mov
    rcx, qword ptr [rbp + 0x60]; // mov
    // asm: xor rcx, rsp
    rax_result = sub_7FF71C1133B0(); // 0x7ff71c1133b0
    r11, [rsp + 0x170]; // lea
    rbx, qword ptr [r11 + 0x28]; // mov
    rsi, qword ptr [r11 + 0x30]; // mov
    rdi, qword ptr [r11 + 0x38]; // mov
    rsp, r11; // mov
    return rax_result;

loc_7FF71C111F28:
    // --- Basic Block 28 (0x00007FF71C111F28 -> 0x00007FF71C111F97) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rcx, qword ptr [rip + 0x329d]; // mov
    rdx, [rip + 0x3716]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x328a]; // mov
    rdx, [rip + 0x3743]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3277]; // mov
    rdx, [rip + 0x3760]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3264]; // mov
    rdx, [rip + 0x3795]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3251]; // mov
    rdx, [rip + 0x37c2]; // lea
    // asm: add rsp, 0x28
    goto loc_7FF71C111000;

loc_7FF71C111F97:
    // --- Basic Block 29 (0x00007FF71C111F97 -> 0x00007FF71C111FB5) ---
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
    r10, qword ptr [rcx + 0x10]; // mov
    r9, rdx; // mov
    r8, rcx; // mov
    // asm: cmp r10, qword ptr [rdx + 0x10]
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FB5;
    }

loc_7FF71C111FB5:
    // --- Basic Block 30 (0x00007FF71C111FB5 -> 0x00007FF71C111FBC) ---
    eax = 0;
    // asm: test r10, r10
    if (je_condition) {
        goto loc_7FF71C111FED;
    } else {
        goto loc_7FF71C111FBC;
    }

loc_7FF71C111FBC:
    // --- Basic Block 31 (0x00007FF71C111FBC -> 0x00007FF71C111FC4) ---
    rbx, qword ptr [rdx + 0x18]; // mov
    r11, qword ptr [rcx + 0x18]; // mov

loc_7FF71C111FC4:
    // --- Basic Block 32 (0x00007FF71C111FC4 -> 0x00007FF71C111FCD) ---
    rdx, r8; // mov
    // asm: cmp r11, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FD0;
    } else {
        goto loc_7FF71C111FCD;
    }

loc_7FF71C111FCD:
    // --- Basic Block 33 (0x00007FF71C111FCD -> 0x00007FF71C111FD0) ---
    rdx, qword ptr [r8]; // mov

loc_7FF71C111FD0:
    // --- Basic Block 34 (0x00007FF71C111FD0 -> 0x00007FF71C111FD9) ---
    rcx, r9; // mov
    // asm: cmp rbx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FDC;
    } else {
        goto loc_7FF71C111FD9;
    }

loc_7FF71C111FD9:
    // --- Basic Block 35 (0x00007FF71C111FD9 -> 0x00007FF71C111FDC) ---
    rcx, qword ptr [r9]; // mov

loc_7FF71C111FDC:
    // --- Basic Block 36 (0x00007FF71C111FDC -> 0x00007FF71C111FE5) ---
    // asm: movzx ecx, byte ptr [rcx + rax]
    // asm: cmp byte ptr [rdx + rax], cl
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FE5;
    }

loc_7FF71C111FE5:
    // --- Basic Block 37 (0x00007FF71C111FE5 -> 0x00007FF71C111FED) ---
    // asm: inc rax
    // asm: cmp rax, r10
    if (jb_condition) {
        goto loc_7FF71C111FC4;
    } else {
        goto loc_7FF71C111FED;
    }

loc_7FF71C111FED:
    // --- Basic Block 38 (0x00007FF71C111FED -> 0x00007FF71C111FF5) ---
    al, 1; // mov
    rbx, qword ptr [rsp + 8]; // mov
    return rax_result;

loc_7FF71C111FF5:
    // --- Basic Block 39 (0x00007FF71C111FF5 -> 0x00007FF71C111FFD) ---
    rbx, qword ptr [rsp + 8]; // mov
    // asm: xor al, al
    return rax_result;

loc_7FF71C111FFD:
    // --- Basic Block 40 (0x00007FF71C111FFD -> 0x00007FF71C112033) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x48
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C111850(); // 0x7ff71c111850
    rdx, [rip + 0x497b]; // lea
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C1140F2(); // 0x7ff71c1140f2
    // asm: int3 
    // asm: sub rsp, 0x30
    rdx, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rdx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C11205F;
    } else {
        goto loc_7FF71C112033;
    }

loc_7FF71C112033:
    // --- Basic Block 41 (0x00007FF71C112033 -> 0x00007FF71C112042) ---
    rcx, qword ptr [rcx]; // mov
    // asm: inc rdx
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11205A;
    } else {
        goto loc_7FF71C112042;
    }

loc_7FF71C112042:
    // --- Basic Block 42 (0x00007FF71C112042 -> 0x00007FF71C112057) ---
    rax, qword ptr [rcx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rcx, rax
    // asm: sub rcx, 8
    // asm: cmp rcx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112078;
    } else {
        goto loc_7FF71C112057;
    }

loc_7FF71C112057:
    // --- Basic Block 43 (0x00007FF71C112057 -> 0x00007FF71C11205A) ---
    rcx, rax; // mov

loc_7FF71C11205A:
    // --- Basic Block 44 (0x00007FF71C11205A -> 0x00007FF71C11205F) ---
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C11205F:
    // --- Basic Block 45 (0x00007FF71C11205F -> 0x00007FF71C112078) ---
    qword ptr [rbx + 0x10], 0; // mov
    qword ptr [rbx + 0x18], 0xf; // mov
    byte ptr [rbx], 0; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF71C111B00` (0x7FF71C111B00)
- **Size**: `1400 bytes` | **Complexity V(G)**: `11` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111B00 | Address: 0x00007FF71C111B00
// Size: 1400 bytes | Basic Blocks: 38 | Complexity V(G): 11
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111B00(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111B00:
    // --- Basic Block 0 (0x00007FF71C111B00 -> 0x00007FF71C111B69) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rbx - 0x78]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x36fe]);
    rcx, rbx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x3595]);
    // asm: test dil, 1
    if (je_condition) {
        goto loc_7FF71C111B76;
    } else {
        goto loc_7FF71C111B69;
    }

loc_7FF71C111B69:
    // --- Basic Block 1 (0x00007FF71C111B69 -> 0x00007FF71C111B76) ---
    edx, 0xe8; // mov
    rcx, rsi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111B76:
    // --- Basic Block 2 (0x00007FF71C111B76 -> 0x00007FF71C111B89) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rsi; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111B89:
    // --- Basic Block 3 (0x00007FF71C111B89 -> 0x00007FF71C111BA9) ---
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
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111BB6;
    } else {
        goto loc_7FF71C111BA9;
    }

loc_7FF71C111BA9:
    // --- Basic Block 4 (0x00007FF71C111BA9 -> 0x00007FF71C111BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111BB6:
    // --- Basic Block 5 (0x00007FF71C111BB6 -> 0x00007FF71C111BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111BC4:
    // --- Basic Block 6 (0x00007FF71C111BC4 -> 0x00007FF71C111BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140EC(); // 0x7ff71c1140ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111C04;
    } else {
        goto loc_7FF71C111BF7;
    }

loc_7FF71C111BF7:
    // --- Basic Block 7 (0x00007FF71C111BF7 -> 0x00007FF71C111C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111C04:
    // --- Basic Block 8 (0x00007FF71C111C04 -> 0x00007FF71C111C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111C12:
    // --- Basic Block 9 (0x00007FF71C111C12 -> 0x00007FF71C111C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111C78;
    }

loc_7FF71C111C78:
    // --- Basic Block 10 (0x00007FF71C111C78 -> 0x00007FF71C111C80) ---

loc_7FF71C111C80:
    // --- Basic Block 11 (0x00007FF71C111C80 -> 0x00007FF71C111C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C111C8D;
    } else {
        goto loc_7FF71C111C8A;
    }

loc_7FF71C111C8A:
    // --- Basic Block 12 (0x00007FF71C111C8A -> 0x00007FF71C111C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF71C111C8D:
    // --- Basic Block 13 (0x00007FF71C111C8D -> 0x00007FF71C111CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C1131D0(); // 0x7ff71c1131d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF71C1120C0(); // 0x7ff71c1120c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111CDA;
    }

loc_7FF71C111CDA:
    // --- Basic Block 14 (0x00007FF71C111CDA -> 0x00007FF71C111CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF71C111C80;

loc_7FF71C111CE3:
    // --- Basic Block 15 (0x00007FF71C111CE3 -> 0x00007FF71C111CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C111CF9:
    // --- Basic Block 16 (0x00007FF71C111CF9 -> 0x00007FF71C111D9D) ---
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
    rax_result = indirect_call(qword ptr [rip + 0x3316]);
    dword ptr [rsp + 0x40], edi; // mov
    dword ptr [rsp + 0x38], edi; // mov
    qword ptr [rsp + 0x30], rdi; // mov
    qword ptr [rsp + 0x28], rdi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    r9, [rsp + 0x40]; // lea
    r8d = 0;
    edx = 0;
    rcx, [rip + 0x38be]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3300]);
    esi, 0x539; // mov
    ebx, edi; // mov
    rcx, [rbp + 0x50]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111DB2;
    } else {
        goto loc_7FF71C111D9D;
    }

loc_7FF71C111D9D:
    // --- Basic Block 17 (0x00007FF71C111D9D -> 0x00007FF71C111DA0) ---

loc_7FF71C111DA0:
    // --- Basic Block 18 (0x00007FF71C111DA0 -> 0x00007FF71C111DB2) ---
    // asm: movsx ecx, byte ptr [rbp + rbx + 0x50]
    // asm: imul esi, esi, 0x21
    // asm: xor esi, ecx
    // asm: inc rbx
    // asm: cmp rbx, rax
    if (jb_condition) {
        goto loc_7FF71C111DA0;
    } else {
        goto loc_7FF71C111DB2;
    }

loc_7FF71C111DB2:
    // --- Basic Block 19 (0x00007FF71C111DB2 -> 0x00007FF71C111F28) ---
    // asm: xor esi, dword ptr [rsp + 0x40]
    rax, [rip + 0x387b]; // lea
    qword ptr [rsp + 0x60], rax; // mov
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3364]);
    dword ptr [rsp + 0x44], 2; // mov
    r9d = 0;
    r8d = 0;
    rdx, [rsp + 0x68]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x334d]);
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    r15, [rip + 0x3834]; // lea
    qword ptr [rsp + rcx + 0x60], r15; // mov
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    edx, [rcx - 0x88]; // lea
    dword ptr [rsp + rcx + 0x5c], edx; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x33e9]);
    rax, [rip + 0x378a]; // lea
    qword ptr [rsp + 0x68], rax; // mov
    qword ptr [rbp - 0x30], rdi; // mov
    dword ptr [rbp - 0x28], 4; // mov
    edx, 8; // mov
    rcx, [rsp + 0x50]; // lea
    rax_result = sub_7FF71C113238(); // 0x7ff71c113238
    rbx, rax; // mov
    rdx, [rip + 0x37f5]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, rax; // mov
    rdx, [rip + 0xdbd]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32e7]);
    rcx, rax; // mov
    rdx, [rip + 0x42d]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32d7]);
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
    rax_result = indirect_call(qword ptr [rip + 0x327f]);
    edx, esi; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x32ac]);
    rdx, r14; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C112920(); // 0x7ff71c112920
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    qword ptr [rsp + rdx + 0x60], r15; // mov
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rsp + rdx + 0x5c], r8d; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rsp + 0x70]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3366]);
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x31fc]);
    rax, r14; // mov
    rcx, qword ptr [rbp + 0x60]; // mov
    // asm: xor rcx, rsp
    rax_result = sub_7FF71C1133B0(); // 0x7ff71c1133b0
    r11, [rsp + 0x170]; // lea
    rbx, qword ptr [r11 + 0x28]; // mov
    rsi, qword ptr [r11 + 0x30]; // mov
    rdi, qword ptr [r11 + 0x38]; // mov
    rsp, r11; // mov
    return rax_result;

loc_7FF71C111F28:
    // --- Basic Block 20 (0x00007FF71C111F28 -> 0x00007FF71C111F97) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rcx, qword ptr [rip + 0x329d]; // mov
    rdx, [rip + 0x3716]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x328a]; // mov
    rdx, [rip + 0x3743]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3277]; // mov
    rdx, [rip + 0x3760]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3264]; // mov
    rdx, [rip + 0x3795]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3251]; // mov
    rdx, [rip + 0x37c2]; // lea
    // asm: add rsp, 0x28
    goto loc_7FF71C111000;

loc_7FF71C111F97:
    // --- Basic Block 21 (0x00007FF71C111F97 -> 0x00007FF71C111FB5) ---
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
    r10, qword ptr [rcx + 0x10]; // mov
    r9, rdx; // mov
    r8, rcx; // mov
    // asm: cmp r10, qword ptr [rdx + 0x10]
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FB5;
    }

loc_7FF71C111FB5:
    // --- Basic Block 22 (0x00007FF71C111FB5 -> 0x00007FF71C111FBC) ---
    eax = 0;
    // asm: test r10, r10
    if (je_condition) {
        goto loc_7FF71C111FED;
    } else {
        goto loc_7FF71C111FBC;
    }

loc_7FF71C111FBC:
    // --- Basic Block 23 (0x00007FF71C111FBC -> 0x00007FF71C111FC4) ---
    rbx, qword ptr [rdx + 0x18]; // mov
    r11, qword ptr [rcx + 0x18]; // mov

loc_7FF71C111FC4:
    // --- Basic Block 24 (0x00007FF71C111FC4 -> 0x00007FF71C111FCD) ---
    rdx, r8; // mov
    // asm: cmp r11, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FD0;
    } else {
        goto loc_7FF71C111FCD;
    }

loc_7FF71C111FCD:
    // --- Basic Block 25 (0x00007FF71C111FCD -> 0x00007FF71C111FD0) ---
    rdx, qword ptr [r8]; // mov

loc_7FF71C111FD0:
    // --- Basic Block 26 (0x00007FF71C111FD0 -> 0x00007FF71C111FD9) ---
    rcx, r9; // mov
    // asm: cmp rbx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FDC;
    } else {
        goto loc_7FF71C111FD9;
    }

loc_7FF71C111FD9:
    // --- Basic Block 27 (0x00007FF71C111FD9 -> 0x00007FF71C111FDC) ---
    rcx, qword ptr [r9]; // mov

loc_7FF71C111FDC:
    // --- Basic Block 28 (0x00007FF71C111FDC -> 0x00007FF71C111FE5) ---
    // asm: movzx ecx, byte ptr [rcx + rax]
    // asm: cmp byte ptr [rdx + rax], cl
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FE5;
    }

loc_7FF71C111FE5:
    // --- Basic Block 29 (0x00007FF71C111FE5 -> 0x00007FF71C111FED) ---
    // asm: inc rax
    // asm: cmp rax, r10
    if (jb_condition) {
        goto loc_7FF71C111FC4;
    } else {
        goto loc_7FF71C111FED;
    }

loc_7FF71C111FED:
    // --- Basic Block 30 (0x00007FF71C111FED -> 0x00007FF71C111FF5) ---
    al, 1; // mov
    rbx, qword ptr [rsp + 8]; // mov
    return rax_result;

loc_7FF71C111FF5:
    // --- Basic Block 31 (0x00007FF71C111FF5 -> 0x00007FF71C111FFD) ---
    rbx, qword ptr [rsp + 8]; // mov
    // asm: xor al, al
    return rax_result;

loc_7FF71C111FFD:
    // --- Basic Block 32 (0x00007FF71C111FFD -> 0x00007FF71C112033) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x48
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C111850(); // 0x7ff71c111850
    rdx, [rip + 0x497b]; // lea
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C1140F2(); // 0x7ff71c1140f2
    // asm: int3 
    // asm: sub rsp, 0x30
    rdx, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rdx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C11205F;
    } else {
        goto loc_7FF71C112033;
    }

loc_7FF71C112033:
    // --- Basic Block 33 (0x00007FF71C112033 -> 0x00007FF71C112042) ---
    rcx, qword ptr [rcx]; // mov
    // asm: inc rdx
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11205A;
    } else {
        goto loc_7FF71C112042;
    }

loc_7FF71C112042:
    // --- Basic Block 34 (0x00007FF71C112042 -> 0x00007FF71C112057) ---
    rax, qword ptr [rcx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rcx, rax
    // asm: sub rcx, 8
    // asm: cmp rcx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112078;
    } else {
        goto loc_7FF71C112057;
    }

loc_7FF71C112057:
    // --- Basic Block 35 (0x00007FF71C112057 -> 0x00007FF71C11205A) ---
    rcx, rax; // mov

loc_7FF71C11205A:
    // --- Basic Block 36 (0x00007FF71C11205A -> 0x00007FF71C11205F) ---
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C11205F:
    // --- Basic Block 37 (0x00007FF71C11205F -> 0x00007FF71C112078) ---
    qword ptr [rbx + 0x10], 0; // mov
    qword ptr [rbx + 0x18], 0xf; // mov
    byte ptr [rbx], 0; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF71C111B90` (0x7FF71C111B90)
- **Size**: `1696 bytes` | **Complexity V(G)**: `18` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111B90 | Address: 0x00007FF71C111B90
// Size: 1696 bytes | Basic Blocks: 52 | Complexity V(G): 18
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111B90(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111B90:
    // --- Basic Block 0 (0x00007FF71C111B90 -> 0x00007FF71C111BA9) ---
    qword ptr [rsp + 8], rbx; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111BB6;
    } else {
        goto loc_7FF71C111BA9;
    }

loc_7FF71C111BA9:
    // --- Basic Block 1 (0x00007FF71C111BA9 -> 0x00007FF71C111BB6) ---
    edx, 0x78; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111BB6:
    // --- Basic Block 2 (0x00007FF71C111BB6 -> 0x00007FF71C111BC4) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111BC4:
    // --- Basic Block 3 (0x00007FF71C111BC4 -> 0x00007FF71C111BF7) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C1140EC(); // 0x7ff71c1140ec
    // asm: test bl, 1
    if (je_condition) {
        goto loc_7FF71C111C04;
    } else {
        goto loc_7FF71C111BF7;
    }

loc_7FF71C111BF7:
    // --- Basic Block 4 (0x00007FF71C111BF7 -> 0x00007FF71C111C04) ---
    edx, 0x18; // mov
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C111C04:
    // --- Basic Block 5 (0x00007FF71C111C04 -> 0x00007FF71C111C12) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C111C12:
    // --- Basic Block 6 (0x00007FF71C111C12 -> 0x00007FF71C111C78) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111C78;
    }

loc_7FF71C111C78:
    // --- Basic Block 7 (0x00007FF71C111C78 -> 0x00007FF71C111C80) ---

loc_7FF71C111C80:
    // --- Basic Block 8 (0x00007FF71C111C80 -> 0x00007FF71C111C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C111C8D;
    } else {
        goto loc_7FF71C111C8A;
    }

loc_7FF71C111C8A:
    // --- Basic Block 9 (0x00007FF71C111C8A -> 0x00007FF71C111C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF71C111C8D:
    // --- Basic Block 10 (0x00007FF71C111C8D -> 0x00007FF71C111CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C1131D0(); // 0x7ff71c1131d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF71C1120C0(); // 0x7ff71c1120c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111CDA;
    }

loc_7FF71C111CDA:
    // --- Basic Block 11 (0x00007FF71C111CDA -> 0x00007FF71C111CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF71C111C80;

loc_7FF71C111CE3:
    // --- Basic Block 12 (0x00007FF71C111CE3 -> 0x00007FF71C111CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C111CF9:
    // --- Basic Block 13 (0x00007FF71C111CF9 -> 0x00007FF71C111D9D) ---
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
    rax_result = indirect_call(qword ptr [rip + 0x3316]);
    dword ptr [rsp + 0x40], edi; // mov
    dword ptr [rsp + 0x38], edi; // mov
    qword ptr [rsp + 0x30], rdi; // mov
    qword ptr [rsp + 0x28], rdi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    r9, [rsp + 0x40]; // lea
    r8d = 0;
    edx = 0;
    rcx, [rip + 0x38be]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3300]);
    esi, 0x539; // mov
    ebx, edi; // mov
    rcx, [rbp + 0x50]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111DB2;
    } else {
        goto loc_7FF71C111D9D;
    }

loc_7FF71C111D9D:
    // --- Basic Block 14 (0x00007FF71C111D9D -> 0x00007FF71C111DA0) ---

loc_7FF71C111DA0:
    // --- Basic Block 15 (0x00007FF71C111DA0 -> 0x00007FF71C111DB2) ---
    // asm: movsx ecx, byte ptr [rbp + rbx + 0x50]
    // asm: imul esi, esi, 0x21
    // asm: xor esi, ecx
    // asm: inc rbx
    // asm: cmp rbx, rax
    if (jb_condition) {
        goto loc_7FF71C111DA0;
    } else {
        goto loc_7FF71C111DB2;
    }

loc_7FF71C111DB2:
    // --- Basic Block 16 (0x00007FF71C111DB2 -> 0x00007FF71C111F28) ---
    // asm: xor esi, dword ptr [rsp + 0x40]
    rax, [rip + 0x387b]; // lea
    qword ptr [rsp + 0x60], rax; // mov
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3364]);
    dword ptr [rsp + 0x44], 2; // mov
    r9d = 0;
    r8d = 0;
    rdx, [rsp + 0x68]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x334d]);
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    r15, [rip + 0x3834]; // lea
    qword ptr [rsp + rcx + 0x60], r15; // mov
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    edx, [rcx - 0x88]; // lea
    dword ptr [rsp + rcx + 0x5c], edx; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x33e9]);
    rax, [rip + 0x378a]; // lea
    qword ptr [rsp + 0x68], rax; // mov
    qword ptr [rbp - 0x30], rdi; // mov
    dword ptr [rbp - 0x28], 4; // mov
    edx, 8; // mov
    rcx, [rsp + 0x50]; // lea
    rax_result = sub_7FF71C113238(); // 0x7ff71c113238
    rbx, rax; // mov
    rdx, [rip + 0x37f5]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, rax; // mov
    rdx, [rip + 0xdbd]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32e7]);
    rcx, rax; // mov
    rdx, [rip + 0x42d]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32d7]);
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
    rax_result = indirect_call(qword ptr [rip + 0x327f]);
    edx, esi; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x32ac]);
    rdx, r14; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C112920(); // 0x7ff71c112920
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    qword ptr [rsp + rdx + 0x60], r15; // mov
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rsp + rdx + 0x5c], r8d; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rsp + 0x70]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3366]);
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x31fc]);
    rax, r14; // mov
    rcx, qword ptr [rbp + 0x60]; // mov
    // asm: xor rcx, rsp
    rax_result = sub_7FF71C1133B0(); // 0x7ff71c1133b0
    r11, [rsp + 0x170]; // lea
    rbx, qword ptr [r11 + 0x28]; // mov
    rsi, qword ptr [r11 + 0x30]; // mov
    rdi, qword ptr [r11 + 0x38]; // mov
    rsp, r11; // mov
    return rax_result;

loc_7FF71C111F28:
    // --- Basic Block 17 (0x00007FF71C111F28 -> 0x00007FF71C111F97) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rcx, qword ptr [rip + 0x329d]; // mov
    rdx, [rip + 0x3716]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x328a]; // mov
    rdx, [rip + 0x3743]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3277]; // mov
    rdx, [rip + 0x3760]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3264]; // mov
    rdx, [rip + 0x3795]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3251]; // mov
    rdx, [rip + 0x37c2]; // lea
    // asm: add rsp, 0x28
    goto loc_7FF71C111000;

loc_7FF71C111F97:
    // --- Basic Block 18 (0x00007FF71C111F97 -> 0x00007FF71C111FB5) ---
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
    r10, qword ptr [rcx + 0x10]; // mov
    r9, rdx; // mov
    r8, rcx; // mov
    // asm: cmp r10, qword ptr [rdx + 0x10]
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FB5;
    }

loc_7FF71C111FB5:
    // --- Basic Block 19 (0x00007FF71C111FB5 -> 0x00007FF71C111FBC) ---
    eax = 0;
    // asm: test r10, r10
    if (je_condition) {
        goto loc_7FF71C111FED;
    } else {
        goto loc_7FF71C111FBC;
    }

loc_7FF71C111FBC:
    // --- Basic Block 20 (0x00007FF71C111FBC -> 0x00007FF71C111FC4) ---
    rbx, qword ptr [rdx + 0x18]; // mov
    r11, qword ptr [rcx + 0x18]; // mov

loc_7FF71C111FC4:
    // --- Basic Block 21 (0x00007FF71C111FC4 -> 0x00007FF71C111FCD) ---
    rdx, r8; // mov
    // asm: cmp r11, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FD0;
    } else {
        goto loc_7FF71C111FCD;
    }

loc_7FF71C111FCD:
    // --- Basic Block 22 (0x00007FF71C111FCD -> 0x00007FF71C111FD0) ---
    rdx, qword ptr [r8]; // mov

loc_7FF71C111FD0:
    // --- Basic Block 23 (0x00007FF71C111FD0 -> 0x00007FF71C111FD9) ---
    rcx, r9; // mov
    // asm: cmp rbx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FDC;
    } else {
        goto loc_7FF71C111FD9;
    }

loc_7FF71C111FD9:
    // --- Basic Block 24 (0x00007FF71C111FD9 -> 0x00007FF71C111FDC) ---
    rcx, qword ptr [r9]; // mov

loc_7FF71C111FDC:
    // --- Basic Block 25 (0x00007FF71C111FDC -> 0x00007FF71C111FE5) ---
    // asm: movzx ecx, byte ptr [rcx + rax]
    // asm: cmp byte ptr [rdx + rax], cl
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FE5;
    }

loc_7FF71C111FE5:
    // --- Basic Block 26 (0x00007FF71C111FE5 -> 0x00007FF71C111FED) ---
    // asm: inc rax
    // asm: cmp rax, r10
    if (jb_condition) {
        goto loc_7FF71C111FC4;
    } else {
        goto loc_7FF71C111FED;
    }

loc_7FF71C111FED:
    // --- Basic Block 27 (0x00007FF71C111FED -> 0x00007FF71C111FF5) ---
    al, 1; // mov
    rbx, qword ptr [rsp + 8]; // mov
    return rax_result;

loc_7FF71C111FF5:
    // --- Basic Block 28 (0x00007FF71C111FF5 -> 0x00007FF71C111FFD) ---
    rbx, qword ptr [rsp + 8]; // mov
    // asm: xor al, al
    return rax_result;

loc_7FF71C111FFD:
    // --- Basic Block 29 (0x00007FF71C111FFD -> 0x00007FF71C112033) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x48
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C111850(); // 0x7ff71c111850
    rdx, [rip + 0x497b]; // lea
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C1140F2(); // 0x7ff71c1140f2
    // asm: int3 
    // asm: sub rsp, 0x30
    rdx, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rdx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C11205F;
    } else {
        goto loc_7FF71C112033;
    }

loc_7FF71C112033:
    // --- Basic Block 30 (0x00007FF71C112033 -> 0x00007FF71C112042) ---
    rcx, qword ptr [rcx]; // mov
    // asm: inc rdx
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11205A;
    } else {
        goto loc_7FF71C112042;
    }

loc_7FF71C112042:
    // --- Basic Block 31 (0x00007FF71C112042 -> 0x00007FF71C112057) ---
    rax, qword ptr [rcx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rcx, rax
    // asm: sub rcx, 8
    // asm: cmp rcx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112078;
    } else {
        goto loc_7FF71C112057;
    }

loc_7FF71C112057:
    // --- Basic Block 32 (0x00007FF71C112057 -> 0x00007FF71C11205A) ---
    rcx, rax; // mov

loc_7FF71C11205A:
    // --- Basic Block 33 (0x00007FF71C11205A -> 0x00007FF71C11205F) ---
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C11205F:
    // --- Basic Block 34 (0x00007FF71C11205F -> 0x00007FF71C112078) ---
    qword ptr [rbx + 0x10], 0; // mov
    qword ptr [rbx + 0x18], 0xf; // mov
    byte ptr [rbx], 0; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C112078:
    // --- Basic Block 35 (0x00007FF71C112078 -> 0x00007FF71C1120ED) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x32ef]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rcx, [rip + 0x34ed]; // lea
    rax_result = sub_7FF71C11322C(); // 0x7ff71c11322c
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    // asm: sub rsp, 0x30
    r15, qword ptr [rcx + 0x18]; // mov
    rsi, r8; // mov
    r14, qword ptr [rcx + 0x10]; // mov
    rax, r15; // mov
    // asm: sub rax, r14
    r13, rdx; // mov
    rdi, rcx; // mov
    // asm: cmp r8, rax
    if (ja_condition) {
        goto loc_7FF71C112116;
    } else {
        goto loc_7FF71C1120ED;
    }

loc_7FF71C1120ED:
    // --- Basic Block 36 (0x00007FF71C1120ED -> 0x00007FF71C1120FE) ---
    rax, [r14 + r8]; // lea
    qword ptr [rcx + 0x10], rax; // mov
    rax, rcx; // mov
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C112101;
    } else {
        goto loc_7FF71C1120FE;
    }

loc_7FF71C1120FE:
    // --- Basic Block 37 (0x00007FF71C1120FE -> 0x00007FF71C112101) ---
    rax, qword ptr [rcx]; // mov

loc_7FF71C112101:
    // --- Basic Block 38 (0x00007FF71C112101 -> 0x00007FF71C112116) ---
    rbx, [r14 + rax]; // lea
    rcx, rbx; // mov
    rax_result = sub_7FF71C114104(); // 0x7ff71c114104
    byte ptr [rbx + rsi], 0; // mov
    goto loc_7FF71C11221B;

loc_7FF71C112116:
    // --- Basic Block 39 (0x00007FF71C112116 -> 0x00007FF71C11212F) ---
    // asm: movabs rbx, 0x7fffffffffffffff
    rax, rbx; // mov
    // asm: sub rax, r14
    // asm: cmp rax, rsi
    if (jb_condition) {
        goto loc_7FF71C112230;
    } else {
        goto loc_7FF71C11212F;
    }

loc_7FF71C11212F:
    // --- Basic Block 40 (0x00007FF71C11212F -> 0x00007FF71C112149) ---
    qword ptr [rsp + 0x60], rbp; // mov
    qword ptr [rsp + 0x68], r12; // mov
    r12, [r14 + r8]; // lea
    rcx, r12; // mov
    // asm: or rcx, 0xf
    // asm: cmp rcx, rbx
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C112149;
    }

loc_7FF71C112149:
    // --- Basic Block 41 (0x00007FF71C112149 -> 0x00007FF71C11215A) ---
    rdx, r15; // mov
    rax, rbx; // mov
    // asm: shr rdx, 1
    // asm: sub rax, rdx
    // asm: cmp r15, rax
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C11215A;
    }

loc_7FF71C11215A:
    // --- Basic Block 42 (0x00007FF71C11215A -> 0x00007FF71C112168) ---
    rax, [r15 + rdx]; // lea
    rbx, rcx; // mov
    // asm: cmp rcx, rax
    // asm: cmovb rbx, rax

loc_7FF71C112168:
    // --- Basic Block 43 (0x00007FF71C112168 -> 0x00007FF71C11218C) ---
    rcx, [rbx + 1]; // lea
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    qword ptr [rdi + 0x10], r12; // mov
    rbp, rax; // mov
    qword ptr [rdi + 0x18], rbx; // mov
    r8, r14; // mov
    rcx, rax; // mov
    r12, [r14 + rax]; // lea
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C1121F3;
    } else {
        goto loc_7FF71C11218C;
    }

loc_7FF71C11218C:
    // --- Basic Block 44 (0x00007FF71C11218C -> 0x00007FF71C1121B7) ---
    rbx, qword ptr [rdi]; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    rdx, [r15 + 1]; // lea
    byte ptr [r12 + rsi], 0; // mov
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C1121CF;
    } else {
        goto loc_7FF71C1121B7;
    }

loc_7FF71C1121B7:
    // --- Basic Block 45 (0x00007FF71C1121B7 -> 0x00007FF71C1121CC) ---
    rax, qword ptr [rbx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rbx, rax
    // asm: sub rbx, 8
    // asm: cmp rbx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C1121D9;
    } else {
        goto loc_7FF71C1121CC;
    }

loc_7FF71C1121CC:
    // --- Basic Block 46 (0x00007FF71C1121CC -> 0x00007FF71C1121CF) ---
    rbx, rax; // mov

loc_7FF71C1121CF:
    // --- Basic Block 47 (0x00007FF71C1121CF -> 0x00007FF71C1121D9) ---
    rcx, rbx; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0
    goto loc_7FF71C11220E;

loc_7FF71C1121D9:
    // --- Basic Block 48 (0x00007FF71C1121D9 -> 0x00007FF71C1121F3) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x318e]);
    // asm: int3 

loc_7FF71C1121F3:
    // --- Basic Block 49 (0x00007FF71C1121F3 -> 0x00007FF71C11220E) ---
    rdx, rdi; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [r12 + rsi], 0; // mov

loc_7FF71C11220E:
    // --- Basic Block 50 (0x00007FF71C11220E -> 0x00007FF71C11221B) ---
    qword ptr [rdi], rbp; // mov
    rbp, qword ptr [rsp + 0x60]; // mov
    r12, qword ptr [rsp + 0x68]; // mov

loc_7FF71C11221B:
    // --- Basic Block 51 (0x00007FF71C11221B -> 0x00007FF71C112230) ---
    rbx, qword ptr [rsp + 0x70]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF71C111C20` (0x7FF71C111C20)
- **Size**: `1699 bytes` | **Complexity V(G)**: `19` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111C20 | Address: 0x00007FF71C111C20
// Size: 1699 bytes | Basic Blocks: 51 | Complexity V(G): 19
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111C20(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111C20:
    // --- Basic Block 0 (0x00007FF71C111C20 -> 0x00007FF71C111C78) ---
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
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r14, rax; // mov
    // asm: cmp qword ptr [rbx + 0x10], rbp
    if (jbe_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111C78;
    }

loc_7FF71C111C78:
    // --- Basic Block 1 (0x00007FF71C111C78 -> 0x00007FF71C111C80) ---

loc_7FF71C111C80:
    // --- Basic Block 2 (0x00007FF71C111C80 -> 0x00007FF71C111C8A) ---
    rcx, rbx; // mov
    // asm: cmp qword ptr [rbx + 0x18], 0xf
    if (jbe_condition) {
        goto loc_7FF71C111C8D;
    } else {
        goto loc_7FF71C111C8A;
    }

loc_7FF71C111C8A:
    // --- Basic Block 3 (0x00007FF71C111C8A -> 0x00007FF71C111C8D) ---
    rcx, qword ptr [rbx]; // mov

loc_7FF71C111C8D:
    // --- Basic Block 4 (0x00007FF71C111C8D -> 0x00007FF71C111CDA) ---
    edx = 0;
    rax, rbp; // mov
    // asm: div r14
    // asm: movzx r9d, byte ptr [rdx + rsi]
    // asm: movzx eax, byte ptr [rcx + rbp]
    // asm: xor r9d, eax
    r8, [rip + 0x39a4]; // lea
    edx, 4; // mov
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C1131D0(); // 0x7ff71c1131d0
    rcx, [rsp + 0x58]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    r8, rax; // mov
    rdx, [rsp + 0x58]; // lea
    rcx, rdi; // mov
    rax_result = sub_7FF71C1120C0(); // 0x7ff71c1120c0
    // asm: inc rbp
    // asm: cmp rbp, qword ptr [rbx + 0x10]
    if (jae_condition) {
        goto loc_7FF71C111CE3;
    } else {
        goto loc_7FF71C111CDA;
    }

loc_7FF71C111CDA:
    // --- Basic Block 5 (0x00007FF71C111CDA -> 0x00007FF71C111CE3) ---
    rsi, qword ptr [rip + 0x732f]; // mov
    goto loc_7FF71C111C80;

loc_7FF71C111CE3:
    // --- Basic Block 6 (0x00007FF71C111CE3 -> 0x00007FF71C111CF9) ---
    rax, rdi; // mov
    rbx, qword ptr [rsp + 0x60]; // mov
    rbp, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C111CF9:
    // --- Basic Block 7 (0x00007FF71C111CF9 -> 0x00007FF71C111D9D) ---
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
    rax_result = indirect_call(qword ptr [rip + 0x3316]);
    dword ptr [rsp + 0x40], edi; // mov
    dword ptr [rsp + 0x38], edi; // mov
    qword ptr [rsp + 0x30], rdi; // mov
    qword ptr [rsp + 0x28], rdi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    r9, [rsp + 0x40]; // lea
    r8d = 0;
    edx = 0;
    rcx, [rip + 0x38be]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3300]);
    esi, 0x539; // mov
    ebx, edi; // mov
    rcx, [rbp + 0x50]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111DB2;
    } else {
        goto loc_7FF71C111D9D;
    }

loc_7FF71C111D9D:
    // --- Basic Block 8 (0x00007FF71C111D9D -> 0x00007FF71C111DA0) ---

loc_7FF71C111DA0:
    // --- Basic Block 9 (0x00007FF71C111DA0 -> 0x00007FF71C111DB2) ---
    // asm: movsx ecx, byte ptr [rbp + rbx + 0x50]
    // asm: imul esi, esi, 0x21
    // asm: xor esi, ecx
    // asm: inc rbx
    // asm: cmp rbx, rax
    if (jb_condition) {
        goto loc_7FF71C111DA0;
    } else {
        goto loc_7FF71C111DB2;
    }

loc_7FF71C111DB2:
    // --- Basic Block 10 (0x00007FF71C111DB2 -> 0x00007FF71C111F28) ---
    // asm: xor esi, dword ptr [rsp + 0x40]
    rax, [rip + 0x387b]; // lea
    qword ptr [rsp + 0x60], rax; // mov
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3364]);
    dword ptr [rsp + 0x44], 2; // mov
    r9d = 0;
    r8d = 0;
    rdx, [rsp + 0x68]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x334d]);
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    r15, [rip + 0x3834]; // lea
    qword ptr [rsp + rcx + 0x60], r15; // mov
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    edx, [rcx - 0x88]; // lea
    dword ptr [rsp + rcx + 0x5c], edx; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x33e9]);
    rax, [rip + 0x378a]; // lea
    qword ptr [rsp + 0x68], rax; // mov
    qword ptr [rbp - 0x30], rdi; // mov
    dword ptr [rbp - 0x28], 4; // mov
    edx, 8; // mov
    rcx, [rsp + 0x50]; // lea
    rax_result = sub_7FF71C113238(); // 0x7ff71c113238
    rbx, rax; // mov
    rdx, [rip + 0x37f5]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, rax; // mov
    rdx, [rip + 0xdbd]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32e7]);
    rcx, rax; // mov
    rdx, [rip + 0x42d]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32d7]);
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
    rax_result = indirect_call(qword ptr [rip + 0x327f]);
    edx, esi; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x32ac]);
    rdx, r14; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C112920(); // 0x7ff71c112920
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    qword ptr [rsp + rdx + 0x60], r15; // mov
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rsp + rdx + 0x5c], r8d; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rsp + 0x70]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3366]);
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x31fc]);
    rax, r14; // mov
    rcx, qword ptr [rbp + 0x60]; // mov
    // asm: xor rcx, rsp
    rax_result = sub_7FF71C1133B0(); // 0x7ff71c1133b0
    r11, [rsp + 0x170]; // lea
    rbx, qword ptr [r11 + 0x28]; // mov
    rsi, qword ptr [r11 + 0x30]; // mov
    rdi, qword ptr [r11 + 0x38]; // mov
    rsp, r11; // mov
    return rax_result;

loc_7FF71C111F28:
    // --- Basic Block 11 (0x00007FF71C111F28 -> 0x00007FF71C111F97) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rcx, qword ptr [rip + 0x329d]; // mov
    rdx, [rip + 0x3716]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x328a]; // mov
    rdx, [rip + 0x3743]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3277]; // mov
    rdx, [rip + 0x3760]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3264]; // mov
    rdx, [rip + 0x3795]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3251]; // mov
    rdx, [rip + 0x37c2]; // lea
    // asm: add rsp, 0x28
    goto loc_7FF71C111000;

loc_7FF71C111F97:
    // --- Basic Block 12 (0x00007FF71C111F97 -> 0x00007FF71C111FB5) ---
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
    r10, qword ptr [rcx + 0x10]; // mov
    r9, rdx; // mov
    r8, rcx; // mov
    // asm: cmp r10, qword ptr [rdx + 0x10]
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FB5;
    }

loc_7FF71C111FB5:
    // --- Basic Block 13 (0x00007FF71C111FB5 -> 0x00007FF71C111FBC) ---
    eax = 0;
    // asm: test r10, r10
    if (je_condition) {
        goto loc_7FF71C111FED;
    } else {
        goto loc_7FF71C111FBC;
    }

loc_7FF71C111FBC:
    // --- Basic Block 14 (0x00007FF71C111FBC -> 0x00007FF71C111FC4) ---
    rbx, qword ptr [rdx + 0x18]; // mov
    r11, qword ptr [rcx + 0x18]; // mov

loc_7FF71C111FC4:
    // --- Basic Block 15 (0x00007FF71C111FC4 -> 0x00007FF71C111FCD) ---
    rdx, r8; // mov
    // asm: cmp r11, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FD0;
    } else {
        goto loc_7FF71C111FCD;
    }

loc_7FF71C111FCD:
    // --- Basic Block 16 (0x00007FF71C111FCD -> 0x00007FF71C111FD0) ---
    rdx, qword ptr [r8]; // mov

loc_7FF71C111FD0:
    // --- Basic Block 17 (0x00007FF71C111FD0 -> 0x00007FF71C111FD9) ---
    rcx, r9; // mov
    // asm: cmp rbx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FDC;
    } else {
        goto loc_7FF71C111FD9;
    }

loc_7FF71C111FD9:
    // --- Basic Block 18 (0x00007FF71C111FD9 -> 0x00007FF71C111FDC) ---
    rcx, qword ptr [r9]; // mov

loc_7FF71C111FDC:
    // --- Basic Block 19 (0x00007FF71C111FDC -> 0x00007FF71C111FE5) ---
    // asm: movzx ecx, byte ptr [rcx + rax]
    // asm: cmp byte ptr [rdx + rax], cl
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FE5;
    }

loc_7FF71C111FE5:
    // --- Basic Block 20 (0x00007FF71C111FE5 -> 0x00007FF71C111FED) ---
    // asm: inc rax
    // asm: cmp rax, r10
    if (jb_condition) {
        goto loc_7FF71C111FC4;
    } else {
        goto loc_7FF71C111FED;
    }

loc_7FF71C111FED:
    // --- Basic Block 21 (0x00007FF71C111FED -> 0x00007FF71C111FF5) ---
    al, 1; // mov
    rbx, qword ptr [rsp + 8]; // mov
    return rax_result;

loc_7FF71C111FF5:
    // --- Basic Block 22 (0x00007FF71C111FF5 -> 0x00007FF71C111FFD) ---
    rbx, qword ptr [rsp + 8]; // mov
    // asm: xor al, al
    return rax_result;

loc_7FF71C111FFD:
    // --- Basic Block 23 (0x00007FF71C111FFD -> 0x00007FF71C112033) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x48
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C111850(); // 0x7ff71c111850
    rdx, [rip + 0x497b]; // lea
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C1140F2(); // 0x7ff71c1140f2
    // asm: int3 
    // asm: sub rsp, 0x30
    rdx, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rdx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C11205F;
    } else {
        goto loc_7FF71C112033;
    }

loc_7FF71C112033:
    // --- Basic Block 24 (0x00007FF71C112033 -> 0x00007FF71C112042) ---
    rcx, qword ptr [rcx]; // mov
    // asm: inc rdx
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11205A;
    } else {
        goto loc_7FF71C112042;
    }

loc_7FF71C112042:
    // --- Basic Block 25 (0x00007FF71C112042 -> 0x00007FF71C112057) ---
    rax, qword ptr [rcx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rcx, rax
    // asm: sub rcx, 8
    // asm: cmp rcx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112078;
    } else {
        goto loc_7FF71C112057;
    }

loc_7FF71C112057:
    // --- Basic Block 26 (0x00007FF71C112057 -> 0x00007FF71C11205A) ---
    rcx, rax; // mov

loc_7FF71C11205A:
    // --- Basic Block 27 (0x00007FF71C11205A -> 0x00007FF71C11205F) ---
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C11205F:
    // --- Basic Block 28 (0x00007FF71C11205F -> 0x00007FF71C112078) ---
    qword ptr [rbx + 0x10], 0; // mov
    qword ptr [rbx + 0x18], 0xf; // mov
    byte ptr [rbx], 0; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C112078:
    // --- Basic Block 29 (0x00007FF71C112078 -> 0x00007FF71C1120ED) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x32ef]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rcx, [rip + 0x34ed]; // lea
    rax_result = sub_7FF71C11322C(); // 0x7ff71c11322c
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    // asm: sub rsp, 0x30
    r15, qword ptr [rcx + 0x18]; // mov
    rsi, r8; // mov
    r14, qword ptr [rcx + 0x10]; // mov
    rax, r15; // mov
    // asm: sub rax, r14
    r13, rdx; // mov
    rdi, rcx; // mov
    // asm: cmp r8, rax
    if (ja_condition) {
        goto loc_7FF71C112116;
    } else {
        goto loc_7FF71C1120ED;
    }

loc_7FF71C1120ED:
    // --- Basic Block 30 (0x00007FF71C1120ED -> 0x00007FF71C1120FE) ---
    rax, [r14 + r8]; // lea
    qword ptr [rcx + 0x10], rax; // mov
    rax, rcx; // mov
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C112101;
    } else {
        goto loc_7FF71C1120FE;
    }

loc_7FF71C1120FE:
    // --- Basic Block 31 (0x00007FF71C1120FE -> 0x00007FF71C112101) ---
    rax, qword ptr [rcx]; // mov

loc_7FF71C112101:
    // --- Basic Block 32 (0x00007FF71C112101 -> 0x00007FF71C112116) ---
    rbx, [r14 + rax]; // lea
    rcx, rbx; // mov
    rax_result = sub_7FF71C114104(); // 0x7ff71c114104
    byte ptr [rbx + rsi], 0; // mov
    goto loc_7FF71C11221B;

loc_7FF71C112116:
    // --- Basic Block 33 (0x00007FF71C112116 -> 0x00007FF71C11212F) ---
    // asm: movabs rbx, 0x7fffffffffffffff
    rax, rbx; // mov
    // asm: sub rax, r14
    // asm: cmp rax, rsi
    if (jb_condition) {
        goto loc_7FF71C112230;
    } else {
        goto loc_7FF71C11212F;
    }

loc_7FF71C11212F:
    // --- Basic Block 34 (0x00007FF71C11212F -> 0x00007FF71C112149) ---
    qword ptr [rsp + 0x60], rbp; // mov
    qword ptr [rsp + 0x68], r12; // mov
    r12, [r14 + r8]; // lea
    rcx, r12; // mov
    // asm: or rcx, 0xf
    // asm: cmp rcx, rbx
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C112149;
    }

loc_7FF71C112149:
    // --- Basic Block 35 (0x00007FF71C112149 -> 0x00007FF71C11215A) ---
    rdx, r15; // mov
    rax, rbx; // mov
    // asm: shr rdx, 1
    // asm: sub rax, rdx
    // asm: cmp r15, rax
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C11215A;
    }

loc_7FF71C11215A:
    // --- Basic Block 36 (0x00007FF71C11215A -> 0x00007FF71C112168) ---
    rax, [r15 + rdx]; // lea
    rbx, rcx; // mov
    // asm: cmp rcx, rax
    // asm: cmovb rbx, rax

loc_7FF71C112168:
    // --- Basic Block 37 (0x00007FF71C112168 -> 0x00007FF71C11218C) ---
    rcx, [rbx + 1]; // lea
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    qword ptr [rdi + 0x10], r12; // mov
    rbp, rax; // mov
    qword ptr [rdi + 0x18], rbx; // mov
    r8, r14; // mov
    rcx, rax; // mov
    r12, [r14 + rax]; // lea
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C1121F3;
    } else {
        goto loc_7FF71C11218C;
    }

loc_7FF71C11218C:
    // --- Basic Block 38 (0x00007FF71C11218C -> 0x00007FF71C1121B7) ---
    rbx, qword ptr [rdi]; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    rdx, [r15 + 1]; // lea
    byte ptr [r12 + rsi], 0; // mov
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C1121CF;
    } else {
        goto loc_7FF71C1121B7;
    }

loc_7FF71C1121B7:
    // --- Basic Block 39 (0x00007FF71C1121B7 -> 0x00007FF71C1121CC) ---
    rax, qword ptr [rbx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rbx, rax
    // asm: sub rbx, 8
    // asm: cmp rbx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C1121D9;
    } else {
        goto loc_7FF71C1121CC;
    }

loc_7FF71C1121CC:
    // --- Basic Block 40 (0x00007FF71C1121CC -> 0x00007FF71C1121CF) ---
    rbx, rax; // mov

loc_7FF71C1121CF:
    // --- Basic Block 41 (0x00007FF71C1121CF -> 0x00007FF71C1121D9) ---
    rcx, rbx; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0
    goto loc_7FF71C11220E;

loc_7FF71C1121D9:
    // --- Basic Block 42 (0x00007FF71C1121D9 -> 0x00007FF71C1121F3) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x318e]);
    // asm: int3 

loc_7FF71C1121F3:
    // --- Basic Block 43 (0x00007FF71C1121F3 -> 0x00007FF71C11220E) ---
    rdx, rdi; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [r12 + rsi], 0; // mov

loc_7FF71C11220E:
    // --- Basic Block 44 (0x00007FF71C11220E -> 0x00007FF71C11221B) ---
    qword ptr [rdi], rbp; // mov
    rbp, qword ptr [rsp + 0x60]; // mov
    r12, qword ptr [rsp + 0x68]; // mov

loc_7FF71C11221B:
    // --- Basic Block 45 (0x00007FF71C11221B -> 0x00007FF71C112230) ---
    rbx, qword ptr [rsp + 0x70]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C112230:
    // --- Basic Block 46 (0x00007FF71C112230 -> 0x00007FF71C112250) ---
    rax_result = sub_7FF71C1120A0(); // 0x7ff71c1120a0
    // asm: int3 
    // asm: int3 
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
    rax, rdx; // mov
    // asm: cmp r8, 0x1000
    if (jb_condition) {
        goto loc_7FF71C112268;
    } else {
        goto loc_7FF71C112250;
    }

loc_7FF71C112250:
    // --- Basic Block 47 (0x00007FF71C112250 -> 0x00007FF71C112265) ---
    rcx, qword ptr [rdx - 8]; // mov
    // asm: add r8, 0x27
    // asm: sub rax, rcx
    // asm: sub rax, 8
    // asm: cmp rax, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112277;
    } else {
        goto loc_7FF71C112265;
    }

loc_7FF71C112265:
    // --- Basic Block 48 (0x00007FF71C112265 -> 0x00007FF71C112268) ---
    rax, rcx; // mov

loc_7FF71C112268:
    // --- Basic Block 49 (0x00007FF71C112268 -> 0x00007FF71C112277) ---
    rdx, r8; // mov
    rcx, rax; // mov
    // asm: add rsp, 0x38
    goto loc_7FF71C1132B0;

loc_7FF71C112277:
    // --- Basic Block 50 (0x00007FF71C112277 -> 0x00007FF71C1122C3) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x30f0]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    edx, 0x800; // mov
    r8d, 0xe00; // mov
    rbx, rcx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2f66]);
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF71C111D00` (0x7FF71C111D00)
- **Size**: `1475 bytes` | **Complexity V(G)**: `17` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111D00 | Address: 0x00007FF71C111D00
// Size: 1475 bytes | Basic Blocks: 44 | Complexity V(G): 17
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111D00(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111D00:
    // --- Basic Block 0 (0x00007FF71C111D00 -> 0x00007FF71C111D9D) ---
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
    rax_result = indirect_call(qword ptr [rip + 0x3316]);
    dword ptr [rsp + 0x40], edi; // mov
    dword ptr [rsp + 0x38], edi; // mov
    qword ptr [rsp + 0x30], rdi; // mov
    qword ptr [rsp + 0x28], rdi; // mov
    qword ptr [rsp + 0x20], rdi; // mov
    r9, [rsp + 0x40]; // lea
    r8d = 0;
    edx = 0;
    rcx, [rip + 0x38be]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3300]);
    esi, 0x539; // mov
    ebx, edi; // mov
    rcx, [rbp + 0x50]; // lea
    rax_result = sub_7FF71C114122(); // 0x7ff71c114122
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C111DB2;
    } else {
        goto loc_7FF71C111D9D;
    }

loc_7FF71C111D9D:
    // --- Basic Block 1 (0x00007FF71C111D9D -> 0x00007FF71C111DA0) ---

loc_7FF71C111DA0:
    // --- Basic Block 2 (0x00007FF71C111DA0 -> 0x00007FF71C111DB2) ---
    // asm: movsx ecx, byte ptr [rbp + rbx + 0x50]
    // asm: imul esi, esi, 0x21
    // asm: xor esi, ecx
    // asm: inc rbx
    // asm: cmp rbx, rax
    if (jb_condition) {
        goto loc_7FF71C111DA0;
    } else {
        goto loc_7FF71C111DB2;
    }

loc_7FF71C111DB2:
    // --- Basic Block 3 (0x00007FF71C111DB2 -> 0x00007FF71C111F28) ---
    // asm: xor esi, dword ptr [rsp + 0x40]
    rax, [rip + 0x387b]; // lea
    qword ptr [rsp + 0x60], rax; // mov
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3364]);
    dword ptr [rsp + 0x44], 2; // mov
    r9d = 0;
    r8d = 0;
    rdx, [rsp + 0x68]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x334d]);
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    r15, [rip + 0x3834]; // lea
    qword ptr [rsp + rcx + 0x60], r15; // mov
    rax, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rcx, dword ptr [rax + 4]
    edx, [rcx - 0x88]; // lea
    dword ptr [rsp + rcx + 0x5c], edx; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x33e9]);
    rax, [rip + 0x378a]; // lea
    qword ptr [rsp + 0x68], rax; // mov
    qword ptr [rbp - 0x30], rdi; // mov
    dword ptr [rbp - 0x28], 4; // mov
    edx, 8; // mov
    rcx, [rsp + 0x50]; // lea
    rax_result = sub_7FF71C113238(); // 0x7ff71c113238
    rbx, rax; // mov
    rdx, [rip + 0x37f5]; // lea
    rcx, [rsp + 0x60]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, rax; // mov
    rdx, [rip + 0xdbd]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32e7]);
    rcx, rax; // mov
    rdx, [rip + 0x42d]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x32d7]);
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
    rax_result = indirect_call(qword ptr [rip + 0x327f]);
    edx, esi; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x32ac]);
    rdx, r14; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C112920(); // 0x7ff71c112920
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    qword ptr [rsp + rdx + 0x60], r15; // mov
    rcx, qword ptr [rsp + 0x60]; // mov
    // asm: movsxd rdx, dword ptr [rcx + 4]
    r8d, [rdx - 0x88]; // lea
    dword ptr [rsp + rdx + 0x5c], r8d; // mov
    rcx, [rsp + 0x68]; // lea
    rax_result = sub_7FF71C1118D0(); // 0x7ff71c1118d0
    rcx, [rsp + 0x70]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x3366]);
    rcx, [rbp - 0x18]; // lea
    rax_result = indirect_call(qword ptr [rip + 0x31fc]);
    rax, r14; // mov
    rcx, qword ptr [rbp + 0x60]; // mov
    // asm: xor rcx, rsp
    rax_result = sub_7FF71C1133B0(); // 0x7ff71c1133b0
    r11, [rsp + 0x170]; // lea
    rbx, qword ptr [r11 + 0x28]; // mov
    rsi, qword ptr [r11 + 0x30]; // mov
    rdi, qword ptr [r11 + 0x38]; // mov
    rsp, r11; // mov
    return rax_result;

loc_7FF71C111F28:
    // --- Basic Block 4 (0x00007FF71C111F28 -> 0x00007FF71C111F97) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x28
    rcx, qword ptr [rip + 0x329d]; // mov
    rdx, [rip + 0x3716]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x328a]; // mov
    rdx, [rip + 0x3743]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3277]; // mov
    rdx, [rip + 0x3760]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3264]; // mov
    rdx, [rip + 0x3795]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3251]; // mov
    rdx, [rip + 0x37c2]; // lea
    // asm: add rsp, 0x28
    goto loc_7FF71C111000;

loc_7FF71C111F97:
    // --- Basic Block 5 (0x00007FF71C111F97 -> 0x00007FF71C111FB5) ---
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
    r10, qword ptr [rcx + 0x10]; // mov
    r9, rdx; // mov
    r8, rcx; // mov
    // asm: cmp r10, qword ptr [rdx + 0x10]
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FB5;
    }

loc_7FF71C111FB5:
    // --- Basic Block 6 (0x00007FF71C111FB5 -> 0x00007FF71C111FBC) ---
    eax = 0;
    // asm: test r10, r10
    if (je_condition) {
        goto loc_7FF71C111FED;
    } else {
        goto loc_7FF71C111FBC;
    }

loc_7FF71C111FBC:
    // --- Basic Block 7 (0x00007FF71C111FBC -> 0x00007FF71C111FC4) ---
    rbx, qword ptr [rdx + 0x18]; // mov
    r11, qword ptr [rcx + 0x18]; // mov

loc_7FF71C111FC4:
    // --- Basic Block 8 (0x00007FF71C111FC4 -> 0x00007FF71C111FCD) ---
    rdx, r8; // mov
    // asm: cmp r11, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FD0;
    } else {
        goto loc_7FF71C111FCD;
    }

loc_7FF71C111FCD:
    // --- Basic Block 9 (0x00007FF71C111FCD -> 0x00007FF71C111FD0) ---
    rdx, qword ptr [r8]; // mov

loc_7FF71C111FD0:
    // --- Basic Block 10 (0x00007FF71C111FD0 -> 0x00007FF71C111FD9) ---
    rcx, r9; // mov
    // asm: cmp rbx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FDC;
    } else {
        goto loc_7FF71C111FD9;
    }

loc_7FF71C111FD9:
    // --- Basic Block 11 (0x00007FF71C111FD9 -> 0x00007FF71C111FDC) ---
    rcx, qword ptr [r9]; // mov

loc_7FF71C111FDC:
    // --- Basic Block 12 (0x00007FF71C111FDC -> 0x00007FF71C111FE5) ---
    // asm: movzx ecx, byte ptr [rcx + rax]
    // asm: cmp byte ptr [rdx + rax], cl
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FE5;
    }

loc_7FF71C111FE5:
    // --- Basic Block 13 (0x00007FF71C111FE5 -> 0x00007FF71C111FED) ---
    // asm: inc rax
    // asm: cmp rax, r10
    if (jb_condition) {
        goto loc_7FF71C111FC4;
    } else {
        goto loc_7FF71C111FED;
    }

loc_7FF71C111FED:
    // --- Basic Block 14 (0x00007FF71C111FED -> 0x00007FF71C111FF5) ---
    al, 1; // mov
    rbx, qword ptr [rsp + 8]; // mov
    return rax_result;

loc_7FF71C111FF5:
    // --- Basic Block 15 (0x00007FF71C111FF5 -> 0x00007FF71C111FFD) ---
    rbx, qword ptr [rsp + 8]; // mov
    // asm: xor al, al
    return rax_result;

loc_7FF71C111FFD:
    // --- Basic Block 16 (0x00007FF71C111FFD -> 0x00007FF71C112033) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x48
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C111850(); // 0x7ff71c111850
    rdx, [rip + 0x497b]; // lea
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C1140F2(); // 0x7ff71c1140f2
    // asm: int3 
    // asm: sub rsp, 0x30
    rdx, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rdx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C11205F;
    } else {
        goto loc_7FF71C112033;
    }

loc_7FF71C112033:
    // --- Basic Block 17 (0x00007FF71C112033 -> 0x00007FF71C112042) ---
    rcx, qword ptr [rcx]; // mov
    // asm: inc rdx
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11205A;
    } else {
        goto loc_7FF71C112042;
    }

loc_7FF71C112042:
    // --- Basic Block 18 (0x00007FF71C112042 -> 0x00007FF71C112057) ---
    rax, qword ptr [rcx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rcx, rax
    // asm: sub rcx, 8
    // asm: cmp rcx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112078;
    } else {
        goto loc_7FF71C112057;
    }

loc_7FF71C112057:
    // --- Basic Block 19 (0x00007FF71C112057 -> 0x00007FF71C11205A) ---
    rcx, rax; // mov

loc_7FF71C11205A:
    // --- Basic Block 20 (0x00007FF71C11205A -> 0x00007FF71C11205F) ---
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C11205F:
    // --- Basic Block 21 (0x00007FF71C11205F -> 0x00007FF71C112078) ---
    qword ptr [rbx + 0x10], 0; // mov
    qword ptr [rbx + 0x18], 0xf; // mov
    byte ptr [rbx], 0; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C112078:
    // --- Basic Block 22 (0x00007FF71C112078 -> 0x00007FF71C1120ED) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x32ef]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rcx, [rip + 0x34ed]; // lea
    rax_result = sub_7FF71C11322C(); // 0x7ff71c11322c
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    // asm: sub rsp, 0x30
    r15, qword ptr [rcx + 0x18]; // mov
    rsi, r8; // mov
    r14, qword ptr [rcx + 0x10]; // mov
    rax, r15; // mov
    // asm: sub rax, r14
    r13, rdx; // mov
    rdi, rcx; // mov
    // asm: cmp r8, rax
    if (ja_condition) {
        goto loc_7FF71C112116;
    } else {
        goto loc_7FF71C1120ED;
    }

loc_7FF71C1120ED:
    // --- Basic Block 23 (0x00007FF71C1120ED -> 0x00007FF71C1120FE) ---
    rax, [r14 + r8]; // lea
    qword ptr [rcx + 0x10], rax; // mov
    rax, rcx; // mov
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C112101;
    } else {
        goto loc_7FF71C1120FE;
    }

loc_7FF71C1120FE:
    // --- Basic Block 24 (0x00007FF71C1120FE -> 0x00007FF71C112101) ---
    rax, qword ptr [rcx]; // mov

loc_7FF71C112101:
    // --- Basic Block 25 (0x00007FF71C112101 -> 0x00007FF71C112116) ---
    rbx, [r14 + rax]; // lea
    rcx, rbx; // mov
    rax_result = sub_7FF71C114104(); // 0x7ff71c114104
    byte ptr [rbx + rsi], 0; // mov
    goto loc_7FF71C11221B;

loc_7FF71C112116:
    // --- Basic Block 26 (0x00007FF71C112116 -> 0x00007FF71C11212F) ---
    // asm: movabs rbx, 0x7fffffffffffffff
    rax, rbx; // mov
    // asm: sub rax, r14
    // asm: cmp rax, rsi
    if (jb_condition) {
        goto loc_7FF71C112230;
    } else {
        goto loc_7FF71C11212F;
    }

loc_7FF71C11212F:
    // --- Basic Block 27 (0x00007FF71C11212F -> 0x00007FF71C112149) ---
    qword ptr [rsp + 0x60], rbp; // mov
    qword ptr [rsp + 0x68], r12; // mov
    r12, [r14 + r8]; // lea
    rcx, r12; // mov
    // asm: or rcx, 0xf
    // asm: cmp rcx, rbx
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C112149;
    }

loc_7FF71C112149:
    // --- Basic Block 28 (0x00007FF71C112149 -> 0x00007FF71C11215A) ---
    rdx, r15; // mov
    rax, rbx; // mov
    // asm: shr rdx, 1
    // asm: sub rax, rdx
    // asm: cmp r15, rax
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C11215A;
    }

loc_7FF71C11215A:
    // --- Basic Block 29 (0x00007FF71C11215A -> 0x00007FF71C112168) ---
    rax, [r15 + rdx]; // lea
    rbx, rcx; // mov
    // asm: cmp rcx, rax
    // asm: cmovb rbx, rax

loc_7FF71C112168:
    // --- Basic Block 30 (0x00007FF71C112168 -> 0x00007FF71C11218C) ---
    rcx, [rbx + 1]; // lea
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    qword ptr [rdi + 0x10], r12; // mov
    rbp, rax; // mov
    qword ptr [rdi + 0x18], rbx; // mov
    r8, r14; // mov
    rcx, rax; // mov
    r12, [r14 + rax]; // lea
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C1121F3;
    } else {
        goto loc_7FF71C11218C;
    }

loc_7FF71C11218C:
    // --- Basic Block 31 (0x00007FF71C11218C -> 0x00007FF71C1121B7) ---
    rbx, qword ptr [rdi]; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    rdx, [r15 + 1]; // lea
    byte ptr [r12 + rsi], 0; // mov
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C1121CF;
    } else {
        goto loc_7FF71C1121B7;
    }

loc_7FF71C1121B7:
    // --- Basic Block 32 (0x00007FF71C1121B7 -> 0x00007FF71C1121CC) ---
    rax, qword ptr [rbx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rbx, rax
    // asm: sub rbx, 8
    // asm: cmp rbx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C1121D9;
    } else {
        goto loc_7FF71C1121CC;
    }

loc_7FF71C1121CC:
    // --- Basic Block 33 (0x00007FF71C1121CC -> 0x00007FF71C1121CF) ---
    rbx, rax; // mov

loc_7FF71C1121CF:
    // --- Basic Block 34 (0x00007FF71C1121CF -> 0x00007FF71C1121D9) ---
    rcx, rbx; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0
    goto loc_7FF71C11220E;

loc_7FF71C1121D9:
    // --- Basic Block 35 (0x00007FF71C1121D9 -> 0x00007FF71C1121F3) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x318e]);
    // asm: int3 

loc_7FF71C1121F3:
    // --- Basic Block 36 (0x00007FF71C1121F3 -> 0x00007FF71C11220E) ---
    rdx, rdi; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [r12 + rsi], 0; // mov

loc_7FF71C11220E:
    // --- Basic Block 37 (0x00007FF71C11220E -> 0x00007FF71C11221B) ---
    qword ptr [rdi], rbp; // mov
    rbp, qword ptr [rsp + 0x60]; // mov
    r12, qword ptr [rsp + 0x68]; // mov

loc_7FF71C11221B:
    // --- Basic Block 38 (0x00007FF71C11221B -> 0x00007FF71C112230) ---
    rbx, qword ptr [rsp + 0x70]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C112230:
    // --- Basic Block 39 (0x00007FF71C112230 -> 0x00007FF71C112250) ---
    rax_result = sub_7FF71C1120A0(); // 0x7ff71c1120a0
    // asm: int3 
    // asm: int3 
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
    rax, rdx; // mov
    // asm: cmp r8, 0x1000
    if (jb_condition) {
        goto loc_7FF71C112268;
    } else {
        goto loc_7FF71C112250;
    }

loc_7FF71C112250:
    // --- Basic Block 40 (0x00007FF71C112250 -> 0x00007FF71C112265) ---
    rcx, qword ptr [rdx - 8]; // mov
    // asm: add r8, 0x27
    // asm: sub rax, rcx
    // asm: sub rax, 8
    // asm: cmp rax, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112277;
    } else {
        goto loc_7FF71C112265;
    }

loc_7FF71C112265:
    // --- Basic Block 41 (0x00007FF71C112265 -> 0x00007FF71C112268) ---
    rax, rcx; // mov

loc_7FF71C112268:
    // --- Basic Block 42 (0x00007FF71C112268 -> 0x00007FF71C112277) ---
    rdx, r8; // mov
    rcx, rax; // mov
    // asm: add rsp, 0x38
    goto loc_7FF71C1132B0;

loc_7FF71C112277:
    // --- Basic Block 43 (0x00007FF71C112277 -> 0x00007FF71C1122C3) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x30f0]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    edx, 0x800; // mov
    r8d, 0xe00; // mov
    rbx, rcx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2f66]);
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

}
```

### Function `sub_00007FF71C111F30` (0x7FF71C111F30)
- **Size**: `1499 bytes` | **Complexity V(G)**: `29` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C111F30 | Address: 0x00007FF71C111F30
// Size: 1499 bytes | Basic Blocks: 72 | Complexity V(G): 29
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C111F30(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C111F30:
    // --- Basic Block 0 (0x00007FF71C111F30 -> 0x00007FF71C111F97) ---
    // asm: sub rsp, 0x28
    rcx, qword ptr [rip + 0x329d]; // mov
    rdx, [rip + 0x3716]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x328a]; // mov
    rdx, [rip + 0x3743]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3277]; // mov
    rdx, [rip + 0x3760]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3264]; // mov
    rdx, [rip + 0x3795]; // lea
    rax_result = sub_7FF71C111000(); // 0x7ff71c111000
    rcx, qword ptr [rip + 0x3251]; // mov
    rdx, [rip + 0x37c2]; // lea
    // asm: add rsp, 0x28
    goto loc_7FF71C111000;

loc_7FF71C111F97:
    // --- Basic Block 1 (0x00007FF71C111F97 -> 0x00007FF71C111FB5) ---
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
    r10, qword ptr [rcx + 0x10]; // mov
    r9, rdx; // mov
    r8, rcx; // mov
    // asm: cmp r10, qword ptr [rdx + 0x10]
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FB5;
    }

loc_7FF71C111FB5:
    // --- Basic Block 2 (0x00007FF71C111FB5 -> 0x00007FF71C111FBC) ---
    eax = 0;
    // asm: test r10, r10
    if (je_condition) {
        goto loc_7FF71C111FED;
    } else {
        goto loc_7FF71C111FBC;
    }

loc_7FF71C111FBC:
    // --- Basic Block 3 (0x00007FF71C111FBC -> 0x00007FF71C111FC4) ---
    rbx, qword ptr [rdx + 0x18]; // mov
    r11, qword ptr [rcx + 0x18]; // mov

loc_7FF71C111FC4:
    // --- Basic Block 4 (0x00007FF71C111FC4 -> 0x00007FF71C111FCD) ---
    rdx, r8; // mov
    // asm: cmp r11, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FD0;
    } else {
        goto loc_7FF71C111FCD;
    }

loc_7FF71C111FCD:
    // --- Basic Block 5 (0x00007FF71C111FCD -> 0x00007FF71C111FD0) ---
    rdx, qword ptr [r8]; // mov

loc_7FF71C111FD0:
    // --- Basic Block 6 (0x00007FF71C111FD0 -> 0x00007FF71C111FD9) ---
    rcx, r9; // mov
    // asm: cmp rbx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C111FDC;
    } else {
        goto loc_7FF71C111FD9;
    }

loc_7FF71C111FD9:
    // --- Basic Block 7 (0x00007FF71C111FD9 -> 0x00007FF71C111FDC) ---
    rcx, qword ptr [r9]; // mov

loc_7FF71C111FDC:
    // --- Basic Block 8 (0x00007FF71C111FDC -> 0x00007FF71C111FE5) ---
    // asm: movzx ecx, byte ptr [rcx + rax]
    // asm: cmp byte ptr [rdx + rax], cl
    if (jne_condition) {
        goto loc_7FF71C111FF5;
    } else {
        goto loc_7FF71C111FE5;
    }

loc_7FF71C111FE5:
    // --- Basic Block 9 (0x00007FF71C111FE5 -> 0x00007FF71C111FED) ---
    // asm: inc rax
    // asm: cmp rax, r10
    if (jb_condition) {
        goto loc_7FF71C111FC4;
    } else {
        goto loc_7FF71C111FED;
    }

loc_7FF71C111FED:
    // --- Basic Block 10 (0x00007FF71C111FED -> 0x00007FF71C111FF5) ---
    al, 1; // mov
    rbx, qword ptr [rsp + 8]; // mov
    return rax_result;

loc_7FF71C111FF5:
    // --- Basic Block 11 (0x00007FF71C111FF5 -> 0x00007FF71C111FFD) ---
    rbx, qword ptr [rsp + 8]; // mov
    // asm: xor al, al
    return rax_result;

loc_7FF71C111FFD:
    // --- Basic Block 12 (0x00007FF71C111FFD -> 0x00007FF71C112033) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: sub rsp, 0x48
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C111850(); // 0x7ff71c111850
    rdx, [rip + 0x497b]; // lea
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C1140F2(); // 0x7ff71c1140f2
    // asm: int3 
    // asm: sub rsp, 0x30
    rdx, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rdx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C11205F;
    } else {
        goto loc_7FF71C112033;
    }

loc_7FF71C112033:
    // --- Basic Block 13 (0x00007FF71C112033 -> 0x00007FF71C112042) ---
    rcx, qword ptr [rcx]; // mov
    // asm: inc rdx
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11205A;
    } else {
        goto loc_7FF71C112042;
    }

loc_7FF71C112042:
    // --- Basic Block 14 (0x00007FF71C112042 -> 0x00007FF71C112057) ---
    rax, qword ptr [rcx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rcx, rax
    // asm: sub rcx, 8
    // asm: cmp rcx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112078;
    } else {
        goto loc_7FF71C112057;
    }

loc_7FF71C112057:
    // --- Basic Block 15 (0x00007FF71C112057 -> 0x00007FF71C11205A) ---
    rcx, rax; // mov

loc_7FF71C11205A:
    // --- Basic Block 16 (0x00007FF71C11205A -> 0x00007FF71C11205F) ---
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C11205F:
    // --- Basic Block 17 (0x00007FF71C11205F -> 0x00007FF71C112078) ---
    qword ptr [rbx + 0x10], 0; // mov
    qword ptr [rbx + 0x18], 0xf; // mov
    byte ptr [rbx], 0; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C112078:
    // --- Basic Block 18 (0x00007FF71C112078 -> 0x00007FF71C1120ED) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x32ef]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rcx, [rip + 0x34ed]; // lea
    rax_result = sub_7FF71C11322C(); // 0x7ff71c11322c
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    // asm: sub rsp, 0x30
    r15, qword ptr [rcx + 0x18]; // mov
    rsi, r8; // mov
    r14, qword ptr [rcx + 0x10]; // mov
    rax, r15; // mov
    // asm: sub rax, r14
    r13, rdx; // mov
    rdi, rcx; // mov
    // asm: cmp r8, rax
    if (ja_condition) {
        goto loc_7FF71C112116;
    } else {
        goto loc_7FF71C1120ED;
    }

loc_7FF71C1120ED:
    // --- Basic Block 19 (0x00007FF71C1120ED -> 0x00007FF71C1120FE) ---
    rax, [r14 + r8]; // lea
    qword ptr [rcx + 0x10], rax; // mov
    rax, rcx; // mov
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C112101;
    } else {
        goto loc_7FF71C1120FE;
    }

loc_7FF71C1120FE:
    // --- Basic Block 20 (0x00007FF71C1120FE -> 0x00007FF71C112101) ---
    rax, qword ptr [rcx]; // mov

loc_7FF71C112101:
    // --- Basic Block 21 (0x00007FF71C112101 -> 0x00007FF71C112116) ---
    rbx, [r14 + rax]; // lea
    rcx, rbx; // mov
    rax_result = sub_7FF71C114104(); // 0x7ff71c114104
    byte ptr [rbx + rsi], 0; // mov
    goto loc_7FF71C11221B;

loc_7FF71C112116:
    // --- Basic Block 22 (0x00007FF71C112116 -> 0x00007FF71C11212F) ---
    // asm: movabs rbx, 0x7fffffffffffffff
    rax, rbx; // mov
    // asm: sub rax, r14
    // asm: cmp rax, rsi
    if (jb_condition) {
        goto loc_7FF71C112230;
    } else {
        goto loc_7FF71C11212F;
    }

loc_7FF71C11212F:
    // --- Basic Block 23 (0x00007FF71C11212F -> 0x00007FF71C112149) ---
    qword ptr [rsp + 0x60], rbp; // mov
    qword ptr [rsp + 0x68], r12; // mov
    r12, [r14 + r8]; // lea
    rcx, r12; // mov
    // asm: or rcx, 0xf
    // asm: cmp rcx, rbx
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C112149;
    }

loc_7FF71C112149:
    // --- Basic Block 24 (0x00007FF71C112149 -> 0x00007FF71C11215A) ---
    rdx, r15; // mov
    rax, rbx; // mov
    // asm: shr rdx, 1
    // asm: sub rax, rdx
    // asm: cmp r15, rax
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C11215A;
    }

loc_7FF71C11215A:
    // --- Basic Block 25 (0x00007FF71C11215A -> 0x00007FF71C112168) ---
    rax, [r15 + rdx]; // lea
    rbx, rcx; // mov
    // asm: cmp rcx, rax
    // asm: cmovb rbx, rax

loc_7FF71C112168:
    // --- Basic Block 26 (0x00007FF71C112168 -> 0x00007FF71C11218C) ---
    rcx, [rbx + 1]; // lea
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    qword ptr [rdi + 0x10], r12; // mov
    rbp, rax; // mov
    qword ptr [rdi + 0x18], rbx; // mov
    r8, r14; // mov
    rcx, rax; // mov
    r12, [r14 + rax]; // lea
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C1121F3;
    } else {
        goto loc_7FF71C11218C;
    }

loc_7FF71C11218C:
    // --- Basic Block 27 (0x00007FF71C11218C -> 0x00007FF71C1121B7) ---
    rbx, qword ptr [rdi]; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    rdx, [r15 + 1]; // lea
    byte ptr [r12 + rsi], 0; // mov
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C1121CF;
    } else {
        goto loc_7FF71C1121B7;
    }

loc_7FF71C1121B7:
    // --- Basic Block 28 (0x00007FF71C1121B7 -> 0x00007FF71C1121CC) ---
    rax, qword ptr [rbx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rbx, rax
    // asm: sub rbx, 8
    // asm: cmp rbx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C1121D9;
    } else {
        goto loc_7FF71C1121CC;
    }

loc_7FF71C1121CC:
    // --- Basic Block 29 (0x00007FF71C1121CC -> 0x00007FF71C1121CF) ---
    rbx, rax; // mov

loc_7FF71C1121CF:
    // --- Basic Block 30 (0x00007FF71C1121CF -> 0x00007FF71C1121D9) ---
    rcx, rbx; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0
    goto loc_7FF71C11220E;

loc_7FF71C1121D9:
    // --- Basic Block 31 (0x00007FF71C1121D9 -> 0x00007FF71C1121F3) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x318e]);
    // asm: int3 

loc_7FF71C1121F3:
    // --- Basic Block 32 (0x00007FF71C1121F3 -> 0x00007FF71C11220E) ---
    rdx, rdi; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [r12 + rsi], 0; // mov

loc_7FF71C11220E:
    // --- Basic Block 33 (0x00007FF71C11220E -> 0x00007FF71C11221B) ---
    qword ptr [rdi], rbp; // mov
    rbp, qword ptr [rsp + 0x60]; // mov
    r12, qword ptr [rsp + 0x68]; // mov

loc_7FF71C11221B:
    // --- Basic Block 34 (0x00007FF71C11221B -> 0x00007FF71C112230) ---
    rbx, qword ptr [rsp + 0x70]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C112230:
    // --- Basic Block 35 (0x00007FF71C112230 -> 0x00007FF71C112250) ---
    rax_result = sub_7FF71C1120A0(); // 0x7ff71c1120a0
    // asm: int3 
    // asm: int3 
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
    rax, rdx; // mov
    // asm: cmp r8, 0x1000
    if (jb_condition) {
        goto loc_7FF71C112268;
    } else {
        goto loc_7FF71C112250;
    }

loc_7FF71C112250:
    // --- Basic Block 36 (0x00007FF71C112250 -> 0x00007FF71C112265) ---
    rcx, qword ptr [rdx - 8]; // mov
    // asm: add r8, 0x27
    // asm: sub rax, rcx
    // asm: sub rax, 8
    // asm: cmp rax, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112277;
    } else {
        goto loc_7FF71C112265;
    }

loc_7FF71C112265:
    // --- Basic Block 37 (0x00007FF71C112265 -> 0x00007FF71C112268) ---
    rax, rcx; // mov

loc_7FF71C112268:
    // --- Basic Block 38 (0x00007FF71C112268 -> 0x00007FF71C112277) ---
    rdx, r8; // mov
    rcx, rax; // mov
    // asm: add rsp, 0x38
    goto loc_7FF71C1132B0;

loc_7FF71C112277:
    // --- Basic Block 39 (0x00007FF71C112277 -> 0x00007FF71C1122C3) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x30f0]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    edx, 0x800; // mov
    r8d, 0xe00; // mov
    rbx, rcx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2f66]);
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1122C3:
    // --- Basic Block 40 (0x00007FF71C1122C3 -> 0x00007FF71C1122F1) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    qword ptr [rsp + 0x18], rbp; // mov
    // asm: sub rsp, 0x20
    // asm: test byte ptr [rcx + 0x70], 2
    ebp, edx; // mov
    rdi, rcx; // mov
    if (jne_condition) {
        goto loc_7FF71C112414;
    } else {
        goto loc_7FF71C1122F1;
    }

loc_7FF71C1122F1:
    // --- Basic Block 41 (0x00007FF71C1122F1 -> 0x00007FF71C1122F6) ---
    // asm: cmp edx, -1
    if (jne_condition) {
        goto loc_7FF71C1122FD;
    } else {
        goto loc_7FF71C1122F6;
    }

loc_7FF71C1122F6:
    // --- Basic Block 42 (0x00007FF71C1122F6 -> 0x00007FF71C1122FD) ---
    eax = 0;
    goto loc_7FF71C112419;

loc_7FF71C1122FD:
    // --- Basic Block 43 (0x00007FF71C1122FD -> 0x00007FF71C112317) ---
    rax_result = indirect_call(qword ptr [rip + 0x2db5]);
    rcx, rdi; // mov
    rbx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2dc9]);
    rsi, rax; // mov
    // asm: test rbx, rbx
    if (je_condition) {
        goto loc_7FF71C112337;
    } else {
        goto loc_7FF71C112317;
    }

loc_7FF71C112317:
    // --- Basic Block 44 (0x00007FF71C112317 -> 0x00007FF71C11231C) ---
    // asm: cmp rbx, rax
    if (jae_condition) {
        goto loc_7FF71C112337;
    } else {
        goto loc_7FF71C11231C;
    }

loc_7FF71C11231C:
    // --- Basic Block 45 (0x00007FF71C11231C -> 0x00007FF71C112337) ---
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2dcb]);
    byte ptr [rax], bpl; // mov
    rax, [rbx + 1]; // lea
    qword ptr [rdi + 0x68], rax; // mov
    eax, ebp; // mov
    goto loc_7FF71C112419;

loc_7FF71C112337:
    // --- Basic Block 46 (0x00007FF71C112337 -> 0x00007FF71C112355) ---
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2d60]);
    // asm: sub rsi, rax
    r15, rax; // mov
    eax = 0;
    // asm: test rbx, rbx
    // asm: cmove rsi, rax
    // asm: cmp rsi, 0x20
    if (jae_condition) {
        goto loc_7FF71C11235C;
    } else {
        goto loc_7FF71C112355;
    }

loc_7FF71C112355:
    // --- Basic Block 47 (0x00007FF71C112355 -> 0x00007FF71C11235C) ---
    ebx, 0x20; // mov
    goto loc_7FF71C112379;

loc_7FF71C11235C:
    // --- Basic Block 48 (0x00007FF71C11235C -> 0x00007FF71C112365) ---
    // asm: cmp rsi, 0x3fffffff
    if (jae_condition) {
        goto loc_7FF71C11236B;
    } else {
        goto loc_7FF71C112365;
    }

loc_7FF71C112365:
    // --- Basic Block 49 (0x00007FF71C112365 -> 0x00007FF71C11236B) ---
    rbx, [rsi + rsi]; // lea
    goto loc_7FF71C112379;

loc_7FF71C11236B:
    // --- Basic Block 50 (0x00007FF71C11236B -> 0x00007FF71C112379) ---
    ebx, 0x7fffffff; // mov
    // asm: cmp rsi, rbx
    if (jae_condition) {
        goto loc_7FF71C112414;
    } else {
        goto loc_7FF71C112379;
    }

loc_7FF71C112379:
    // --- Basic Block 51 (0x00007FF71C112379 -> 0x00007FF71C1123BC) ---
    rcx, rbx; // mov
    qword ptr [rsp + 0x40], r14; // mov
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    r8, rsi; // mov
    rdx, r15; // mov
    rcx, rax; // mov
    r14, rax; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, [rsi + r14]; // lea
    rdx, r14; // mov
    rcx, [r8 + 1]; // lea
    qword ptr [rdi + 0x68], rcx; // mov
    r9, [r14 + rbx]; // lea
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2d35]);
    // asm: test byte ptr [rdi + 0x70], 4
    rcx, rdi; // mov
    if (je_condition) {
        goto loc_7FF71C1123C4;
    } else {
        goto loc_7FF71C1123BC;
    }

loc_7FF71C1123BC:
    // --- Basic Block 52 (0x00007FF71C1123BC -> 0x00007FF71C1123C4) ---
    r9, r14; // mov
    r8, r14; // mov
    goto loc_7FF71C1123DD;

loc_7FF71C1123C4:
    // --- Basic Block 53 (0x00007FF71C1123C4 -> 0x00007FF71C1123DD) ---
    rbx, qword ptr [rdi + 0x68]; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2cda]);
    r8, r14; // mov
    r9, rbx; // mov
    // asm: sub r8, r15
    rcx, rdi; // mov
    // asm: add r8, rax

loc_7FF71C1123DD:
    // --- Basic Block 54 (0x00007FF71C1123DD -> 0x00007FF71C1123F1) ---
    rdx, r14; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2cea]);
    // asm: test byte ptr [rdi + 0x70], 1
    r14, qword ptr [rsp + 0x40]; // mov
    if (je_condition) {
        goto loc_7FF71C112400;
    } else {
        goto loc_7FF71C1123F1;
    }

loc_7FF71C1123F1:
    // --- Basic Block 55 (0x00007FF71C1123F1 -> 0x00007FF71C112400) ---
    rcx, [rdi + 0x74]; // lea
    r8, rsi; // mov
    rdx, r15; // mov
    rax_result = sub_7FF71C112240(); // 0x7ff71c112240

loc_7FF71C112400:
    // --- Basic Block 56 (0x00007FF71C112400 -> 0x00007FF71C112414) ---
    // asm: or dword ptr [rdi + 0x70], 1
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2ce3]);
    byte ptr [rax], bpl; // mov
    eax, ebp; // mov
    goto loc_7FF71C112419;

loc_7FF71C112414:
    // --- Basic Block 57 (0x00007FF71C112414 -> 0x00007FF71C112419) ---
    eax, 0xffffffff; // mov

loc_7FF71C112419:
    // --- Basic Block 58 (0x00007FF71C112419 -> 0x00007FF71C11242C) ---
    rbx, qword ptr [rsp + 0x48]; // mov
    rbp, qword ptr [rsp + 0x50]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11242C:
    // --- Basic Block 59 (0x00007FF71C11242C -> 0x00007FF71C112452) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2c5e]);
    rsi, rax; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1124A8;
    } else {
        goto loc_7FF71C112452;
    }

loc_7FF71C112452:
    // --- Basic Block 60 (0x00007FF71C112452 -> 0x00007FF71C112460) ---
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2c45]);
    // asm: cmp rsi, rax
    if (jbe_condition) {
        goto loc_7FF71C1124A8;
    } else {
        goto loc_7FF71C112460;
    }

loc_7FF71C112460:
    // --- Basic Block 61 (0x00007FF71C112460 -> 0x00007FF71C112465) ---
    // asm: cmp ebx, -1
    if (je_condition) {
        goto loc_7FF71C112470;
    } else {
        goto loc_7FF71C112465;
    }

loc_7FF71C112465:
    // --- Basic Block 62 (0x00007FF71C112465 -> 0x00007FF71C11246A) ---
    // asm: cmp bl, byte ptr [rsi - 1]
    if (je_condition) {
        goto loc_7FF71C112470;
    } else {
        goto loc_7FF71C11246A;
    }

loc_7FF71C11246A:
    // --- Basic Block 63 (0x00007FF71C11246A -> 0x00007FF71C112470) ---
    // asm: test byte ptr [rdi + 0x70], 2
    if (jne_condition) {
        goto loc_7FF71C1124A8;
    } else {
        goto loc_7FF71C112470;
    }

loc_7FF71C112470:
    // --- Basic Block 64 (0x00007FF71C112470 -> 0x00007FF71C112483) ---
    edx, 0xffffffff; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2c4a]);
    // asm: cmp ebx, -1
    if (je_condition) {
        goto loc_7FF71C11248E;
    } else {
        goto loc_7FF71C112483;
    }

loc_7FF71C112483:
    // --- Basic Block 65 (0x00007FF71C112483 -> 0x00007FF71C11248E) ---
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2c1c]);
    byte ptr [rax], bl; // mov

loc_7FF71C11248E:
    // --- Basic Block 66 (0x00007FF71C11248E -> 0x00007FF71C1124A8) ---
    eax = 0;
    // asm: cmp ebx, -1
    // asm: cmove ebx, eax
    eax, ebx; // mov
    rbx, qword ptr [rsp + 0x30]; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1124A8:
    // --- Basic Block 67 (0x00007FF71C1124A8 -> 0x00007FF71C1124BD) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    eax, 0xffffffff; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1124BD:
    // --- Basic Block 68 (0x00007FF71C1124BD -> 0x00007FF71C1124E2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x20], rbx; // mov
    // asm: sub rsp, 0x30
    rsi, qword ptr [rcx + 0x10]; // mov
    // asm: movzx r15d, dl
    r14, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rsi, r14
    if (jae_condition) {
        goto loc_7FF71C11250B;
    } else {
        goto loc_7FF71C1124E2;
    }

loc_7FF71C1124E2:
    // --- Basic Block 69 (0x00007FF71C1124E2 -> 0x00007FF71C1124F0) ---
    rax, [rsi + 1]; // lea
    qword ptr [rcx + 0x10], rax; // mov
    // asm: cmp r14, 0xf
    if (jbe_condition) {
        goto loc_7FF71C1124F3;
    } else {
        goto loc_7FF71C1124F0;
    }

loc_7FF71C1124F0:
    // --- Basic Block 70 (0x00007FF71C1124F0 -> 0x00007FF71C1124F3) ---
    rbx, qword ptr [rcx]; // mov

loc_7FF71C1124F3:
    // --- Basic Block 71 (0x00007FF71C1124F3 -> 0x00007FF71C11250B) ---
    byte ptr [rsi + rbx], r15b; // mov
    byte ptr [rsi + rbx + 1], 0; // mov
    rbx, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

### Function `sub_00007FF71C112000` (0x7FF71C112000)
- **Size**: `1554 bytes` | **Complexity V(G)**: `30` | **Incoming XREFs**: `0`

```c
// ============================================================================
// KYV HEX-RAYS PSEUDOCODE DECOMPILER
// Function: sub_00007FF71C112000 | Address: 0x00007FF71C112000
// Size: 1554 bytes | Basic Blocks: 72 | Complexity V(G): 30
// Calling Convention: x64 fastcall
// ============================================================================

int64_t sub_00007FF71C112000(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)
{
    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1
    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2
    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3
    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4
    int64_t rax_result = 0;

loc_7FF71C112000:
    // --- Basic Block 0 (0x00007FF71C112000 -> 0x00007FF71C112033) ---
    // asm: sub rsp, 0x48
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C111850(); // 0x7ff71c111850
    rdx, [rip + 0x497b]; // lea
    rcx, [rsp + 0x20]; // lea
    rax_result = sub_7FF71C1140F2(); // 0x7ff71c1140f2
    // asm: int3 
    // asm: sub rsp, 0x30
    rdx, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rdx, 0xf
    if (jbe_condition) {
        goto loc_7FF71C11205F;
    } else {
        goto loc_7FF71C112033;
    }

loc_7FF71C112033:
    // --- Basic Block 1 (0x00007FF71C112033 -> 0x00007FF71C112042) ---
    rcx, qword ptr [rcx]; // mov
    // asm: inc rdx
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C11205A;
    } else {
        goto loc_7FF71C112042;
    }

loc_7FF71C112042:
    // --- Basic Block 2 (0x00007FF71C112042 -> 0x00007FF71C112057) ---
    rax, qword ptr [rcx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rcx, rax
    // asm: sub rcx, 8
    // asm: cmp rcx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112078;
    } else {
        goto loc_7FF71C112057;
    }

loc_7FF71C112057:
    // --- Basic Block 3 (0x00007FF71C112057 -> 0x00007FF71C11205A) ---
    rcx, rax; // mov

loc_7FF71C11205A:
    // --- Basic Block 4 (0x00007FF71C11205A -> 0x00007FF71C11205F) ---
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0

loc_7FF71C11205F:
    // --- Basic Block 5 (0x00007FF71C11205F -> 0x00007FF71C112078) ---
    qword ptr [rbx + 0x10], 0; // mov
    qword ptr [rbx + 0x18], 0xf; // mov
    byte ptr [rbx], 0; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C112078:
    // --- Basic Block 6 (0x00007FF71C112078 -> 0x00007FF71C1120ED) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x32ef]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    rcx, [rip + 0x34ed]; // lea
    rax_result = sub_7FF71C11322C(); // 0x7ff71c11322c
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    // asm: sub rsp, 0x30
    r15, qword ptr [rcx + 0x18]; // mov
    rsi, r8; // mov
    r14, qword ptr [rcx + 0x10]; // mov
    rax, r15; // mov
    // asm: sub rax, r14
    r13, rdx; // mov
    rdi, rcx; // mov
    // asm: cmp r8, rax
    if (ja_condition) {
        goto loc_7FF71C112116;
    } else {
        goto loc_7FF71C1120ED;
    }

loc_7FF71C1120ED:
    // --- Basic Block 7 (0x00007FF71C1120ED -> 0x00007FF71C1120FE) ---
    rax, [r14 + r8]; // lea
    qword ptr [rcx + 0x10], rax; // mov
    rax, rcx; // mov
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C112101;
    } else {
        goto loc_7FF71C1120FE;
    }

loc_7FF71C1120FE:
    // --- Basic Block 8 (0x00007FF71C1120FE -> 0x00007FF71C112101) ---
    rax, qword ptr [rcx]; // mov

loc_7FF71C112101:
    // --- Basic Block 9 (0x00007FF71C112101 -> 0x00007FF71C112116) ---
    rbx, [r14 + rax]; // lea
    rcx, rbx; // mov
    rax_result = sub_7FF71C114104(); // 0x7ff71c114104
    byte ptr [rbx + rsi], 0; // mov
    goto loc_7FF71C11221B;

loc_7FF71C112116:
    // --- Basic Block 10 (0x00007FF71C112116 -> 0x00007FF71C11212F) ---
    // asm: movabs rbx, 0x7fffffffffffffff
    rax, rbx; // mov
    // asm: sub rax, r14
    // asm: cmp rax, rsi
    if (jb_condition) {
        goto loc_7FF71C112230;
    } else {
        goto loc_7FF71C11212F;
    }

loc_7FF71C11212F:
    // --- Basic Block 11 (0x00007FF71C11212F -> 0x00007FF71C112149) ---
    qword ptr [rsp + 0x60], rbp; // mov
    qword ptr [rsp + 0x68], r12; // mov
    r12, [r14 + r8]; // lea
    rcx, r12; // mov
    // asm: or rcx, 0xf
    // asm: cmp rcx, rbx
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C112149;
    }

loc_7FF71C112149:
    // --- Basic Block 12 (0x00007FF71C112149 -> 0x00007FF71C11215A) ---
    rdx, r15; // mov
    rax, rbx; // mov
    // asm: shr rdx, 1
    // asm: sub rax, rdx
    // asm: cmp r15, rax
    if (ja_condition) {
        goto loc_7FF71C112168;
    } else {
        goto loc_7FF71C11215A;
    }

loc_7FF71C11215A:
    // --- Basic Block 13 (0x00007FF71C11215A -> 0x00007FF71C112168) ---
    rax, [r15 + rdx]; // lea
    rbx, rcx; // mov
    // asm: cmp rcx, rax
    // asm: cmovb rbx, rax

loc_7FF71C112168:
    // --- Basic Block 14 (0x00007FF71C112168 -> 0x00007FF71C11218C) ---
    rcx, [rbx + 1]; // lea
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    qword ptr [rdi + 0x10], r12; // mov
    rbp, rax; // mov
    qword ptr [rdi + 0x18], rbx; // mov
    r8, r14; // mov
    rcx, rax; // mov
    r12, [r14 + rax]; // lea
    // asm: cmp r15, 0xf
    if (jbe_condition) {
        goto loc_7FF71C1121F3;
    } else {
        goto loc_7FF71C11218C;
    }

loc_7FF71C11218C:
    // --- Basic Block 15 (0x00007FF71C11218C -> 0x00007FF71C1121B7) ---
    rbx, qword ptr [rdi]; // mov
    rdx, rbx; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    rdx, [r15 + 1]; // lea
    byte ptr [r12 + rsi], 0; // mov
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C1121CF;
    } else {
        goto loc_7FF71C1121B7;
    }

loc_7FF71C1121B7:
    // --- Basic Block 16 (0x00007FF71C1121B7 -> 0x00007FF71C1121CC) ---
    rax, qword ptr [rbx - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rbx, rax
    // asm: sub rbx, 8
    // asm: cmp rbx, 0x1f
    if (ja_condition) {
        goto loc_7FF71C1121D9;
    } else {
        goto loc_7FF71C1121CC;
    }

loc_7FF71C1121CC:
    // --- Basic Block 17 (0x00007FF71C1121CC -> 0x00007FF71C1121CF) ---
    rbx, rax; // mov

loc_7FF71C1121CF:
    // --- Basic Block 18 (0x00007FF71C1121CF -> 0x00007FF71C1121D9) ---
    rcx, rbx; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0
    goto loc_7FF71C11220E;

loc_7FF71C1121D9:
    // --- Basic Block 19 (0x00007FF71C1121D9 -> 0x00007FF71C1121F3) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x318e]);
    // asm: int3 

loc_7FF71C1121F3:
    // --- Basic Block 20 (0x00007FF71C1121F3 -> 0x00007FF71C11220E) ---
    rdx, rdi; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, rsi; // mov
    rdx, r13; // mov
    rcx, r12; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [r12 + rsi], 0; // mov

loc_7FF71C11220E:
    // --- Basic Block 21 (0x00007FF71C11220E -> 0x00007FF71C11221B) ---
    qword ptr [rdi], rbp; // mov
    rbp, qword ptr [rsp + 0x60]; // mov
    r12, qword ptr [rsp + 0x68]; // mov

loc_7FF71C11221B:
    // --- Basic Block 22 (0x00007FF71C11221B -> 0x00007FF71C112230) ---
    rbx, qword ptr [rsp + 0x70]; // mov
    rax, rdi; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C112230:
    // --- Basic Block 23 (0x00007FF71C112230 -> 0x00007FF71C112250) ---
    rax_result = sub_7FF71C1120A0(); // 0x7ff71c1120a0
    // asm: int3 
    // asm: int3 
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
    rax, rdx; // mov
    // asm: cmp r8, 0x1000
    if (jb_condition) {
        goto loc_7FF71C112268;
    } else {
        goto loc_7FF71C112250;
    }

loc_7FF71C112250:
    // --- Basic Block 24 (0x00007FF71C112250 -> 0x00007FF71C112265) ---
    rcx, qword ptr [rdx - 8]; // mov
    // asm: add r8, 0x27
    // asm: sub rax, rcx
    // asm: sub rax, 8
    // asm: cmp rax, 0x1f
    if (ja_condition) {
        goto loc_7FF71C112277;
    } else {
        goto loc_7FF71C112265;
    }

loc_7FF71C112265:
    // --- Basic Block 25 (0x00007FF71C112265 -> 0x00007FF71C112268) ---
    rax, rcx; // mov

loc_7FF71C112268:
    // --- Basic Block 26 (0x00007FF71C112268 -> 0x00007FF71C112277) ---
    rdx, r8; // mov
    rcx, rax; // mov
    // asm: add rsp, 0x38
    goto loc_7FF71C1132B0;

loc_7FF71C112277:
    // --- Basic Block 27 (0x00007FF71C112277 -> 0x00007FF71C1122C3) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x30f0]);
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    edx, 0x800; // mov
    r8d, 0xe00; // mov
    rbx, rcx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2f66]);
    rax, rbx; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1122C3:
    // --- Basic Block 28 (0x00007FF71C1122C3 -> 0x00007FF71C1122F1) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
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
    qword ptr [rsp + 0x18], rbp; // mov
    // asm: sub rsp, 0x20
    // asm: test byte ptr [rcx + 0x70], 2
    ebp, edx; // mov
    rdi, rcx; // mov
    if (jne_condition) {
        goto loc_7FF71C112414;
    } else {
        goto loc_7FF71C1122F1;
    }

loc_7FF71C1122F1:
    // --- Basic Block 29 (0x00007FF71C1122F1 -> 0x00007FF71C1122F6) ---
    // asm: cmp edx, -1
    if (jne_condition) {
        goto loc_7FF71C1122FD;
    } else {
        goto loc_7FF71C1122F6;
    }

loc_7FF71C1122F6:
    // --- Basic Block 30 (0x00007FF71C1122F6 -> 0x00007FF71C1122FD) ---
    eax = 0;
    goto loc_7FF71C112419;

loc_7FF71C1122FD:
    // --- Basic Block 31 (0x00007FF71C1122FD -> 0x00007FF71C112317) ---
    rax_result = indirect_call(qword ptr [rip + 0x2db5]);
    rcx, rdi; // mov
    rbx, rax; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2dc9]);
    rsi, rax; // mov
    // asm: test rbx, rbx
    if (je_condition) {
        goto loc_7FF71C112337;
    } else {
        goto loc_7FF71C112317;
    }

loc_7FF71C112317:
    // --- Basic Block 32 (0x00007FF71C112317 -> 0x00007FF71C11231C) ---
    // asm: cmp rbx, rax
    if (jae_condition) {
        goto loc_7FF71C112337;
    } else {
        goto loc_7FF71C11231C;
    }

loc_7FF71C11231C:
    // --- Basic Block 33 (0x00007FF71C11231C -> 0x00007FF71C112337) ---
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2dcb]);
    byte ptr [rax], bpl; // mov
    rax, [rbx + 1]; // lea
    qword ptr [rdi + 0x68], rax; // mov
    eax, ebp; // mov
    goto loc_7FF71C112419;

loc_7FF71C112337:
    // --- Basic Block 34 (0x00007FF71C112337 -> 0x00007FF71C112355) ---
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2d60]);
    // asm: sub rsi, rax
    r15, rax; // mov
    eax = 0;
    // asm: test rbx, rbx
    // asm: cmove rsi, rax
    // asm: cmp rsi, 0x20
    if (jae_condition) {
        goto loc_7FF71C11235C;
    } else {
        goto loc_7FF71C112355;
    }

loc_7FF71C112355:
    // --- Basic Block 35 (0x00007FF71C112355 -> 0x00007FF71C11235C) ---
    ebx, 0x20; // mov
    goto loc_7FF71C112379;

loc_7FF71C11235C:
    // --- Basic Block 36 (0x00007FF71C11235C -> 0x00007FF71C112365) ---
    // asm: cmp rsi, 0x3fffffff
    if (jae_condition) {
        goto loc_7FF71C11236B;
    } else {
        goto loc_7FF71C112365;
    }

loc_7FF71C112365:
    // --- Basic Block 37 (0x00007FF71C112365 -> 0x00007FF71C11236B) ---
    rbx, [rsi + rsi]; // lea
    goto loc_7FF71C112379;

loc_7FF71C11236B:
    // --- Basic Block 38 (0x00007FF71C11236B -> 0x00007FF71C112379) ---
    ebx, 0x7fffffff; // mov
    // asm: cmp rsi, rbx
    if (jae_condition) {
        goto loc_7FF71C112414;
    } else {
        goto loc_7FF71C112379;
    }

loc_7FF71C112379:
    // --- Basic Block 39 (0x00007FF71C112379 -> 0x00007FF71C1123BC) ---
    rcx, rbx; // mov
    qword ptr [rsp + 0x40], r14; // mov
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    r8, rsi; // mov
    rdx, r15; // mov
    rcx, rax; // mov
    r14, rax; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    r8, [rsi + r14]; // lea
    rdx, r14; // mov
    rcx, [r8 + 1]; // lea
    qword ptr [rdi + 0x68], rcx; // mov
    r9, [r14 + rbx]; // lea
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2d35]);
    // asm: test byte ptr [rdi + 0x70], 4
    rcx, rdi; // mov
    if (je_condition) {
        goto loc_7FF71C1123C4;
    } else {
        goto loc_7FF71C1123BC;
    }

loc_7FF71C1123BC:
    // --- Basic Block 40 (0x00007FF71C1123BC -> 0x00007FF71C1123C4) ---
    r9, r14; // mov
    r8, r14; // mov
    goto loc_7FF71C1123DD;

loc_7FF71C1123C4:
    // --- Basic Block 41 (0x00007FF71C1123C4 -> 0x00007FF71C1123DD) ---
    rbx, qword ptr [rdi + 0x68]; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2cda]);
    r8, r14; // mov
    r9, rbx; // mov
    // asm: sub r8, r15
    rcx, rdi; // mov
    // asm: add r8, rax

loc_7FF71C1123DD:
    // --- Basic Block 42 (0x00007FF71C1123DD -> 0x00007FF71C1123F1) ---
    rdx, r14; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2cea]);
    // asm: test byte ptr [rdi + 0x70], 1
    r14, qword ptr [rsp + 0x40]; // mov
    if (je_condition) {
        goto loc_7FF71C112400;
    } else {
        goto loc_7FF71C1123F1;
    }

loc_7FF71C1123F1:
    // --- Basic Block 43 (0x00007FF71C1123F1 -> 0x00007FF71C112400) ---
    rcx, [rdi + 0x74]; // lea
    r8, rsi; // mov
    rdx, r15; // mov
    rax_result = sub_7FF71C112240(); // 0x7ff71c112240

loc_7FF71C112400:
    // --- Basic Block 44 (0x00007FF71C112400 -> 0x00007FF71C112414) ---
    // asm: or dword ptr [rdi + 0x70], 1
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2ce3]);
    byte ptr [rax], bpl; // mov
    eax, ebp; // mov
    goto loc_7FF71C112419;

loc_7FF71C112414:
    // --- Basic Block 45 (0x00007FF71C112414 -> 0x00007FF71C112419) ---
    eax, 0xffffffff; // mov

loc_7FF71C112419:
    // --- Basic Block 46 (0x00007FF71C112419 -> 0x00007FF71C11242C) ---
    rbx, qword ptr [rsp + 0x48]; // mov
    rbp, qword ptr [rsp + 0x50]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C11242C:
    // --- Basic Block 47 (0x00007FF71C11242C -> 0x00007FF71C112452) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 8], rbx; // mov
    qword ptr [rsp + 0x10], rsi; // mov
    // asm: sub rsp, 0x20
    ebx, edx; // mov
    rdi, rcx; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2c5e]);
    rsi, rax; // mov
    // asm: test rax, rax
    if (je_condition) {
        goto loc_7FF71C1124A8;
    } else {
        goto loc_7FF71C112452;
    }

loc_7FF71C112452:
    // --- Basic Block 48 (0x00007FF71C112452 -> 0x00007FF71C112460) ---
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2c45]);
    // asm: cmp rsi, rax
    if (jbe_condition) {
        goto loc_7FF71C1124A8;
    } else {
        goto loc_7FF71C112460;
    }

loc_7FF71C112460:
    // --- Basic Block 49 (0x00007FF71C112460 -> 0x00007FF71C112465) ---
    // asm: cmp ebx, -1
    if (je_condition) {
        goto loc_7FF71C112470;
    } else {
        goto loc_7FF71C112465;
    }

loc_7FF71C112465:
    // --- Basic Block 50 (0x00007FF71C112465 -> 0x00007FF71C11246A) ---
    // asm: cmp bl, byte ptr [rsi - 1]
    if (je_condition) {
        goto loc_7FF71C112470;
    } else {
        goto loc_7FF71C11246A;
    }

loc_7FF71C11246A:
    // --- Basic Block 51 (0x00007FF71C11246A -> 0x00007FF71C112470) ---
    // asm: test byte ptr [rdi + 0x70], 2
    if (jne_condition) {
        goto loc_7FF71C1124A8;
    } else {
        goto loc_7FF71C112470;
    }

loc_7FF71C112470:
    // --- Basic Block 52 (0x00007FF71C112470 -> 0x00007FF71C112483) ---
    edx, 0xffffffff; // mov
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2c4a]);
    // asm: cmp ebx, -1
    if (je_condition) {
        goto loc_7FF71C11248E;
    } else {
        goto loc_7FF71C112483;
    }

loc_7FF71C112483:
    // --- Basic Block 53 (0x00007FF71C112483 -> 0x00007FF71C11248E) ---
    rcx, rdi; // mov
    rax_result = indirect_call(qword ptr [rip + 0x2c1c]);
    byte ptr [rax], bl; // mov

loc_7FF71C11248E:
    // --- Basic Block 54 (0x00007FF71C11248E -> 0x00007FF71C1124A8) ---
    eax = 0;
    // asm: cmp ebx, -1
    // asm: cmove ebx, eax
    eax, ebx; // mov
    rbx, qword ptr [rsp + 0x30]; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1124A8:
    // --- Basic Block 55 (0x00007FF71C1124A8 -> 0x00007FF71C1124BD) ---
    rbx, qword ptr [rsp + 0x30]; // mov
    eax, 0xffffffff; // mov
    rsi, qword ptr [rsp + 0x38]; // mov
    // asm: add rsp, 0x20
    return rax_result;

loc_7FF71C1124BD:
    // --- Basic Block 56 (0x00007FF71C1124BD -> 0x00007FF71C1124E2) ---
    // asm: int3 
    // asm: int3 
    // asm: int3 
    qword ptr [rsp + 0x20], rbx; // mov
    // asm: sub rsp, 0x30
    rsi, qword ptr [rcx + 0x10]; // mov
    // asm: movzx r15d, dl
    r14, qword ptr [rcx + 0x18]; // mov
    rbx, rcx; // mov
    // asm: cmp rsi, r14
    if (jae_condition) {
        goto loc_7FF71C11250B;
    } else {
        goto loc_7FF71C1124E2;
    }

loc_7FF71C1124E2:
    // --- Basic Block 57 (0x00007FF71C1124E2 -> 0x00007FF71C1124F0) ---
    rax, [rsi + 1]; // lea
    qword ptr [rcx + 0x10], rax; // mov
    // asm: cmp r14, 0xf
    if (jbe_condition) {
        goto loc_7FF71C1124F3;
    } else {
        goto loc_7FF71C1124F0;
    }

loc_7FF71C1124F0:
    // --- Basic Block 58 (0x00007FF71C1124F0 -> 0x00007FF71C1124F3) ---
    rbx, qword ptr [rcx]; // mov

loc_7FF71C1124F3:
    // --- Basic Block 59 (0x00007FF71C1124F3 -> 0x00007FF71C11250B) ---
    byte ptr [rsi + rbx], r15b; // mov
    byte ptr [rsi + rbx + 1], 0; // mov
    rbx, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

loc_7FF71C11250B:
    // --- Basic Block 60 (0x00007FF71C11250B -> 0x00007FF71C11252A) ---
    qword ptr [rsp + 0x58], rdi; // mov
    // asm: movabs rdi, 0x7fffffffffffffff
    rax, rdi; // mov
    // asm: sub rax, rsi
    // asm: cmp rax, 1
    if (jb_condition) {
        goto loc_7FF71C112612;
    } else {
        goto loc_7FF71C11252A;
    }

loc_7FF71C11252A:
    // --- Basic Block 61 (0x00007FF71C11252A -> 0x00007FF71C112544) ---
    qword ptr [rsp + 0x50], rbp; // mov
    qword ptr [rsp + 0x60], r12; // mov
    r12, [rsi + 1]; // lea
    rcx, r12; // mov
    // asm: or rcx, 0xf
    // asm: cmp rcx, rdi
    if (ja_condition) {
        goto loc_7FF71C112563;
    } else {
        goto loc_7FF71C112544;
    }

loc_7FF71C112544:
    // --- Basic Block 62 (0x00007FF71C112544 -> 0x00007FF71C112555) ---
    rdx, r14; // mov
    rax, rdi; // mov
    // asm: shr rdx, 1
    // asm: sub rax, rdx
    // asm: cmp r14, rax
    if (ja_condition) {
        goto loc_7FF71C112563;
    } else {
        goto loc_7FF71C112555;
    }

loc_7FF71C112555:
    // --- Basic Block 63 (0x00007FF71C112555 -> 0x00007FF71C112563) ---
    rax, [r14 + rdx]; // lea
    rdi, rcx; // mov
    // asm: cmp rcx, rax
    // asm: cmovb rdi, rax

loc_7FF71C112563:
    // --- Basic Block 64 (0x00007FF71C112563 -> 0x00007FF71C112588) ---
    rcx, [rdi + 1]; // lea
    rax_result = sub_7FF71C111270(); // 0x7ff71c111270
    qword ptr [rbx + 0x10], r12; // mov
    rbp, rax; // mov
    r12, qword ptr [rsp + 0x60]; // mov
    r8, rsi; // mov
    qword ptr [rbx + 0x18], rdi; // mov
    rcx, rax; // mov
    // asm: cmp r14, 0xf
    if (jbe_condition) {
        goto loc_7FF71C1125E5;
    } else {
        goto loc_7FF71C112588;
    }

loc_7FF71C112588:
    // --- Basic Block 65 (0x00007FF71C112588 -> 0x00007FF71C1125A9) ---
    rdi, qword ptr [rbx]; // mov
    rdx, rdi; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    rdx, [r14 + 1]; // lea
    byte ptr [rsi + rbp], r15b; // mov
    byte ptr [rsi + rbp + 1], 0; // mov
    // asm: cmp rdx, 0x1000
    if (jb_condition) {
        goto loc_7FF71C1125C1;
    } else {
        goto loc_7FF71C1125A9;
    }

loc_7FF71C1125A9:
    // --- Basic Block 66 (0x00007FF71C1125A9 -> 0x00007FF71C1125BE) ---
    rax, qword ptr [rdi - 8]; // mov
    // asm: add rdx, 0x27
    // asm: sub rdi, rax
    // asm: sub rdi, 8
    // asm: cmp rdi, 0x1f
    if (ja_condition) {
        goto loc_7FF71C1125CB;
    } else {
        goto loc_7FF71C1125BE;
    }

loc_7FF71C1125BE:
    // --- Basic Block 67 (0x00007FF71C1125BE -> 0x00007FF71C1125C1) ---
    rdi, rax; // mov

loc_7FF71C1125C1:
    // --- Basic Block 68 (0x00007FF71C1125C1 -> 0x00007FF71C1125CB) ---
    rcx, rdi; // mov
    rax_result = sub_7FF71C1132B0(); // 0x7ff71c1132b0
    goto loc_7FF71C1125F6;

loc_7FF71C1125CB:
    // --- Basic Block 69 (0x00007FF71C1125CB -> 0x00007FF71C1125E5) ---
    r9d = 0;
    qword ptr [rsp + 0x20], 0; // mov
    r8d = 0;
    edx = 0;
    ecx = 0;
    rax_result = indirect_call(qword ptr [rip + 0x2d9c]);
    // asm: int3 

loc_7FF71C1125E5:
    // --- Basic Block 70 (0x00007FF71C1125E5 -> 0x00007FF71C1125F6) ---
    rdx, rbx; // mov
    rax_result = sub_7FF71C1140FE(); // 0x7ff71c1140fe
    byte ptr [rsi + rbp], r15b; // mov
    byte ptr [rsi + rbp + 1], 0; // mov

loc_7FF71C1125F6:
    // --- Basic Block 71 (0x00007FF71C1125F6 -> 0x00007FF71C112612) ---
    rdi, qword ptr [rsp + 0x58]; // mov
    qword ptr [rbx], rbp; // mov
    rbp, qword ptr [rsp + 0x50]; // mov
    rbx, qword ptr [rsp + 0x68]; // mov
    // asm: add rsp, 0x30
    return rax_result;

}
```

