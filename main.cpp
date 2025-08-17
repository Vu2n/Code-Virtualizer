#include "VM.h"
#include <iostream>
#include <windows.h>
#include <functional>
#include <cstdlib>
#include <numeric>
#include <vector>
#include <random>
#include <ctime>

int calculate_checksum(const std::vector<int>& data) {
    return std::accumulate(data.begin(), data.end(), 0, std::bit_xor<int>());
}

int main() {
    VM my_vm;

    std::mt19937 rng(static_cast<uint32_t>(GetTickCount()) ^ static_cast<uint32_t>(time(nullptr)));
    std::uniform_int_distribution<int> dist(1, 0x7fffffff);
    int authSuccessId = dist(rng);
    int authFailureId = authSuccessId ^ 0x5A5A5A5A; 

    my_vm.register_external_call(authSuccessId, []() { MessageBoxA(NULL, "Auth Successful!", "Login", MB_OK); });
    my_vm.register_external_call(authFailureId, []() { MessageBoxA(NULL, "Auth Failed.", "Login", MB_OK); });

    int user_input;
    std::cout << "Enter the authentication key: ";
    std::cin >> user_input;
    std::cin.ignore();

    // --- Build bytecode with light obfuscation ---
    std::vector<int> bytecode;
    auto add_instruction = [&](const std::vector<int>& instr) {
        int instr_addr = static_cast<int>(bytecode.size());
        bytecode.insert(bytecode.end(), instr.begin(), instr.end());
        // Self-mutate + junk to keep static analysis noisy
        bytecode.insert(bytecode.end(), { VM_MUTATE, instr_addr, VM_PUSH_JUNK });
        };

    // Stack plan:
    //   1) Push U
    //   2) Push C1 = checksum(start,len) over "critical section"
    //   3) Push C2 = checksum(start2,len2) over a sub-window of the same section
    //   4) T0 = C1 ^ C2
    //   5) T  = rotl(T0, 5)
    //   6) CMP(U, T) -> 1 if equal
    //   7) JUMP_IF_EQUAL -> success; else failure

    // 1) U
    add_instruction({ VM_PUSH, user_input });

    int checksum_check_instr_addr = static_cast<int>(bytecode.size());
    bytecode.insert(bytecode.end(), { VM_CHECKSUM_CHECK, 0, 0, 0 });
    bytecode.insert(bytecode.end(), { VM_MUTATE, checksum_check_instr_addr, VM_PUSH_JUNK });

    // --- Begin critical section we will hash/derive from ---
    int critical_section_start_addr = static_cast<int>(bytecode.size());

    // 2) C1 = checksum over the whole critical section (start,len patched later)
    int c1_instr_addr = static_cast<int>(bytecode.size());
    bytecode.insert(bytecode.end(), { VM_CHECKSUM_PUSH, 0, 0 });
    bytecode.insert(bytecode.end(), { VM_MUTATE, c1_instr_addr, VM_PUSH_JUNK });

    // 3) C2 = checksum over a subrange (will be start+offset, len/2). Patched later.
    int c2_instr_addr = static_cast<int>(bytecode.size());
    bytecode.insert(bytecode.end(), { VM_CHECKSUM_PUSH, 0, 0 });
    bytecode.insert(bytecode.end(), { VM_MUTATE, c2_instr_addr, VM_PUSH_JUNK });

    // 4) T0 = C1 ^ C2
    add_instruction({ VM_XOR });

    // 5) T = rotl(T0, 5)
    add_instruction({ VM_ROTL, 5 });

    // 6) CMP(U, T)
    add_instruction({ VM_CMP });

    // 7) Conditional branch
    int jump_instr_addr = static_cast<int>(bytecode.size());
    add_instruction({ VM_JUMP_IF_EQUAL, 0 /* patched to success addr */ });

    // --- End critical section (everything from start to here participates in derivation) ---
    int critical_section_len = static_cast<int>(bytecode.size()) - critical_section_start_addr;

    // --- Failure branch ---
    int failure_branch_addr = static_cast<int>(bytecode.size());
    // We mutate the immediate for CALL_EXTERNAL *after* we registered, to avoid stable constants.
    int call_fail_addr = static_cast<int>(bytecode.size());
    add_instruction({ VM_CALL_EXTERNAL, authFailureId });
    // Mild misdirection: flip the immediate to the success ID after it's used elsewhere
    add_instruction({ VM_MUTATE, call_fail_addr + 1, authSuccessId });
    add_instruction({ VM_TIMING_CHECK }); // still useful to break naive pauses
    bytecode.push_back(VM_RET);

    // --- Success branch ---
    int success_branch_addr = static_cast<int>(bytecode.size());
    int call_succ_addr = static_cast<int>(bytecode.size());
    add_instruction({ VM_CALL_EXTERNAL, authSuccessId });
    // Flip to failure ID post-use just to add noise
    add_instruction({ VM_MUTATE, call_succ_addr + 1, authFailureId });
    add_instruction({ VM_TIMING_CHECK });
    bytecode.push_back(VM_RET);

    // Patch the jump target to success
    bytecode[jump_instr_addr + 1] = success_branch_addr;

    // --- Patch operands for CHECKSUM_PUSH (C1, C2) and CHECKSUM_CHECK ---

    // For C1: full critical section
    bytecode[c1_instr_addr + 1] = critical_section_start_addr;
    bytecode[c1_instr_addr + 2] = critical_section_len;

    // For C2: subrange — pick a stable offset/len based on current bytecode size (static per build)
    // Use the middle half of the critical section to diversify the checksum source.
    int sub_off = critical_section_len / 4;
    int sub_len = critical_section_len / 2;
    if (sub_len <= 0) { sub_off = 0; sub_len = critical_section_len; }
    bytecode[c2_instr_addr + 1] = critical_section_start_addr + sub_off;
    bytecode[c2_instr_addr + 2] = sub_len;

    // Integrity check over the same critical section (expected value computed host-side)
    std::vector<int> crit_section_data(bytecode.begin() + critical_section_start_addr,
        bytecode.begin() + critical_section_start_addr + critical_section_len);
    int expected_checksum = calculate_checksum(crit_section_data);
    bytecode[checksum_check_instr_addr + 1] = critical_section_start_addr;
    bytecode[checksum_check_instr_addr + 2] = critical_section_len;
    bytecode[checksum_check_instr_addr + 3] = expected_checksum;

    // --- Run ---
    my_vm.load_bytecode(bytecode);
    std::cout << "Running authentication logic..." << std::endl;
    my_vm.run();

    std::cin.get();
    return 0;
}
