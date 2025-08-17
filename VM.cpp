#include "VM.h"
#include <windows.h>
#include <iostream>
#include <cassert>
#include <numeric>

// Constructor: Set up the handler map
VM::VM() {
    initialize_handlers();
}

// Maps each opcode's dispatch key to its handler function
void VM::initialize_handlers() {
    auto bind_handler = [this](auto handler_func) {
        return [this, handler_func]() { (this->*handler_func)(); };
        };

    opcode_handlers[(VM_PUSH * 17 + 3) % 50] = bind_handler(&VM::handle_push);
    opcode_handlers[(VM_POP * 17 + 3) % 50] = bind_handler(&VM::handle_pop);
    opcode_handlers[(VM_ADD * 17 + 3) % 50] = bind_handler(&VM::handle_add);
    opcode_handlers[(VM_RET * 17 + 3) % 50] = bind_handler(&VM::handle_ret);
    opcode_handlers[(VM_CALL_EXTERNAL * 17 + 3) % 50] = bind_handler(&VM::handle_call_external);
    opcode_handlers[(VM_CMP * 17 + 3) % 50] = bind_handler(&VM::handle_cmp);
    opcode_handlers[(VM_JUMP_IF_EQUAL * 17 + 3) % 50] = bind_handler(&VM::handle_jump_if_equal);
    opcode_handlers[(VM_SUB * 17 + 3) % 50] = bind_handler(&VM::handle_sub);
    opcode_handlers[(VM_PUSH_JUNK * 17 + 3) % 50] = bind_handler(&VM::handle_push_junk);
    opcode_handlers[(VM_XOR * 17 + 3) % 50] = bind_handler(&VM::handle_xor);
    opcode_handlers[(VM_MUTATE * 17 + 3) % 50] = bind_handler(&VM::handle_mutate);
    opcode_handlers[(VM_TIMING_CHECK * 17 + 3) % 50] = bind_handler(&VM::handle_timing_check);
    opcode_handlers[(VM_CHECKSUM_CHECK * 17 + 3) % 50] = bind_handler(&VM::handle_checksum_check);
    opcode_handlers[(VM_CHECKSUM_PUSH * 17 + 3) % 50] = bind_handler(&VM::handle_checksum_push);
    opcode_handlers[(VM_ROTL * 17 + 3) % 50] = bind_handler(&VM::handle_rotl);
}

void VM::load_bytecode(const std::vector<int>& code) {
    this->bytecode = code;
}

// this shit is so obf like bro :sob:

void VM::run() {
    start_time = std::chrono::steady_clock::now();
    is_running = true;

    while (is_running) {
        if (integrity_failed) {
            std::cerr << "Integrity failure detected. Halting." << std::endl;
            return;
        }

        if (instruction_pointer >= bytecode.size()) {
            is_running = false;
            break;
        }

        int opcode = bytecode[instruction_pointer++];
        int dispatch_key = (opcode * 17 + 3) % 50;

        if (opcode_handlers.count(dispatch_key)) {
            opcode_handlers[dispatch_key]();
        }
        else {
            handle_unknown();
        }
    }
}

// --- Individual Handler Functions ---
void VM::handle_push() {
    int v = bytecode[instruction_pointer++];
    stack.push_back(v);
}

void VM::handle_pop() {
    if (!stack.empty()) stack.pop_back();
}

void VM::handle_add() {
    if (bytecode[0] != VM_PUSH_JUNK && bytecode[0] != VM_PUSH) integrity_failed = true;
    int b = stack.back(); stack.pop_back();
    int a = stack.back(); stack.pop_back();
    stack.push_back(a + b);
}

void VM::handle_ret() { is_running = false; }

void VM::handle_call_external() {
    int id = bytecode[instruction_pointer++];
    if (external_calls.count(id)) external_calls[id]();
}

void VM::handle_cmp() {
    int b = stack.back(); stack.pop_back();
    int a = stack.back(); stack.pop_back();
    stack.push_back(a == b ? 1 : 0);
}

void VM::handle_jump_if_equal() {
    int cond = stack.back(); stack.pop_back();
    int addr = bytecode[instruction_pointer++];
    if (cond == 1 && !integrity_failed)
        instruction_pointer = addr;
}

void VM::handle_sub() {
    int b = stack.back(); stack.pop_back();
    int a = stack.back(); stack.pop_back();
    stack.push_back(a - b);
}

void VM::handle_push_junk() { instruction_pointer++; }

void VM::handle_xor() {
    int b = stack.back(); stack.pop_back();
    int a = stack.back(); stack.pop_back();
    stack.push_back(a ^ b);
}

void VM::handle_mutate() {
    int addr = bytecode[instruction_pointer++];
    int val = bytecode[instruction_pointer++];
    if (addr < bytecode.size()) bytecode[addr] = val;
}

void VM::handle_timing_check() {
    if (std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start_time).count() > 2) {
        MessageBoxA(NULL, "Debugger Detected! (Timing Anomaly)", "Security Alert", MB_OK | MB_ICONERROR);
        integrity_failed = true;
    }
}

void VM::handle_checksum_check() {
    int start = bytecode[instruction_pointer++];
    int len = bytecode[instruction_pointer++];
    int expected = bytecode[instruction_pointer++];
    int actual = std::accumulate(bytecode.begin() + start, bytecode.begin() + start + len, 0, std::bit_xor<int>());
    if (actual != expected) {
        MessageBoxA(NULL, "Tampering Detected! (Checksum Mismatch)", "Security Alert", MB_OK | MB_ICONERROR);
        integrity_failed = true;
    }
}

void VM::handle_checksum_push() {
    int start = bytecode[instruction_pointer++];
    int len = bytecode[instruction_pointer++];
    int actual = std::accumulate(bytecode.begin() + start,
        bytecode.begin() + start + len,
        0, std::bit_xor<int>());
    stack.push_back(actual);
}

void VM::handle_rotl() {
    int bits = bytecode[instruction_pointer++];
    int v = stack.back(); stack.pop_back();
    unsigned int u = static_cast<unsigned int>(v);
    unsigned int rot = (u << bits) | (u >> (32 - bits));
    stack.push_back(static_cast<int>(rot));
}

void VM::handle_unknown() {
    std::cerr << "Unknown opcode." << std::endl;
    is_running = false;
}

void VM::register_external_call(int id, std::function<void()> func) {
    external_calls[id] = func;
}

int VM::get_result() {
    if (!stack.empty()) return stack.back();
    return 0;
}
