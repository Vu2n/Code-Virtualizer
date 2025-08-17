#ifndef VM_H
#define VM_H

#include <vector>
#include <map>
#include <iostream>
#include <functional>
#include <chrono>

enum VMOpcodes {
    VM_PUSH, VM_POP, VM_ADD, VM_RET, VM_CALL_EXTERNAL, VM_CMP,
    VM_JUMP_IF_EQUAL, VM_SUB, VM_PUSH_JUNK, VM_XOR, VM_MUTATE,
    VM_TIMING_CHECK, VM_CHECKSUM_CHECK,
    VM_CHECKSUM_PUSH,    // NEW: pushes checksum(start,len) onto stack
    VM_ROTL              // NEW: rotate-left
};

class VM {
public:
    VM(); // Constructor to initialize handlers
    void load_bytecode(const std::vector<int>& code);
    void run();
    int get_result();
    void register_external_call(int id, std::function<void()> func);

    std::vector<int> bytecode;

private:
    std::vector<int> stack;
    int instruction_pointer = 0;
    std::map<int, std::function<void()>> external_calls;

    // --- State and Anti-Analysis ---
    std::chrono::steady_clock::time_point start_time;
    bool integrity_failed = false;
    bool is_running = false;

    // --- Handler Infrastructure ---
    std::map<int, std::function<void()>> opcode_handlers;
    void initialize_handlers();

    // --- Opcode Handler Functions ---
    void handle_push();
    void handle_pop();
    void handle_add();
    void handle_ret();
    void handle_call_external();
    void handle_cmp();
    void handle_jump_if_equal();
    void handle_sub();
    void handle_push_junk();
    void handle_xor();
    void handle_mutate();
    void handle_timing_check();
    void handle_checksum_check();
    void handle_checksum_push(); // NEW
    void handle_rotl();          // NEW
    void handle_unknown();
};

#endif // VM_H
