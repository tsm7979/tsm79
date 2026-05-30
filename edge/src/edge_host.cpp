// TSM Edge Compute Host — Layer 4 of the polyglot stack ("C++ + WebAssembly").
//
// A C++ host that runs untrusted, multi-tenant WebAssembly "workers" inside a
// wasmtime sandbox — the Cloudflare/Fastly Compute@Edge model. Each invocation
// is bounded by CPU *fuel* and isolated linear memory, so customer policy code
// (written in ANY language that targets Wasm) cannot escape or hang the host.
// The worker returns an edge verdict (allow/block/redact) for a request.
//
// Build: see edge/CMakeLists.txt (links the wasmtime C API).
// Run:   ./edge_host path/to/worker.wasm

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <thread>
#include <chrono>
#include <wasm.h>
#include <wasmtime.h>

namespace {

constexpr uint64_t kFuelBudget = 2'000'000;

[[noreturn]] void die(const char* msg, wasmtime_error_t* err, wasm_trap_t* trap) {
    fprintf(stderr, "[edge] FATAL: %s\n", msg);
    wasm_byte_vec_t out{};
    if (err) { wasmtime_error_message(err, &out); wasmtime_error_delete(err); }
    else if (trap) { wasm_trap_message(trap, &out); wasm_trap_delete(trap); }
    if (out.data) { fprintf(stderr, "[edge]   %.*s\n", (int)out.size, out.data); wasm_byte_vec_delete(&out); }
    exit(1);
}

std::vector<uint8_t> read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[edge] cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(n > 0 ? (size_t)n : 0);
    if (n > 0 && fread(buf.data(), 1, (size_t)n, f) != (size_t)n) { fclose(f); exit(1); }
    fclose(f);
    return buf;
}

// Host capability: tsm.log(ptr,len) — the worker's only window to the outside.
// In a real platform this is where KV/cache/fetch/metrics host calls live; the
// sandbox grants the worker nothing it isn't explicitly handed here.
wasm_trap_t* host_log(void*, wasmtime_caller_t* caller,
                      const wasmtime_val_t* args, size_t nargs,
                      wasmtime_val_t*, size_t) {
    if (nargs < 2) return nullptr;
    int32_t ptr = args[0].of.i32;
    int32_t len = args[1].of.i32;
    wasmtime_extern_t mem_ext;
    if (wasmtime_caller_export_get(caller, "memory", 6, &mem_ext) &&
        mem_ext.kind == WASMTIME_EXTERN_MEMORY) {
        wasmtime_context_t* ctx = wasmtime_caller_context(caller);
        uint8_t* data = wasmtime_memory_data(ctx, &mem_ext.of.memory);
        size_t size = wasmtime_memory_data_size(ctx, &mem_ext.of.memory);
        if (ptr >= 0 && len >= 0 && (size_t)ptr + (size_t)len <= size)
            fprintf(stdout, "[edge]   worker.log: \"%.*s\"\n", len, (const char*)(data + ptr));
    }
    return nullptr;
}

} // namespace

int main(int argc, char** argv) {
    const char* wasm_path = (argc > 1) ? argv[1] : "worker.wasm";

    // ── Engine with fuel metering (bounds each worker's CPU) ───────────────
    wasm_config_t* config = wasm_config_new();
    wasmtime_config_consume_fuel_set(config, true);
    wasmtime_config_epoch_interruption_set(config, true);   // wall-clock deadline
    wasm_engine_t* engine = wasm_engine_new_with_config(config);

    // Epoch ticker: bumps the engine epoch every 100ms so a worker that runs
    // past its epoch deadline traps (defends against a worker that blocks/spins
    // without burning fuel — belt-and-suspenders alongside the fuel budget).
    std::thread([engine] {
        for (;;) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            wasmtime_engine_increment_epoch(engine);
        }
    }).detach();

    std::vector<uint8_t> wasm = read_file(wasm_path);
    wasmtime_module_t* module = nullptr;
    if (wasmtime_error_t* e = wasmtime_module_new(engine, wasm.data(), wasm.size(), &module))
        die("module compile failed", e, nullptr);
    fprintf(stdout, "[edge] loaded worker: %s (%zu bytes)\n", wasm_path, wasm.size());

    // ── Linker: publish the host capability surface (tsm.log) ──────────────
    wasmtime_linker_t* linker = wasmtime_linker_new(engine);
    {
        wasm_valtype_t* ps[2] = { wasm_valtype_new(WASM_I32), wasm_valtype_new(WASM_I32) };
        wasm_valtype_vec_t params, results;
        wasm_valtype_vec_new(&params, 2, ps);
        wasm_valtype_vec_new_empty(&results);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);
        if (wasmtime_error_t* e = wasmtime_linker_define_func(
                linker, "tsm", 3, "log", 3, ty, host_log, nullptr, nullptr))
            die("define tsm.log failed", e, nullptr);
        wasm_functype_delete(ty);
    }

    struct Req { const char* label; const char* path; };
    const Req reqs[] = {
        {"clean",  "GET /v1/chat/completions"},
        {"admin",  "GET /admin/users"},
        {"secret", "POST /v1/keys?token=sk-abc123"},
        {"git",    "GET /.git/config"},
    };
    const char* verdicts[] = {"ALLOW", "BLOCK", "REDACT"};

    int processed = 0;
    for (const auto& r : reqs) {
        // Fresh store per request → strict isolation between invocations.
        wasmtime_store_t* store = wasmtime_store_new(engine, nullptr, nullptr);
        wasmtime_context_t* ctx = wasmtime_store_context(store);
        // Multi-tenant resource caps: 16 MiB memory, 1 instance, 1 memory per worker.
        wasmtime_store_limiter(store, 16 * 1024 * 1024, -1, 1, -1, 1);
        if (wasmtime_error_t* e = wasmtime_context_set_fuel(ctx, kFuelBudget))
            die("set_fuel failed", e, nullptr);
        wasmtime_context_set_epoch_deadline(ctx, 5);   // ~500ms wall-clock budget

        wasmtime_instance_t instance;
        wasm_trap_t* trap = nullptr;
        if (wasmtime_error_t* e = wasmtime_linker_instantiate(linker, ctx, module, &instance, &trap))
            die("instantiate failed", e, trap);
        if (trap) die("instantiate trapped", nullptr, trap);

        auto get = [&](const char* name) -> wasmtime_extern_t {
            wasmtime_extern_t ext;
            if (!wasmtime_instance_export_get(ctx, &instance, name, strlen(name), &ext)) {
                fprintf(stderr, "[edge] worker missing export: %s\n", name);
                exit(1);
            }
            return ext;
        };

        wasmtime_extern_t mem_ext   = get("memory");
        wasmtime_extern_t iptr_ext  = get("input_ptr");
        wasmtime_extern_t onreq_ext = get("on_request");

        // input_ptr() -> i32  (address of the worker's request buffer)
        wasmtime_val_t res{};
        if (wasmtime_error_t* e = wasmtime_func_call(ctx, &iptr_ext.of.func, nullptr, 0, &res, 1, &trap))
            die("input_ptr() failed", e, trap);
        if (trap) die("input_ptr() trapped", nullptr, trap);
        int32_t in_off = res.of.i32;

        // Write the request into the worker's linear memory.
        uint8_t* mem = wasmtime_memory_data(ctx, &mem_ext.of.memory);
        size_t mem_size = wasmtime_memory_data_size(ctx, &mem_ext.of.memory);
        size_t plen = strlen(r.path);
        if ((size_t)in_off + plen > mem_size) { fprintf(stderr, "[edge] request too large\n"); exit(1); }
        memcpy(mem + in_off, r.path, plen);

        // on_request(len) -> i32 verdict
        wasmtime_val_t arg{}; arg.kind = WASMTIME_I32; arg.of.i32 = (int32_t)plen;
        wasmtime_val_t vres{};
        wasmtime_error_t* e = wasmtime_func_call(ctx, &onreq_ext.of.func, &arg, 1, &vres, 1, &trap);
        if (e || trap) {
            // Fail-closed: a trap (fuel exhaustion, panic, OOB) means BLOCK.
            fprintf(stdout, "[edge] %-7s %-34s -> BLOCK (worker trapped — fail-closed)\n", r.label, r.path);
            if (e) wasmtime_error_delete(e);
            if (trap) wasm_trap_delete(trap);
            wasmtime_store_delete(store);
            processed++;
            continue;
        }
        int v = vres.of.i32;
        uint64_t fuel_left = 0;
        wasmtime_context_get_fuel(ctx, &fuel_left);
        fprintf(stdout, "[edge] %-7s %-34s -> %-6s (fuel used: %llu)\n",
                r.label, r.path, (v >= 0 && v < 3) ? verdicts[v] : "?",
                (unsigned long long)(kFuelBudget - fuel_left));

        wasmtime_store_delete(store);
        processed++;
    }

    wasmtime_linker_delete(linker);
    wasmtime_module_delete(module);
    wasm_engine_delete(engine);
    fprintf(stdout, "[edge] ran %d workers in the wasmtime sandbox — OK\n", processed);
    return 0;
}
