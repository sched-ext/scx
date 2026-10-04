#!/usr/bin/env python3
"""Bounded, fail-closed BPF-to-x86 model for the five straight-line probes.

Not a kernel JIT implementation or a verifier. Uses the inspected x86 register
mapping/BMI2 shift strategy and substitutes POPCNT for the hypothetical scalar
kfunc. Models fastcall save removal separately. No BPF is loaded.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import random
import re
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
OUT = ROOT / "target/cake_register_pressure_20261001"
OUT.mkdir(exist_ok=True)
COMMANDS = []
REG64 = ["rax", "rdi", "rsi", "rdx", "rcx", "r8", "rbx", "r13", "r14", "r15", "rbp"]
REG32 = ["eax", "edi", "esi", "edx", "ecx", "r8d", "ebx", "r13d", "r14d", "r15d", "ebp"]


def run(args, name):
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True, cwd=ROOT)
    (OUT / name).write_text(p.stdout)
    (OUT / (name + ".stderr")).write_text(p.stderr)
    COMMANDS.append({"argv": [str(x) for x in args], "exit_code": p.returncode})
    if p.returncode:
        raise RuntimeError(p.stderr)
    return p.stdout


def reg(s):
    return (REG32 if s[0] == "w" else REG64)[int(s[1:])]


def parse(text):
    result, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if m:
            cur = m[1]
            result[cur] = []
        m = re.match(r"^\s*\d+:\s+(\S.*)$", line)
        if cur and m and not m[1].startswith("R_BPF_"):
            result[cur].append(m[1])
    return result


def lower(insns):
    result = []
    for s in insns:
        if s == "exit":
            continue
        if s.startswith("call "):
            result.append("popcnt rax, rdi")
            continue
        m = re.fullmatch(r"([rw]\d+) = \*\(u(8|16|32|64) \*\)\((r\d+) ([+-]) (0x[0-9a-f]+)\)", s)
        if m:
            dst, width, base, sign, off = m.groups()
            width = int(width)
            operand = f"[{reg(base)} {sign} {off}]"
            if width < 32:
                result.append(f"movzx {REG32[int(dst[1:])]}, {'byte' if width == 8 else 'word'} ptr {operand}")
            else:
                dest = REG32[int(dst[1:])] if width == 32 else REG64[int(dst[1:])]
                result.append(f"mov {dest}, {'dword' if width == 32 else 'qword'} ptr {operand}")
            continue
        m = re.fullmatch(r"\*\(u64 \*\)\((r\d+) ([+-]) (0x[0-9a-f]+)\) = (r\d+)", s)
        if m:
            base, sign, off, src = m.groups()
            result.append(f"mov qword ptr [{reg(base)} {sign} {off}], {reg(src)}")
            continue
        m = re.fullmatch(r"([rw]\d+) (=|\+=|-=|\*=|\^=|&=|\|=|<<=|>>=) ([rw]\d+|-?0x[0-9a-f]+)", s)
        if not m:
            raise ValueError(f"Unsupported probe instruction: {s}")
        dst, op, src = m.groups()
        d = reg(dst)
        source = reg(src) if src[0] in "rw" else src
        opcodes = {"=":"mov", "+=":"add", "-=":"sub", "*=":"imul", "^=":"xor", "&=":"and", "|=":"or", "<<=":"shl", ">>=":"shr"}
        if op in ("<<=", ">>=") and src[0] in "rw":
            if int(src[1:]) == 4:
                result.append(f"{opcodes[op]} {d}, cl")
            else:
                shift_reg = (REG32 if dst[0] == "w" else REG64)[int(src[1:])]
                result.append(f"{'shlx' if op == '<<=' else 'shrx'} {d}, {d}, {shift_reg}")
        elif op == "*=" and src[0] not in "rw":
            result.append(f"imul {d}, {d}, {source}")
        else:
            result.append(f"{opcodes[op]} {d}, {source}")
    return result


def fastcall_removed(insns):
    c = next(i for i, s in enumerate(insns) if s.startswith("call "))
    before, after = insns[c-3:c], insns[c+1:c+4]
    expected_before = [f"*(u64 *)(r10 - {off}) = r{r}" for r, off in [(3,"0x8"),(4,"0x10"),(5,"0x18")]]
    expected_after = [f"r{r} = *(u64 *)(r10 - {off})" for r, off in [(5,"0x18"),(4,"0x10"),(3,"0x8")]]
    assert before == expected_before and after == expected_after
    assert sum("r10 -" in s for s in insns) == 6
    return insns[:c-3] + [insns[c]] + insns[c+4:]


def counts(insns):
    return {"bpf_instructions_including_exit":len(insns),
            "stack_stores":sum(s.startswith("*(u64 *)(r10 -") for s in insns),
            "stack_loads":sum("= *(u64 *)(r10 -" in s for s in insns)}


def mca_summary(s):
    keys = {"Total Cycles":"total_cycles", "Total uOps":"total_uops", "Block RThroughput":"block_reciprocal_throughput", "Instructions":"instructions"}
    out = {}
    for line in s.splitlines():
        a, _, b = line.partition(":")
        if a in keys:
            out[keys[a]] = float(b.strip())
    assert len(out) == len(keys)
    return out


def interpret_lane_probe(insns, word):
    """Execute only the scalar/stack/branch subset used by the lane probes."""
    offsets, slot = {}, 0
    for i, s in enumerate(insns):
        offsets[slot] = i
        slot += 2 if s.endswith(" ll") else 1
    slots = {i:s for s,i in offsets.items()}
    registers, stack, ip, executed = {1:word}, {}, 0, 0
    mask64 = (1<<64)-1
    def value(s):
        if s[0] in "rw":
            v = registers[int(s[1:])]
            return v & ((1<<32)-1) if s[0]=="w" else v
        return int(s,0) & mask64
    while executed < 1000:
        s = insns[ip].removesuffix(" ll")
        executed += 1
        if s=="exit":
            return registers[0], executed
        m = re.fullmatch(r"goto ([+-]0x[0-9a-f]+) <[^>]+>",s)
        if m:
            ip = offsets[slots[ip]+1+int(m[1],0)]
            continue
        m = re.fullmatch(r"if ([rw]\d+) (==|!=|<) ([rw]\d+|-?0x[0-9a-f]+) goto ([+-]0x[0-9a-f]+) <[^>]+>",s)
        if m:
            lhs,op,rhs,delta=m.groups()
            take = {"==":lambda:value(lhs)==value(rhs), "!=":lambda:value(lhs)!=value(rhs),
                    "<":lambda:value(lhs)<value(rhs)}[op]()
            ip = offsets[slots[ip]+1+int(delta,0)] if take else ip+1
            continue
        m = re.fullmatch(r"\*\(u64 \*\)\(r10 - (0x[0-9a-f]+)\) = (r\d+)",s)
        if m:
            stack[int(m[1],0)] = value(m[2]); ip+=1; continue
        m = re.fullmatch(r"(r\d+) = \*\(u64 \*\)\(r10 - (0x[0-9a-f]+)\)",s)
        if m:
            registers[int(m[1][1:])] = stack[int(m[2],0)]; ip+=1; continue
        m = re.fullmatch(r"([rw]\d+) (=|\+=|-=|\*=|\^=|&=|\|=|<<=|>>=) ([rw]\d+|-?0x[0-9a-f]+)",s)
        if not m:
            raise ValueError(f"Unsupported lane instruction: {s}")
        dst,op,src=m.groups()
        a=0 if op=="=" else value(dst)
        b=value(src)
        result = {"=":lambda:b,"+=":lambda:a+b,"-=":lambda:a-b,"*=":lambda:a*b,
                  "^=":lambda:a^b,"&=":lambda:a&b,"|=":lambda:a|b,
                  "<<=":lambda:a << (b & (31 if dst[0]=="w" else 63)),
                  ">>=":lambda:a >> (b & (31 if dst[0]=="w" else 63))}[op]()
        registers[int(dst[1:])] = result & ((1<<32)-1 if dst[0]=="w" else mask64)
        ip+=1
    raise RuntimeError("Unexpected lane-probe control flow")


def main():
    src = HERE / "register-packing.c"
    flags = ["-O2", "-g", "-Wall", "-Wextra", "-Werror"]
    run(["clang", "--version"], "clang-version.txt")
    run(["llvm-mca", "--version"], "mca-version.txt")
    run(["clang", "-target", "bpf", "-mcpu=v3", *flags, "-c", src, "-o", OUT/"packing.bpf.o"], "compile-bpf.log")
    disasm = run(["llvm-objdump", "-dr", "--no-show-raw-insn", OUT/"packing.bpf.o"], "packing.bpf.asm")
    run(["clang", *flags, "-march=znver5", "-fsanitize=undefined", "-fno-sanitize-recover=all", "-DPACKING_TEST", src, "-o", OUT/"validate"], "compile-validation.log")
    validation = json.loads(run([OUT/"validate"], "validation.json"))
    functions = parse(disasm)
    lane_rng = random.Random(42)
    lane_inputs = [i*0x1111111111111111 for i in range(16)] + [lane_rng.getrandbits(64) for _ in range(1000)]
    lane_execution = {}
    for name in ("lanes_increment_saturate_scalar", "lanes_increment_saturate_loop", "lanes_increment_saturate_swar"):
        executed = []
        for word in lane_inputs:
            expected = sum(min(((word>>(4*i))&15)+1,15)<<(4*i) for i in range(16))
            result, n = interpret_lane_probe(functions[name],word)
            assert result == expected
            executed.append(n)
        lane_execution[name] = {"input_cases":len(executed), "min_executed_bpf_instructions":min(executed),
                                "max_executed_bpf_instructions":max(executed),
                                "mean_executed_bpf_instructions":sum(executed)/len(executed), "mismatches":0}
    variants = {k:v for k,v in functions.items() if k.startswith("six_")}
    for k,v in list(variants.items()):
        if k.endswith("_fast"):
            variants[k+"_removed"] = fastcall_removed(v)
    bodies = {k:lower(v) for k,v in variants.items()}
    assembly = [".intel_syntax noprefix", ".text"]
    for name, body in bodies.items():
        # Fixed safe wrapper for correctness execution only. MCA models the
        # body separately; these prologues are not actual kernel JIT frames.
        assembly += [f".global replay_{name}", f".type replay_{name}, @function", f"replay_{name}:",
                     "push rbp", "mov rbp, rsp", "sub rsp, 64", "push rbx", "push r13", "push r14", "push r15",
                     *body, "pop r15", "pop r14", "pop r13", "pop rbx", "add rsp, 64", "pop rbp", "ret"]
    assembly += ['.section .note.GNU-stack,"",@progbits']
    (OUT/"replay.S").write_text("\n".join(assembly)+"\n")
    run(["clang", "-shared", "-fPIC", OUT/"replay.S", "-o", OUT/"replay.so"], "compile-replay.log")
    lib = ctypes.CDLL(str(OUT/"replay.so"))
    callables = []
    for name in bodies:
        f = getattr(lib, "replay_"+name)
        f.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong]
        f.restype = ctypes.c_ulonglong
        callables.append(f)
    rng = random.Random(20261001)
    replay_cases = 0
    for _ in range(10000):
        data = [rng.randrange(256) for _ in range(6)]
        p = (ctypes.c_ubyte * 6)(*data)
        x = rng.getrandbits(64)
        t = x.bit_count()
        a,b,c,d,e,f = [n&15 for n in data]
        expected = (a+t) ^ (b*t) ^ (c<<(t&7)) ^ (d*(t+3)) ^ (e<<((t>>3)&7)) ^ (f+(t>>1))
        for fn in callables:
            assert fn(p,x) == expected
            replay_cases += 1
    model = {}
    for name, body in bodies.items():
        for dependency in ("independent", "dependent"):
            # Keep the input pointer invariant across modeled iterations.
            # R12 and hardware R9 are not allocated by these BPF probes.
            reset = ["mov rdi, r12", "mov rsi, r9" if dependency=="independent" else "mov rsi, rax"]
            path = OUT/f"{name}.{dependency}.s"
            path.write_text(".intel_syntax noprefix\n"+"\n".join(reset+body)+"\n")
            for noalias in (True, False):
                key = f"{name}.{dependency}.noalias-{str(noalias).lower()}"
                result = run(["llvm-mca", "-mcpu=znver5", "-iterations=500", f"-noalias={str(noalias).lower()}", path], key+".mca.txt")
                model[key] = mca_summary(result)
                model[key]["cycles_per_iteration_model"] = model[key]["total_cycles"] / 500
    snapshot = ROOT / "target/release/build/scx_cake-d032ab4aa53d1e48/out/bpf.bpf.o"
    census = run(["python", ROOT/"scheds/rust/scx_cake/bench/fnspills.py", snapshot, "cake_"], "cake-object-stack-census.txt")
    summary = {"scope":"offline compiler comparison, semantic execution and LLVM MCA model",
               "bpf_loaded":False, "scheduler_activated":False, "hardware_performance_measured":False,
               "source_sha256":hashlib.sha256(src.read_bytes()).hexdigest(),
               "script_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "cake_object_path":str(snapshot), "cake_object_sha256":hashlib.sha256(snapshot.read_bytes()).hexdigest(),
               "cake_object_caveat":"existing unpruned build object; no exact source/binary receipt established here",
               "validation":validation, "replay_checks":replay_cases,
               "lane_execution_model":lane_execution,
               "bpf_counts":{k:counts(v) for k,v in functions.items()},
               "model_variant_counts":{k:counts(v) for k,v in variants.items()}, "mca":model,
               "limitations":["Not actual kernel JIT or verifier output", "Removed fastcall pairs assume a correct preserving kernel implementation",
                              "Model omits callback/trampoline/prologue costs and frontend fetch effects", "MCA does not model cache misses or store forwarding",
                              "Alias settings are sensitivity scenarios, not strict upper/lower bounds", "Model uses default register and load/store queue capacities",
                              "One synthetic six-scalar workload, not whole Cake or a universal register penalty"]}
    (OUT/"simulation.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps({"output":str(OUT), "validation":validation, "replay_checks":replay_cases,
                      "counts":summary["model_variant_counts"], "mca":model},indent=2))


if __name__ == "__main__":
    try:
        main()
    finally:
        (OUT/"simulation-commands.json").write_text(json.dumps(COMMANDS,indent=2)+"\n")
