// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! `#[scheduler]`, which turns an `impl` block of typed callbacks into a
//! sched_ext scheduler: see scx_rustsched's `sched` module, which re-exports it
//! and has the types the callbacks take.
//!
//! The attribute reads only the names of the functions in the block and
//! how many parameters each has. For each callback it knows, it emits the
//! BPF entry point, which unpacks the kernel's arguments through
//! `sched::Arg` into whatever types the function declares and hands its
//! result back through `sched::Ret`, and it lists the entry points in the
//! struct_ops map. It parses the token stream by hand, so that the BPF
//! build needs no crate from the registry.

use proc_macro::{Delimiter, TokenStream, TokenTree};

/// The callbacks an `impl` block may define: the struct_ops member, and
/// whether the kernel lets it sleep.
const CALLBACKS: [(&str, bool); 11] = [
    ("select_cid", false),
    ("enqueue", false),
    ("dequeue", false),
    ("dispatch", false),
    ("tick", false),
    ("running", false),
    ("stopping", false),
    ("quiescent", false),
    ("enable", false),
    ("update_idle", false),
    ("init", true),
];

fn error(message: &str) -> TokenStream {
    format!("compile_error!({message:?});").parse().unwrap()
}

/// The value of `key = value` in the attribute's arguments, as source.
fn argument(arguments: &[TokenTree], key: &str) -> Option<String> {
    let mut index = 0;
    while index < arguments.len() {
        let start = index;
        while index < arguments.len()
            && !matches!(&arguments[index], TokenTree::Punct(punct) if punct.as_char() == ',')
        {
            index += 1;
        }
        let item = &arguments[start..index];
        index += 1;
        if let [TokenTree::Ident(name), TokenTree::Punct(equals), value @ ..] = item {
            if name.to_string() == key && equals.as_char() == '=' {
                return Some(value.iter().cloned().collect::<TokenStream>().to_string());
            }
        }
    }
    None
}

/// How many parameters a function's parenthesized list declares.
fn parameters(list: TokenStream) -> usize {
    let (mut count, mut depth, mut any) = (0, 0_i32, false);
    for token in list {
        any = true;
        if let TokenTree::Punct(punct) = &token {
            match punct.as_char() {
                '<' => depth += 1,
                '>' => depth -= 1,
                ',' if depth == 0 => count += 1,
                _ => {}
            }
        }
    }
    // A trailing comma is not a parameter; none of the callbacks takes
    // more parameters than the kernel passes, which the wrapper checks.
    if any { count + 1 } else { 0 }
}

/// Declare a sched_ext scheduler from the callbacks of an `impl` block.
///
/// ```ignore
/// #[scx::scheduler(name = "simple", flags = ENQ_LAST)]
/// impl Simple {
///     fn select_cid(task: &Task, prev: Cid, flags: WakeFlags) -> Cid { ... }
///     fn enqueue(task: &Task, flags: EnqFlags) { ... }
///     fn dispatch(cid: Cid, prev: Option<&Task>) { ... }
/// }
/// ```
///
/// `name` is required. `flags` is an expression over the names of
/// `ops::flags`, zero by default. `timeout_ms` is the watchdog timeout,
/// scx_rustsched's `ops::TIMEOUT_MS` (5 s) by default. The attribute declares the
/// type the block implements.
#[proc_macro_attribute]
pub fn scheduler(arguments: TokenStream, item: TokenStream) -> TokenStream {
    let arguments: Vec<TokenTree> = arguments.into_iter().collect();
    let Some(name) = argument(&arguments, "name") else {
        return error("#[scheduler] needs name = \"...\"");
    };
    let flags = argument(&arguments, "flags").unwrap_or_else(|| "0".into());
    let timeout = argument(&arguments, "timeout_ms")
        .unwrap_or_else(|| "::scx_rustsched::ops::TIMEOUT_MS".into());

    let tokens: Vec<TokenTree> = item.clone().into_iter().collect();
    let (Some(TokenTree::Ident(keyword)), Some(TokenTree::Ident(ty)), Some(TokenTree::Group(body))) =
        (tokens.first(), tokens.get(1), tokens.get(2))
    else {
        return error("#[scheduler] goes on `impl Name { ... }`");
    };
    if keyword.to_string() != "impl" || body.delimiter() != Delimiter::Brace || tokens.len() != 3 {
        return error("#[scheduler] goes on `impl Name { ... }`");
    }
    let ty = ty.to_string();

    // The functions of the block: `fn name(...)`.
    let body: Vec<TokenTree> = body.stream().into_iter().collect();
    let mut functions = Vec::new();
    for window in body.windows(3) {
        if let [
            TokenTree::Ident(keyword),
            TokenTree::Ident(function),
            TokenTree::Group(list),
        ] = window
        {
            if keyword.to_string() == "fn" && list.delimiter() == Delimiter::Parenthesis {
                functions.push((function.to_string(), parameters(list.stream())));
            }
        }
    }
    for (function, _) in &functions {
        if !CALLBACKS.iter().any(|(member, _)| member == function) {
            return error(&format!(
                "#[scheduler]: `{function}` is not a callback this attribute knows"
            ));
        }
    }
    let defined = |member: &str| functions.iter().find(|(function, _)| function == member);

    let mut output = format!("pub struct {ty};\n");
    let mut members = String::new();
    for (member, sleepable) in CALLBACKS {
        let user = defined(member);
        // The runtime has work of its own in these three, so they exist
        // whether the scheduler defines them or not.
        let runtime = matches!(member, "init" | "update_idle" | "dispatch");
        if user.is_none() && !runtime {
            continue;
        }
        let call = user.map(|(_, count)| {
            let arguments = (0..*count)
                .map(|index| format!("::scx_rustsched::sched::Arg::arg(context, {index})"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{ty}::{member}({arguments})")
        });
        let body = match (member, call) {
            ("init", Some(call)) => format!(
                "let result = ::scx_rustsched::sched::init();
                 if result != 0 {{ return result as u64; }}
                 ::scx_rustsched::sched::Ret::ret({call})"
            ),
            ("init", None) => "::scx_rustsched::sched::init() as u64".into(),
            ("update_idle", call) => format!(
                "::scx_rustsched::sched::update_idle(context);
                 {}
                 0",
                call.map(|call| format!("{call};")).unwrap_or_default()
            ),
            ("dispatch", call) => format!(
                "{}
                 ::scx_rustsched::sched::dispatched(context);
                 0",
                call.map(|call| format!("{call};")).unwrap_or_default()
            ),
            (_, Some(call)) => format!("::scx_rustsched::sched::Ret::ret({call})"),
            (_, None) => unreachable!(),
        };
        let section = if sleepable {
            "struct_ops.s"
        } else {
            "struct_ops"
        };
        output += &format!(
            "#[unsafe(no_mangle)]
             #[unsafe(link_section = \"{section}/{member}\")]
             pub unsafe extern \"C\" fn scx_{member}(context: *const u64) -> u64 {{
                 ::scx_rustsched::sched::enter();
                 #[allow(unused_unsafe)]
                 unsafe {{ {body} }}
             }}\n"
        );
        members += &format!("{member}: scx_{member},\n");
    }
    output += &format!(
        "::scx_rustsched::scx_ops! {{
             name: {name}.as_bytes(),
             flags: {{
                 #[allow(unused_imports)]
                 use ::scx_rustsched::ops::flags::*;
                 {flags}
             }},
             timeout_ms: {timeout},
             dump_len: ::scx_rustsched::uei::DUMP_LEN as u32,
             callbacks: {{
                 {members}
                 exit: ::scx_rustsched::uei::rust_exit,
             }}
         }}\n"
    );
    let mut output: TokenStream = match output.parse() {
        Ok(output) => output,
        Err(_) => return error("#[scheduler]: could not generate the entry points"),
    };
    output.extend(item);
    output
}
