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
//!
//! `#[global]` makes a function a BPF global function, and `opts!()`
//! declares the scheduler's tunables from the options of its loader.

use proc_macro::{Delimiter, TokenStream, TokenTree};

/// The callbacks an `impl` block may define: the struct_ops member, and
/// whether the kernel lets it sleep.
const CALLBACKS: [(&str, bool); 13] = [
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
    ("init_task", true),
    ("exit_task", false),
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
/// scx_rustsched's `ops::TIMEOUT_MS` (5 s) by default. `task` names the type of
/// the scheduler's per-task state, which the runtime then creates in
/// ops.init_task(), and `cid` the type of its per-CID state, set up in
/// ops.init(). The attribute declares the type the block implements.
#[proc_macro_attribute]
pub fn scheduler(arguments: TokenStream, item: TokenStream) -> TokenStream {
    let arguments: Vec<TokenTree> = arguments.into_iter().collect();
    let Some(name) = argument(&arguments, "name") else {
        return error("#[scheduler] needs name = \"...\"");
    };
    let flags = argument(&arguments, "flags").unwrap_or_else(|| "0".into());
    let timeout = argument(&arguments, "timeout_ms")
        .unwrap_or_else(|| "::scx_rustsched::ops::TIMEOUT_MS".into());
    let task = argument(&arguments, "task");
    let cid = argument(&arguments, "cid");

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
    if let Some(task) = &task {
        output += &format!("::scx_rustsched::task_state!({task});\n");
    }
    if let Some(cid) = &cid {
        output += &format!("::scx_rustsched::cid_state!({cid});\n");
    }
    let mut members = String::new();
    for (member, sleepable) in CALLBACKS {
        let user = defined(member);
        // The runtime has work of its own in these three, so they exist
        // whether the scheduler defines them or not.
        let runtime = matches!(member, "init" | "update_idle" | "dispatch")
            || (member == "init_task" && task.is_some());
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
            ("init", call) => format!(
                "if let Err(error) = ::scx_rustsched::sched::init() {{
                     return ::scx_rustsched::sched::Ret::ret(Err::<(), _>(error));
                 }}
                 {}
                 {}",
                cid.as_ref()
                    .map(|cid| format!(
                        "if let Err(error) = ::scx_rustsched::sched::init_cids::<{cid}>() {{
                             return ::scx_rustsched::sched::Ret::ret(Err::<(), _>(error));
                         }}"
                    ))
                    .unwrap_or_default(),
                call.map(|call| format!("::scx_rustsched::sched::Ret::ret({call})"))
                    .unwrap_or_else(|| "0".into())
            ),
            ("init_task", call) if task.is_some() => format!(
                "if let Err(error) = ::scx_rustsched::sched::init_task::<{}>(context) {{
                     return ::scx_rustsched::sched::Ret::ret(Err::<(), _>(error));
                 }}
                 {}",
                task.as_ref().unwrap(),
                call.map(|call| format!("::scx_rustsched::sched::Ret::ret({call})"))
                    .unwrap_or_else(|| "0".into())
            ),
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

/// Split a token list at its top-level commas.
fn split(list: TokenStream) -> Vec<Vec<TokenTree>> {
    let (mut items, mut depth) = (vec![Vec::new()], 0_i32);
    let mut previous = ' ';
    for token in list {
        if let TokenTree::Punct(punct) = &token {
            match punct.as_char() {
                '<' => depth += 1,
                // The `>` of `->` closes nothing.
                '>' if previous != '-' => depth -= 1,
                ',' if depth == 0 => {
                    items.push(Vec::new());
                    previous = ',';
                    continue;
                }
                _ => {}
            }
            previous = punct.as_char();
        } else {
            previous = ' ';
        }
        items.last_mut().unwrap().push(token);
    }
    if items.last().is_some_and(Vec::is_empty) {
        items.pop();
    }
    items
}

fn source(tokens: &[TokenTree]) -> String {
    tokens.iter().cloned().collect::<TokenStream>().to_string()
}

/// Make a function a BPF global function: one the verifier checks once,
/// by itself, instead of at every call.
///
/// ```ignore
/// #[scx::global]
/// fn steal(cid: Cid) -> bool {
///     for peer in cid.scope(Scope::Llc) { ... }
///     false
/// }
/// ```
///
/// A scheduler's callbacks are otherwise inlined into one program each,
/// and the verifier walks every path through all of it. A loop, or a long
/// search called from several places, is what to put behind `#[global]`:
/// the verifier then checks its body once and treats each call as opaque.
///
/// The function is called as written. It takes up to five parameters and
/// returns one value, of the types `sched::Abi` covers: `Cid`, `&Task`,
/// integers, `bool` and the flags types. The verifier knows nothing of the
/// arguments but their types, so the body cannot rely on a value being in
/// range because the caller checked it.
#[proc_macro_attribute]
pub fn global(_arguments: TokenStream, item: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = item.into_iter().collect();
    let Some(start) = tokens
        .iter()
        .position(|token| matches!(token, TokenTree::Ident(ident) if ident.to_string() == "fn"))
    else {
        return error("#[global] goes on a function");
    };
    let (Some(TokenTree::Ident(name)), Some(TokenTree::Group(list)), Some(TokenTree::Group(body))) =
        (tokens.get(start + 1), tokens.get(start + 2), tokens.last())
    else {
        return error("#[global] goes on `fn name(...) -> Type { ... }`, without generics");
    };
    if list.delimiter() != Delimiter::Parenthesis || body.delimiter() != Delimiter::Brace {
        return error("#[global] goes on `fn name(...) -> Type { ... }`, without generics");
    }
    let prefix = source(&tokens[..start]);
    if prefix
        .split_whitespace()
        .any(|word| matches!(word, "unsafe" | "async" | "const" | "extern"))
    {
        return error("#[global] goes on a plain function");
    }
    // What follows the parameters is `-> Type`, or nothing.
    let result = &tokens[start + 3..tokens.len() - 1];
    let result = match result {
        [] => "()".to_string(),
        [TokenTree::Punct(dash), TokenTree::Punct(angle), ty @ ..]
            if dash.as_char() == '-' && angle.as_char() == '>' && !ty.is_empty() =>
        {
            source(ty)
        }
        _ => return error("#[global]: expected `-> Type` after the parameters"),
    };
    let mut types = Vec::new();
    for parameter in split(list.stream()) {
        let Some(colon) = parameter
            .iter()
            .position(|token| matches!(token, TokenTree::Punct(punct) if punct.as_char() == ':'))
        else {
            return error("#[global] takes `name: Type` parameters, and no `self`");
        };
        types.push(source(&parameter[colon + 1..]));
    }
    if types.len() > 5 {
        return error("#[global]: a BPF function takes at most five parameters");
    }
    let name = name.to_string();
    let abi = "::scx_rustsched::sched::Abi";
    let join = |each: &dyn Fn(usize, &String) -> String| {
        types
            .iter()
            .enumerate()
            .map(|(index, ty)| each(index, ty))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let outer = join(&|index, ty| format!("a{index}: {ty}"));
    let raw = join(&|index, ty| format!("a{index}: <{ty} as {abi}>::Raw"));
    let unpack = join(&|index, ty| format!("<{ty} as {abi}>::from_raw(a{index})"));
    let pack = join(&|index, ty| format!("<{ty} as {abi}>::into_raw(a{index})"));
    let parameters = list.stream();
    let body = body.stream();
    let output = format!(
        "#[inline(always)]
         {prefix} fn {name}({outer}) -> {result} {{
             #[unsafe(no_mangle)]
             #[inline(never)]
             extern \"C\" fn scx_global_{name}({raw}) -> <{result} as {abi}>::Raw {{
                 #[inline(always)]
                 fn {name}({parameters}) -> {result} {{ {body} }}
                 #[allow(unused_unsafe)]
                 <{result} as {abi}>::into_raw(unsafe {{ {name}({unpack}) }})
             }}
             #[allow(unused_unsafe)]
             unsafe {{ <{result} as {abi}>::from_raw(scx_global_{name}({pack})) }}
         }}"
    );
    match output.parse() {
        Ok(output) => output,
        Err(_) => error("#[global]: could not generate the function"),
    }
}

/// The types of an option that is a tunable as it stands.
const TUNABLE_TYPES: [&str; 9] = ["bool", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"];

/// The default a `#[clap(...)]` or `#[arg(...)]` attribute gives its
/// option, from `default_value = "text"` or `default_value_t = value`.
fn option_default(attribute: &[TokenTree]) -> Option<String> {
    let [TokenTree::Ident(kind), TokenTree::Group(list)] = attribute else {
        return None;
    };
    if !matches!(kind.to_string().as_str(), "clap" | "arg") {
        return None;
    }
    let list: Vec<TokenTree> = list.stream().into_iter().collect();
    list.split(|token| matches!(token, TokenTree::Punct(punct) if punct.as_char() == ','))
        .find_map(|setting| match setting {
            [TokenTree::Ident(key), TokenTree::Punct(_), value @ ..] => {
                match key.to_string().as_str() {
                    "default_value" => Some(source(value).trim().trim_matches('"').to_owned()),
                    "default_value_t" => Some(source(value)),
                    _ => None,
                }
            }
            _ => None,
        })
}

/// Whether an attribute is `#[opts(no_bpf)]`, or an `#[opts(...)]` that
/// says something else, which is an error.
fn opts_marker(attribute: &[TokenTree]) -> Option<Result<(), String>> {
    let [TokenTree::Ident(kind), TokenTree::Group(list)] = attribute else {
        return None;
    };
    if kind.to_string() != "opts" {
        return None;
    }
    let list = list.stream().to_string();
    Some(if list.trim() == "no_bpf" {
        Ok(())
    } else {
        Err(format!(
            "#[opts({list})]: the only marker is #[opts(no_bpf)]"
        ))
    })
}

/// The derive that lets a field of the loader's options carry
/// `#[opts(no_bpf)]`: an option that only the loader uses, for which
/// `opts!()` declares no tunable on the BPF side.
///
/// ```ignore
/// #[derive(clap::Args, scx_rustsched_macros::Opts)]
/// struct Opts {
///     /// Scheduling slice duration in microseconds.
///     #[clap(short = 's', long, default_value = "5000")]
///     slice_us: u64,
///
///     /// Treat every CPU as having the same capacity.
///     #[opts(no_bpf)]
///     #[clap(long)]
///     uniform_capacity: bool,
/// }
/// ```
///
/// It generates nothing: the marker is read by `opts!()`, from the source.
#[proc_macro_derive(Opts, attributes(opts))]
pub fn derive_opts(_item: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// The stem and the factor to nanoseconds of a tunable named after an
/// option in microseconds or milliseconds: `SLICE_US` is `SLICE`, 1000.
fn time_unit(name: &str) -> Option<(&str, u64)> {
    [("_US", 1_000), ("_MS", 1_000_000)]
        .into_iter()
        .find_map(|(suffix, factor)| Some((name.strip_suffix(suffix)?, factor)))
}

/// `opts!()` declares the scheduler's tunables from the options of its
/// loader, so that they are written once: for each field of `struct Opts`
/// in `../src/main.rs` that is an integer or a `bool`, a `params!` tunable
/// of the field's name in upper case, with its type, its documentation and
/// the default its `clap` attribute gives it.
///
/// ```ignore
/// // src/main.rs, the loader
/// #[derive(clap::Args)]
/// struct Opts {
///     /// Scheduling slice duration in microseconds.
///     #[clap(short = 's', long, default_value = "5000")]
///     slice_us: u64,
/// }
///
/// // bpf/src/main.rs, the scheduler
/// scx::opts!();
///
/// dsq::insert(task, Dsq::Global, SLICE_NS.get(), flags);
/// ```
///
/// A time is in nanoseconds in the scheduler: an option in microseconds
/// or milliseconds, named `_us` or `_ms`, gives the tunable named `_NS`,
/// with the default converted, and the loader converts what it is given.
///
/// A field of any other type, such as a `String`, is not a tunable: the
/// loader turns it into one the scheduler declares with `params!`. Nor is
/// a field marked `#[opts(no_bpf)]`, an option only the loader uses, see
/// the `Opts` derive. `opts!("path")` reads another file, relative to the
/// BPF crate.
#[proc_macro]
pub fn opts(arguments: TokenStream) -> TokenStream {
    let relative = match arguments.into_iter().collect::<Vec<_>>().as_slice() {
        [] => "../src/main.rs".to_owned(),
        [TokenTree::Literal(path)] => path.to_string().trim_matches('"').to_owned(),
        _ => return error("opts!() takes at most the path of the loader's source"),
    };
    let path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .join(relative);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return error(&format!("opts!() cannot read {}", path.display()));
    };
    let Ok(file) = text.parse::<TokenStream>() else {
        return error(&format!("opts!() cannot parse {}", path.display()));
    };
    let file: Vec<TokenTree> = file.into_iter().collect();
    let Some(TokenTree::Group(body)) = file
        .windows(3)
        .find(|window| {
            matches!(window, [TokenTree::Ident(keyword), TokenTree::Ident(name), TokenTree::Group(body)]
                if keyword.to_string() == "struct"
                    && name.to_string() == "Opts"
                    && body.delimiter() == Delimiter::Brace)
        })
        .map(|window| &window[2])
    else {
        return error(&format!("opts!() finds no `struct Opts {{ ... }}` in {}", path.display()));
    };
    // The file is part of the build: a change to it rebuilds the crate.
    let mut output = format!(
        "const _: &[u8] = include_bytes!({:?});\n",
        path.display().to_string()
    );
    output += "::scx_rustsched::params! {\n";
    let body: Vec<TokenTree> = body.stream().into_iter().collect();
    let (mut index, mut documentation, mut default) = (0, String::new(), None);
    let mut no_bpf = false;
    while index < body.len() {
        match (&body[index], body.get(index + 1)) {
            // An attribute: the documentation is kept, and clap's gives
            // the default.
            (TokenTree::Punct(punct), Some(TokenTree::Group(attribute)))
                if punct.as_char() == '#' =>
            {
                let attribute: Vec<TokenTree> = attribute.stream().into_iter().collect();
                if matches!(attribute.first(), Some(TokenTree::Ident(name)) if name.to_string() == "doc")
                {
                    documentation += &format!("#[{}]\n", source(&attribute));
                }
                default = option_default(&attribute).or(default);
                match opts_marker(&attribute) {
                    Some(Ok(())) => no_bpf = true,
                    Some(Err(message)) => return error(&message),
                    None => {}
                }
                index += 2;
            }
            // A field: its type runs to the next comma outside angle
            // brackets.
            (TokenTree::Ident(name), Some(TokenTree::Punct(punct))) if punct.as_char() == ':' => {
                let (mut end, mut depth) = (index + 2, 0);
                while end < body.len() {
                    match &body[end] {
                        TokenTree::Punct(punct) if punct.as_char() == '<' => depth += 1,
                        TokenTree::Punct(punct) if punct.as_char() == '>' => depth -= 1,
                        TokenTree::Punct(punct) if punct.as_char() == ',' && depth == 0 => break,
                        _ => {}
                    }
                    end += 1;
                }
                let ty = source(&body[index + 2..end]);
                if TUNABLE_TYPES.contains(&ty.trim()) && !no_bpf {
                    let default = default
                        .take()
                        .unwrap_or_else(|| if ty.trim() == "bool" { "false" } else { "0" }.into());
                    // Time is in nanoseconds in the scheduler, whatever
                    // unit the option takes it in.
                    let name = name.to_string().to_uppercase();
                    let (name, default) = match time_unit(&name) {
                        Some((stem, factor)) if ty.trim() != "bool" => {
                            (format!("{stem}_NS"), format!("({default}) * {factor}"))
                        }
                        _ => (name, default),
                    };
                    output += &format!("{documentation}{name}: {ty} = {default};\n");
                }
                (documentation, default, no_bpf) = (String::new(), None, false);
                index = end + 1;
            }
            // `pub` and its like, before the field's name.
            _ => index += 1,
        }
    }
    output += "}\n";
    output
        .parse()
        .unwrap_or_else(|_| error("opts!() cannot declare the tunables of `struct Opts`"))
}
