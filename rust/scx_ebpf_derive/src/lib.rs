//! Proc macros for pure-Rust sched_ext schedulers.
//!
//! Provides `scx_ops_define!` which generates callback trampolines and
//! the `sched_ext_ops` static from a list of callback handlers.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    Ident, LitStr, Token,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

/// Parameter types for callback signatures.
#[derive(Clone, Copy)]
enum ParamType {
    /// `*mut task_struct` — cast from `*ctx.add(N) as *mut scx_ebpf::vmlinux::task_struct`
    Task,
    /// `*mut scx_exit_info` — cast from `*ctx.add(N) as *mut scx_ebpf::vmlinux::scx_exit_info`
    ExitInfo,
    /// `*mut core::ffi::c_void` — generic kernel pointer (cpumask, args, dctx, etc.)
    Ptr,
    /// `i32` — cast from `*ctx.add(N) as i32`
    I32,
    /// `u32` — cast from `*ctx.add(N) as u32`
    U32,
    /// `u64` — read directly from `*ctx.add(N)`
    U64,
    /// `bool` — `*ctx.add(N) != 0`
    Bool,
}

/// Description of a sched_ext_ops callback's kernel signature.
struct CallbackSig {
    name: &'static str,
    params: &'static [(ParamType, &'static str)],
    ret: Option<&'static str>,
    sleepable: bool,
}

use ParamType::*;

const CALLBACKS: &[CallbackSig] = &[
    CallbackSig {
        name: "select_cpu",
        params: &[(Task, "p"), (I32, "prev_cpu"), (U64, "wake_flags")],
        ret: Some("i32"),
        sleepable: false,
    },
    CallbackSig {
        name: "enqueue",
        params: &[(Task, "p"), (U64, "enq_flags")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dequeue",
        params: &[(Task, "p"), (U64, "deq_flags")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dispatch",
        params: &[(I32, "cpu"), (Task, "prev")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "tick",
        params: &[],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "runnable",
        params: &[(Task, "p"), (U64, "enq_flags")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "running",
        params: &[(Task, "p")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "stopping",
        params: &[(Task, "p"), (Bool, "runnable")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "quiescent",
        params: &[(Task, "p"), (U64, "deq_flags")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "set_weight",
        params: &[(Task, "p"), (U32, "weight")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "set_cpumask",
        params: &[(Task, "p"), (Ptr, "cpumask")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "update_idle",
        params: &[(I32, "cpu"), (Bool, "idle")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "cpu_acquire",
        params: &[(I32, "cpu"), (Ptr, "args")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "cpu_release",
        params: &[(I32, "cpu"), (Ptr, "args")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "init_task",
        params: &[(Task, "p"), (Ptr, "args")],
        ret: Some("i32"),
        sleepable: false,
    },
    CallbackSig {
        name: "exit_task",
        params: &[(Task, "p"), (Ptr, "args")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "enable",
        params: &[(Task, "p")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "disable",
        params: &[(Task, "p")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dump",
        params: &[(Ptr, "dctx")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dump_cpu",
        params: &[(Ptr, "dctx"), (I32, "cpu"), (Bool, "idle")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dump_task",
        params: &[(Ptr, "dctx"), (Task, "p")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "cpu_online",
        params: &[(I32, "cpu")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "cpu_offline",
        params: &[(I32, "cpu")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "init",
        params: &[],
        ret: Some("i32"),
        sleepable: true,
    },
    CallbackSig {
        name: "exit",
        params: &[(ExitInfo, "ei")],
        ret: None,
        sleepable: false,
    },
];

/// A single `field: handler` pair in the macro input.
struct CallbackEntry {
    field: Ident,
    handler: syn::Path,
}

/// A single entry in the macro input — either a callback or a data field.
enum MacroEntry {
    Callback(CallbackEntry),
    DataField { field: Ident, value: syn::LitInt },
}

impl Parse for MacroEntry {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let field: Ident = input.parse()?;
        input.parse::<Token![:]>()?;

        // Peek to see if the value is a literal integer or a path.
        if input.peek(syn::LitInt) {
            let value: syn::LitInt = input.parse()?;
            Ok(MacroEntry::DataField { field, value })
        } else {
            let handler: syn::Path = input.parse()?;
            Ok(MacroEntry::Callback(CallbackEntry { field, handler }))
        }
    }
}

/// The full macro input: `name: "...", field: handler, ...`
///
/// Supports optional data fields mixed with callbacks:
/// - `timeout_ms: 5000` — scheduler timeout in milliseconds
/// - `flags: 0` — scheduler flags
struct ScxOpsDef {
    name: LitStr,
    callbacks: Vec<CallbackEntry>,
    timeout_ms: Option<u32>,
    flags: Option<u64>,
}

impl Parse for ScxOpsDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let _name_kw: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let name: LitStr = input.parse()?;
        input.parse::<Token![,]>()?;

        let mut callbacks = Vec::new();
        let mut timeout_ms = None;
        let mut flags = None;

        let entries = Punctuated::<MacroEntry, Token![,]>::parse_terminated(input)?;
        for entry in entries {
            match entry {
                MacroEntry::Callback(cb) => callbacks.push(cb),
                MacroEntry::DataField { field, value } => {
                    let field_str = field.to_string();
                    match field_str.as_str() {
                        "timeout_ms" => {
                            timeout_ms = Some(value.base10_parse::<u32>()?);
                        }
                        "flags" => {
                            flags = Some(value.base10_parse::<u64>()?);
                        }
                        _ => {
                            return Err(syn::Error::new(
                                field.span(),
                                format!("unknown data field: `{field_str}` (expected timeout_ms or flags)"),
                            ));
                        }
                    }
                }
            }
        }

        Ok(Self { name, callbacks, timeout_ms, flags })
    }
}

fn param_extract(ty: ParamType, idx: usize, name: &Ident) -> proc_macro2::TokenStream {
    match ty {
        Task => quote! {
            let #name = unsafe { *ctx.add(#idx) as *mut scx_ebpf::vmlinux::task_struct };
        },
        ExitInfo => quote! {
            let #name = unsafe { *ctx.add(#idx) as *mut scx_ebpf::vmlinux::scx_exit_info };
        },
        Ptr => quote! {
            let #name = unsafe { *ctx.add(#idx) as *mut core::ffi::c_void };
        },
        I32 => quote! {
            let #name = unsafe { *ctx.add(#idx) as i32 };
        },
        U32 => quote! {
            let #name = unsafe { *ctx.add(#idx) as u32 };
        },
        U64 => quote! {
            let #name = unsafe { *ctx.add(#idx) };
        },
        Bool => quote! {
            let #name = unsafe { *ctx.add(#idx) != 0 };
        },
    }
}

/// Generates trampolines, the `sched_ext_ops` static, and boilerplate.
///
/// Usage:
/// ```ignore
/// scx_ops_define! {
///     name: "my_scheduler",
///     enqueue: my_enqueue,
///     dispatch: my_dispatch,
///     init: my_init,
///     exit: my_exit,
/// }
/// ```
#[proc_macro]
pub fn scx_ops_define(input: TokenStream) -> TokenStream {
    let def = syn::parse_macro_input!(input as ScxOpsDef);
    let mut trampolines = Vec::new();
    let mut ops_fields = Vec::new();

    for entry in &def.callbacks {
        let field_name = &entry.field;
        let handler = &entry.handler;
        let field_str = field_name.to_string();

        let sig = match CALLBACKS.iter().find(|s| s.name == field_str) {
            Some(s) => s,
            None => {
                return syn::Error::new(
                    field_name.span(),
                    format!("unknown sched_ext callback: `{field_str}`"),
                )
                .to_compile_error()
                .into();
            }
        };

        let section = if sig.sleepable {
            format!("struct_ops.s/{field_str}")
        } else {
            format!("struct_ops/{field_str}")
        };

        let mut extracts = Vec::new();
        let mut call_args = Vec::new();

        for (i, (ty, param_name)) in sig.params.iter().enumerate() {
            let param_ident = Ident::new(param_name, Span::call_site());
            extracts.push(param_extract(*ty, i, &param_ident));
            call_args.push(quote! { #param_ident });
        }

        let ret_type = match sig.ret {
            Some("i32") => quote! { -> i32 },
            _ => quote! {},
        };

        let trampoline = if sig.params.is_empty() {
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = #section)]
                unsafe extern "C" fn #field_name() #ret_type {
                    #handler(#(#call_args),*)
                }
            }
        } else {
            quote! {
                #[unsafe(no_mangle)]
                #[unsafe(link_section = #section)]
                unsafe extern "C" fn #field_name(ctx: *const u64) #ret_type {
                    #(#extracts)*
                    #handler(#(#call_args),*)
                }
            }
        };

        trampolines.push(trampoline);
        ops_fields.push(quote! { #field_name: Some(#field_name), });
    }

    let sched_name = def.name.value();
    let name_bytes: Vec<u8> = {
        let mut n = vec![0u8; 128];
        for (i, b) in sched_name.bytes().enumerate() {
            if i >= 127 { break; }
            n[i] = b;
        }
        n
    };

    // Generate data field overrides for timeout_ms and flags.
    let timeout_field = match def.timeout_ms {
        Some(v) => quote! { timeout_ms: #v, },
        None => quote! {},
    };
    let flags_field = match def.flags {
        Some(v) => quote! { flags: #v, },
        None => quote! {},
    };

    let output = quote! {
        #(#trampolines)*

        #[unsafe(link_section = ".struct_ops.link")]
        #[unsafe(no_mangle)]
        static _scx_ops: scx_ebpf::ops::sched_ext_ops = scx_ebpf::ops::sched_ext_ops {
            #(#ops_fields)*
            #timeout_field
            #flags_field
            name: [#(#name_bytes),*],
            ..scx_ebpf::ops::DEFAULT_OPS
        };
    };

    output.into()
}
