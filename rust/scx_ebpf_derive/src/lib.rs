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

/// Description of a sched_ext_ops callback's kernel signature.
struct CallbackSig {
    name: &'static str,
    /// Each param: (extraction expression from ctx, cast type).
    /// `"ptr"` means `*ctx.add(N) as *mut task_struct`
    /// `"i32"` means `*ctx.add(N) as i32`
    /// `"u64"` means `*ctx.add(N)`
    /// `"bool"` means `*ctx.add(N) != 0`
    params: &'static [(&'static str, &'static str)],
    /// Return type: `None` for void, `Some("i32")` for s32
    ret: Option<&'static str>,
    /// Whether this is sleepable (uses struct_ops.s/ section)
    sleepable: bool,
}

const CALLBACKS: &[CallbackSig] = &[
    CallbackSig {
        name: "select_cpu",
        params: &[("ptr", "p"), ("i32", "prev_cpu"), ("u64", "wake_flags")],
        ret: Some("i32"),
        sleepable: false,
    },
    CallbackSig {
        name: "enqueue",
        params: &[("ptr", "p"), ("u64", "enq_flags")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dequeue",
        params: &[("ptr", "p"), ("u64", "deq_flags")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dispatch",
        params: &[("i32", "cpu"), ("ptr", "prev")],
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
        params: &[("ptr", "p"), ("u64", "enq_flags")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "running",
        params: &[("ptr", "p")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "stopping",
        params: &[("ptr", "p"), ("bool", "runnable")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "quiescent",
        params: &[("ptr", "p"), ("u64", "deq_flags")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "set_weight",
        params: &[("ptr", "p"), ("u32", "weight")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "set_cpumask",
        params: &[("ptr", "p"), ("ptr", "cpumask")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "update_idle",
        params: &[("i32", "cpu"), ("bool", "idle")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "cpu_acquire",
        params: &[("i32", "cpu"), ("ptr", "args")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "cpu_release",
        params: &[("i32", "cpu"), ("ptr", "args")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "init_task",
        params: &[("ptr", "p"), ("ptr", "args")],
        ret: Some("i32"),
        sleepable: false,
    },
    CallbackSig {
        name: "exit_task",
        params: &[("ptr", "p"), ("ptr", "args")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "enable",
        params: &[("ptr", "p")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "disable",
        params: &[("ptr", "p")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dump",
        params: &[("ptr", "dctx")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dump_cpu",
        params: &[("ptr", "dctx"), ("i32", "cpu"), ("bool", "idle")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "dump_task",
        params: &[("ptr", "dctx"), ("ptr", "p")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "cpu_online",
        params: &[("i32", "cpu")],
        ret: None,
        sleepable: false,
    },
    CallbackSig {
        name: "cpu_offline",
        params: &[("i32", "cpu")],
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
        params: &[("ptr", "ei")],
        ret: None,
        sleepable: false,
    },
];

/// A single `field: handler` pair in the macro input.
struct CallbackEntry {
    field: Ident,
    handler: syn::Path,
}

impl Parse for CallbackEntry {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let field = input.parse()?;
        input.parse::<Token![:]>()?;
        let handler = input.parse()?;
        Ok(Self { field, handler })
    }
}

/// The full macro input: `name: "...", field: handler, ...`
struct ScxOpsDef {
    name: LitStr,
    callbacks: Vec<CallbackEntry>,
}

impl Parse for ScxOpsDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Parse `name: "..."`
        let _name_kw: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let name: LitStr = input.parse()?;
        input.parse::<Token![,]>()?;

        // Parse remaining `field: handler` entries
        let entries = Punctuated::<CallbackEntry, Token![,]>::parse_terminated(input)?;

        Ok(Self {
            name,
            callbacks: entries.into_iter().collect(),
        })
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

        // Find the callback signature
        let sig = CALLBACKS.iter().find(|s| s.name == field_str);
        let sig = match sig {
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

        // Generate the link section name
        let section = if sig.sleepable {
            format!("struct_ops.s/{field_str}")
        } else {
            format!("struct_ops/{field_str}")
        };

        // Generate parameter extraction from ctx
        let mut param_extracts = Vec::new();
        let mut call_args = Vec::new();

        for (i, (ty, param_name)) in sig.params.iter().enumerate() {
            let param_ident = Ident::new(param_name, Span::call_site());
            let extract = match *ty {
                "ptr" => quote! {
                    let #param_ident = unsafe { *ctx.add(#i) as *mut core::ffi::c_void };
                },
                "i32" => quote! {
                    let #param_ident = unsafe { *ctx.add(#i) as i32 };
                },
                "u32" => quote! {
                    let #param_ident = unsafe { *ctx.add(#i) as u32 };
                },
                "u64" => quote! {
                    let #param_ident = unsafe { *ctx.add(#i) };
                },
                "bool" => quote! {
                    let #param_ident = unsafe { *ctx.add(#i) != 0 };
                },
                _ => unreachable!(),
            };
            param_extracts.push(extract);
            call_args.push(quote! { #param_ident });
        }

        // Generate the trampoline function
        let ret_type = match sig.ret {
            Some("i32") => quote! { -> i32 },
            _ => quote! {},
        };

        let trampoline = if sig.params.is_empty() {
            // No ctx parameter for init()
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
                    #(#param_extracts)*
                    #handler(#(#call_args),*)
                }
            }
        };

        trampolines.push(trampoline);

        // Generate the ops struct field assignment
        ops_fields.push(quote! {
            #field_name: Some(#field_name),
        });
    }

    // Generate the scheduler name as a [u8; 128] constant
    let sched_name = def.name.value();
    let name_bytes: Vec<u8> = {
        let mut n = vec![0u8; 128];
        for (i, b) in sched_name.bytes().enumerate() {
            if i >= 127 {
                break;
            }
            n[i] = b;
        }
        n
    };

    let output = quote! {
        #(#trampolines)*

        #[unsafe(link_section = ".struct_ops.link")]
        #[unsafe(no_mangle)]
        static _scx_ops: scx_ebpf::ops::sched_ext_ops = scx_ebpf::ops::sched_ext_ops {
            #(#ops_fields)*
            name: [#(#name_bytes),*],
            ..scx_ebpf::ops::DEFAULT_OPS
        };
    };

    output.into()
}
