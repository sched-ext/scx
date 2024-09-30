use quote::{format_ident, quote, quote_spanned};
use scx_stats::{StatsData, StatsKind, StatsMetaAux};
use std::sync::atomic::{AtomicU64, Ordering};
use syn::parse_macro_input;
use syn::spanned::Spanned;
use syn::{Attribute, Data, DeriveInput, Fields, Lit};

static ASSERT_IDX: AtomicU64 = AtomicU64::new(0);

#[proc_macro_derive(Stats, attributes(stat))]
pub fn stat(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let stats_aux = parse_macro_input!(input as StatsMetaAux);
    let (meta, ident, paths) = (stats_aux.meta, stats_aux.ident, stats_aux.paths);

    let mut output = proc_macro2::TokenStream::new();

    for (_fname, field) in meta.fields.iter() {
        match &field.data {
            StatsData::Datum(datum)
            | StatsData::Array(datum)
            | StatsData::Dict { key: _, datum } => {
                if let StatsKind::Struct(name) = &datum {
                    let path = &paths[name.as_str()];
                    let idx = ASSERT_IDX.fetch_add(1, Ordering::Relaxed);
                    let assert_id = format_ident!("_AssertStatsMeta_{}", idx);
                    #[rustfmt::skip]
                    let assert = quote_spanned! {path.span()=>
                          struct #assert_id where #path: scx_stats::Meta;
                    };
                    output.extend(assert.into_iter());
                }
            }
        }
    }

    let body = serde_json::to_string(&meta).unwrap();
    let trait_body = quote! {
    #[rustfmt::skip]
    impl scx_stats::Meta for #ident {
        fn meta() -> scx_stats::StatsMeta {
            let body = #body;
            scx_stats::serde_json::from_str(body).unwrap()
        }
    }
    };
    output.extend(trait_body.into_iter());

    output.into()
}

#[proc_macro_attribute]
pub fn stat_doc(
    _attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let ident = input.ident;
    let vis = input.vis;
    let attrs = input.attrs;
    let generics = input.generics;
    let data = input.data;

    let mut output = proc_macro2::TokenStream::new();

    if let Data::Struct(data_struct) = data {
        let fields = match data_struct.fields {
            Fields::Named(fields_named) => fields_named.named,
            _ => {
                return syn::Error::new_spanned(
                    ident,
                    "stat attribute can only be used on structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        };

        let mut new_fields = Vec::new();

        for mut field in fields {
            let mut doc_string = None;
            let mut new_attrs = Vec::new();

            for attr in field.attrs.clone() {
                if attr.path().is_ident("stat") {
                    // Parse the arguments within #[stat(...)]
                    attr.parse_nested_meta(|meta| {
                        if meta.path.is_ident("desc") {
                            // Extract the literal string value from `desc`
                            let desc_literal: Lit = meta.value()?.parse()?;
                            if let Lit::Str(lit_str) = desc_literal {
                                doc_string = Some(lit_str.value());
                            }
                        }
                        Ok(())
                    })
                    .unwrap_or_else(|err| {
                        panic!("Failed to parse the stat attribute: {}", err);
                    });
                }
                new_attrs.push(attr);
            }

            // If a description string was found, add a #[doc = "..."] attribute
            if let Some(description) = doc_string {
                let doc_attr = Attribute {
                    pound_token: syn::token::Pound::default(),
                    style: syn::AttrStyle::Outer,
                    bracket_token: syn::token::Bracket::default(),
                    meta: syn::Meta::NameValue(syn::MetaNameValue {
                        path: syn::Path::from(format_ident!("doc")),
                        eq_token: syn::token::Eq::default(),
                        value: syn::Expr::Lit(syn::ExprLit {
                            lit: Lit::Str(syn::LitStr::new(&description, field.span())),
                            attrs: vec![],
                        }),
                    }),
                };
                new_attrs.push(doc_attr);
            }

            field.attrs = new_attrs;
            new_fields.push(field);
        }

        // Rebuild the struct with the modified fields
        let struct_def = quote! {
            #(#attrs)*
            #vis struct #ident #generics {
                #(#new_fields),*
            }
        };

        output.extend(struct_def);
        return output.into();
    }

    // If not a struct with named fields, return an error
    syn::Error::new_spanned(
        ident,
        "stat attribute can only be used on structs with named fields",
    )
    .to_compile_error()
    .into()
}
