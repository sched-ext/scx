use quote::{format_ident, quote, quote_spanned};
use scx_stats::{StatsData, StatsKind, StatsMetaAux};
use std::sync::atomic::{AtomicU64, Ordering};
use syn::parse_macro_input;
use syn::spanned::Spanned;

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
