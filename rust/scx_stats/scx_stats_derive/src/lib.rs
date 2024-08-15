use quote::{format_ident, quote, quote_spanned};
use scx_stats::{ScxStatsData, ScxStatsKind, ScxStatsMetaAux};
use syn::parse_macro_input;
use syn::spanned::Spanned;

#[proc_macro_derive(Stats, attributes(stat))]
pub fn stat(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let stats_aux = parse_macro_input!(input as ScxStatsMetaAux);
    let (meta, ident, paths) = (stats_aux.meta, stats_aux.ident, stats_aux.paths);

    let mut output = proc_macro2::TokenStream::new();

    for (idx, field) in meta.fields.iter().enumerate() {
        match &field.data {
            ScxStatsData::Datum(datum)
            | ScxStatsData::Array(datum)
            | ScxStatsData::Dict { key: _, datum } => {
                if let ScxStatsKind::Struct(name) = &datum {
                    let path = &paths[name.as_str()];
                    let assert_id = format_ident!("_AssertScxStatsMeta_{}", idx);
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
        fn meta() -> scx_stats::ScxStatsMeta {
            let body = #body;
            scx_stats::serde_json::from_str(body).unwrap()
        }
    }
    };
    output.extend(trait_body.into_iter());

    output.into()
}
