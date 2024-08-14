use quote::{format_ident, quote, quote_spanned};
use scx_stat::{ScxStatData, ScxStatKind, ScxStatMetaAux};
use syn::parse_macro_input;
use syn::spanned::Spanned;

#[proc_macro_derive(Stat, attributes(stat))]
pub fn stat(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let stat_aux = parse_macro_input!(input as ScxStatMetaAux);
    let (meta, ident, paths) = (stat_aux.meta, stat_aux.ident, stat_aux.paths);

    let mut output = proc_macro2::TokenStream::new();

    for (idx, field) in meta.fields.iter().enumerate() {
        match &field.data {
            ScxStatData::Datum(datum)
            | ScxStatData::Array(datum)
            | ScxStatData::Dict { key: _, datum } => {
                if let ScxStatKind::Struct(name) = &datum {
                    let path = &paths[name.as_str()];
                    let assert_id = format_ident!("_AssertScxStatMeta_{}", idx);
                    #[rustfmt::skip]
                    let assert = quote_spanned! {path.span()=>
                          struct #assert_id where #path: scx_stat::StatMeta;
                    };
                    output.extend(assert.into_iter());
                }
            }
        }
    }

    let body = serde_json::to_string(&meta).unwrap();
    let trait_body = quote! {
    #[rustfmt::skip]
    impl scx_stat::StatMeta for #ident {
        fn stat_meta() -> scx_stat::ScxStatMeta {
            let body = #body;
            scx_stat::serde_json::from_str(body).unwrap()
        }
    }
    };
    output.extend(trait_body.into_iter());

    output.into()
}
