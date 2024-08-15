use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use syn::parse::{Parse, ParseBuffer};
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Field, Fields, GenericArgument, Ident, ItemStruct, LitStr, Path,
    PathArguments, Token, Type, TypePath,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ScxStatsKind {
    I64,
    U64,
    Float,
    String,
    Struct(String),
}

impl ScxStatsKind {
    pub fn new(ty: &Type, paths: &mut BTreeMap<String, Path>) -> syn::Result<Self> {
        match ty {
            Type::Reference(reference) => return Self::new(&reference.elem, paths),
            Type::Path(TypePath { qself: _, path }) => {
                if let Some(ident) = path.get_ident() {
                    match ident.to_string().as_str() {
                        "String" | "str" => return Ok(Self::String),
                        "i8" | "i16" | "i32" | "i64" | "isize" => return Ok(Self::I64),
                        "u8" | "u16" | "u32" | "u64" | "usize" => return Ok(Self::U64),
                        "f32" | "f64" => return Ok(Self::Float),
                        _ => {}
                    }
                }
                let name = path.to_token_stream().to_string();
                paths.insert(name.to_string(), path.clone());
                return Ok(Self::Struct(name));
            }
            _ => {}
        }
        Err(Error::new(ty.span(), "ScxStats: Unsupported element type"))
    }

    pub fn can_be_dict_key(&self) -> bool {
        match self {
            Self::I64 | Self::U64 | Self::String => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ScxStatsData {
    #[serde(rename = "datum")]
    Datum(ScxStatsKind),
    #[serde(rename = "array")]
    Array(ScxStatsKind),
    #[serde(rename = "dict")]
    Dict {
        key: ScxStatsKind,
        datum: ScxStatsKind,
    },
}

impl ScxStatsData {
    fn new_array(path: &Path, paths: &mut BTreeMap<String, Path>) -> syn::Result<Option<Self>> {
        if path.leading_colon.is_some() {
            return Ok(None);
        }

        let is_vec = match path.segments.len() {
            1 => path.segments[0].ident == "Vec",
            3 => {
                path.segments[0].ident == "std"
                    && path.segments[1].ident == "vec"
                    && path.segments[2].ident == "Vec"
            }
            _ => false,
        };

        if !is_vec {
            return Ok(None);
        }

        if let PathArguments::AngleBracketed(ab) = &path.segments.last().unwrap().arguments {
            let args = &ab.args;
            if args.len() < 1 {
                return Err(Error::new(args.span(), "T generic argument missing"));
            }

            match &args[0] {
                GenericArgument::Type(ty) => Ok(Some(Self::Array(ScxStatsKind::new(&ty, paths)?))),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    fn new_dict(path: &Path, paths: &mut BTreeMap<String, Path>) -> syn::Result<Option<Self>> {
        if path.leading_colon.is_some() {
            return Ok(None);
        }

        let is_btree_map = match path.segments.len() {
            1 => path.segments[0].ident == "BTreeMap",
            3 => {
                path.segments[0].ident == "std"
                    && path.segments[1].ident == "collections"
                    && path.segments[2].ident == "BTreeMap"
            }
            _ => false,
        };

        if !is_btree_map {
            return Ok(None);
        }

        if let PathArguments::AngleBracketed(ab) = &path.segments.last().unwrap().arguments {
            let args = &ab.args;
            if args.len() < 2 {
                return Err(Error::new(args.span(), "K, V generic arguments missing"));
            }

            match (&args[0], &args[1]) {
                (GenericArgument::Type(ty0), GenericArgument::Type(ty1)) => {
                    let kind0 = ScxStatsKind::new(&ty0, paths)?;
                    let kind1 = ScxStatsKind::new(&ty1, paths)?;

                    if kind0.can_be_dict_key() {
                        Ok(Some(Self::Dict {
                            key: kind0,
                            datum: kind1,
                        }))
                    } else {
                        Err(Error::new(ty0.span(), "K must be an integer or String"))
                    }
                }
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    pub fn new(ty: &Type, paths: &mut BTreeMap<String, Path>) -> syn::Result<Self> {
        let kind = ScxStatsKind::new(ty, paths)?;
        if let ScxStatsKind::Struct(_) = &kind {
            if let Type::Path(path) = ty {
                if let Some(ar) = Self::new_array(&path.path, paths)? {
                    return Ok(ar);
                }
                if let Some(dict) = Self::new_dict(&path.path, paths)? {
                    return Ok(dict);
                }
            }
        }
        Ok(Self::Datum(kind))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ScxStatsAttr {
    Desc(String),
    OMPrefix(String),
}

struct ScxStatsAttrVec {
    attrs: Vec<ScxStatsAttr>,
}

impl Parse for ScxStatsAttrVec {
    fn parse(input: &ParseBuffer) -> syn::Result<Self> {
        let mut attrs = vec![];
        loop {
            let ident = input.parse::<Ident>()?;
            match ident.to_string().as_str() {
                "desc" => {
                    input.parse::<Token!(=)>()?;
                    attrs.push(ScxStatsAttr::Desc(input.parse::<LitStr>()?.value()))
                }
                "om_prefix" => {
                    input.parse::<Token!(=)>()?;
                    attrs.push(ScxStatsAttr::OMPrefix(input.parse::<LitStr>()?.value()))
                }
                _ => Err(Error::new(ident.span(), "Unknown attribute"))?,
            }
            if !input.is_empty() {
                input.parse::<Token!(,)>()?;
            }
            if input.is_empty() {
                break;
            }
        }
        Ok(Self { attrs })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScxStatsAttrs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub om_prefix: Option<String>,
}

impl ScxStatsAttrs {
    pub fn new(attrs: &[Attribute]) -> syn::Result<Self> {
        let mut sattrs: Self = Self::default();

        for attr in attrs {
            if attr.path().is_ident("stat") {
		let vec = attr.parse_args::<ScxStatsAttrVec>()?;
		for attr in vec.attrs.into_iter() {
                    match attr {
			ScxStatsAttr::Desc(v) => sattrs.desc = Some(v),
			ScxStatsAttr::OMPrefix(v) => sattrs.om_prefix = Some(v),
                    }
		}
            }
        }

        Ok(sattrs)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScxStatsField {
    pub name: String,
    #[serde(flatten)]
    pub data: ScxStatsData,
    #[serde(flatten)]
    pub attrs: ScxStatsAttrs,
}

impl ScxStatsField {
    pub fn new(field: &Field, paths: &mut BTreeMap<String, Path>) -> syn::Result<Self> {
        Ok(Self {
            name: field.ident.as_ref().unwrap().to_string(),
            data: ScxStatsData::new(&field.ty, paths)?,
            attrs: ScxStatsAttrs::new(&field.attrs)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScxStatsMeta {
    pub name: String,
    pub desc: Option<String>,
    pub fields: Vec<ScxStatsField>,
}

#[derive(Clone, Debug)]
pub struct ScxStatsMetaAux {
    pub meta: ScxStatsMeta,
    pub ident: Ident,
    pub paths: BTreeMap<String, Path>,
}

impl Parse for ScxStatsMetaAux {
    fn parse(input: &ParseBuffer) -> syn::Result<Self> {
        let mut paths = BTreeMap::new();
        let mut fields = vec![];

        let item_struct: ItemStruct = input.parse()?;
        let attrs = ScxStatsAttrs::new(&item_struct.attrs)?;

        if let Fields::Named(named_fields) = &item_struct.fields {
            for field in named_fields.named.iter() {
                fields.push(ScxStatsField::new(field, &mut paths)?);
            }
        }

        Ok(Self {
            meta: ScxStatsMeta {
                name: item_struct.ident.to_string(),
                desc: attrs.desc,
                fields,
            },
            ident: item_struct.ident,
            paths,
        })
    }
}

pub trait Meta {
    fn meta() -> ScxStatsMeta;
}
