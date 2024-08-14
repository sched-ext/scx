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
pub enum ScxStatKind {
    I64,
    U64,
    Float,
    String,
    Struct(String),
}

impl ScxStatKind {
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
        Err(Error::new(ty.span(), "ScxStat: Unsupported element type"))
    }

    pub fn can_be_dict_key(&self) -> bool {
        match self {
            Self::I64 | Self::U64 | Self::String => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ScxStatData {
    #[serde(rename = "datum")]
    Datum(ScxStatKind),
    #[serde(rename = "array")]
    Array(ScxStatKind),
    #[serde(rename = "dict")]
    Dict {
        key: ScxStatKind,
        datum: ScxStatKind,
    },
}

impl ScxStatData {
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
                GenericArgument::Type(ty) => Ok(Some(Self::Array(ScxStatKind::new(&ty, paths)?))),
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
                    let kind0 = ScxStatKind::new(&ty0, paths)?;
                    let kind1 = ScxStatKind::new(&ty1, paths)?;

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
        let kind = ScxStatKind::new(ty, paths)?;
        if let ScxStatKind::Struct(_) = &kind {
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
pub enum ScxStatAttr {
    Desc(String),
}

impl Parse for ScxStatAttr {
    fn parse(input: &ParseBuffer) -> syn::Result<Self> {
        let ident = input.parse::<Ident>()?;
        match ident.to_string().as_str() {
            "desc" => {
                input.parse::<Token!(=)>()?;
                Ok(Self::Desc(input.parse::<LitStr>()?.value()))
            }
            _ => Err(Error::new(ident.span(), "Unknown attribute")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScxStatAttrs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
}

impl ScxStatAttrs {
    pub fn new(attrs: &[Attribute]) -> syn::Result<Self> {
        let mut desc: Option<String> = None;

        for attr in attrs {
            if attr.path().is_ident("stat") {
                match attr.parse_args::<ScxStatAttr>()? {
                    ScxStatAttr::Desc(v) => desc = Some(v),
                }
            }
        }

        Ok(Self { desc })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScxStatField {
    pub name: String,
    #[serde(flatten)]
    pub data: ScxStatData,
    #[serde(flatten)]
    pub attrs: ScxStatAttrs,
}

impl ScxStatField {
    pub fn new(field: &Field, paths: &mut BTreeMap<String, Path>) -> syn::Result<Self> {
        Ok(Self {
            name: field.ident.as_ref().unwrap().to_string(),
            data: ScxStatData::new(&field.ty, paths)?,
            attrs: ScxStatAttrs::new(&field.attrs)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScxStatMeta {
    pub name: String,
    pub desc: Option<String>,
    pub fields: Vec<ScxStatField>,
}

#[derive(Clone, Debug)]
pub struct ScxStatMetaAux {
    pub meta: ScxStatMeta,
    pub ident: Ident,
    pub paths: BTreeMap<String, Path>,
}

impl Parse for ScxStatMetaAux {
    fn parse(input: &ParseBuffer) -> syn::Result<Self> {
        let mut paths = BTreeMap::new();
        let mut fields = vec![];

        let item_struct: ItemStruct = input.parse()?;
        let attrs = ScxStatAttrs::new(&item_struct.attrs)?;

        if let Fields::Named(named_fields) = &item_struct.fields {
            for field in named_fields.named.iter() {
                fields.push(ScxStatField::new(field, &mut paths)?);
            }
        }

        Ok(Self {
            meta: ScxStatMeta {
                name: item_struct.ident.to_string(),
                desc: attrs.desc,
                fields,
            },
            ident: item_struct.ident,
            paths,
        })
    }
}

pub trait StatMeta {
    fn stat_meta() -> ScxStatMeta;
}
