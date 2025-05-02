use proc_macro_error2::{OptionExt, abort};
use proc_macro2::{Span, TokenStream};
use syn::parse_quote_spanned;
use syn::spanned::Spanned;
use syn::{Attribute, Ident, ItemStruct, Type, Visibility};

pub struct Model {
    pub is_unit: bool,
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub ident: Ident,
    pub fields: Vec<Field>,
}

#[derive(Debug)]
pub struct NormalField {
    pub vis: Visibility,
    pub ident: Ident,
    pub out_ty: Type,
    pub bits: Option<u8>,
}

fn out_ty_from_padding(padding: u8, span: Span) -> Type {
    match padding {
        1..=8 => parse_quote_spanned!(span =>u8),
        9..=16 => parse_quote_spanned!(span =>u16),
        17..=32 => parse_quote_spanned!(span =>u32),
        33..=64 => parse_quote_spanned!(span =>u64),
        _other => abort!(span, "unsupported field size"),
    }
}

impl From<syn::Field> for NormalField {
    fn from(field: syn::Field) -> Self {
        let bits;
        let out_ty;
        if let Ok(padding) = padding_from_type(&field.ty) {
            out_ty = out_ty_from_padding(padding, field.ty.span());
            bits = Some(padding);
        } else {
            out_ty = field.ty;
            bits = None;
        };

        NormalField {
            vis: field.vis,
            ident: field.ident.expect("unit struct not handled by NormalField"),
            out_ty,
            bits,
        }
    }
}

#[derive(Debug)]
pub enum Field {
    Unit(syn::Field),
    Normal(NormalField),
    PaddBits(u8),
}

impl Field {
    pub fn normal(&self) -> Option<&NormalField> {
        match self {
            Field::Normal(field) => Some(field),
            _ => None,
        }
    }
    pub fn unwrap_unit(&self) -> &syn::Field {
        match self {
            Field::Unit(field) => field,
            _ => panic!("can not unwrap a not unit Field as unit, field: {self:?}"),
        }
    }
}

fn padding_from_type(ty: &syn::Type) -> Result<u8, (&'static str, Span)> {
    let syn::Type::Path(ty) = ty else {
        abort!(ty.span(), "only normal types are supported");
    };

    let end = ty.path.segments.last().expect("type can not be empty");
    match end.ident.to_string().trim_start_matches("u").parse() {
        Ok(padding) => Ok(padding),
        Err(_) => Err((
            "field did not start with u and/or did not end in number",
            end.ident.span(),
        )),
    }
}

impl From<syn::Field> for Field {
    fn from(field: syn::Field) -> Self {
        match field.ident {
            Some(ident) if ident.to_string() == "reserved" => Self::PaddBits(
                padding_from_type(&field.ty)
                .unwrap_or_else(|(msg, span)| abort!(span, msg)),
            ),
            Some(_) => Self::Normal(NormalField::from(field)),
            None => Self::Unit(field),
        }
    }
}

impl Model {
    pub(crate) fn try_from(item: ItemStruct, _attr: TokenStream) -> Self {
        assert!(
            item.generics.lifetimes().count() == 0,
            "lifetimes not supported"
        );
        assert!(
            item.generics.const_params().count() == 0,
            "const params not supported"
        );
        assert!(
            item.generics.type_params().count() == 0,
            "generic types not supported"
        );

        Self {
            is_unit: item
                .fields
                .iter()
                .next()
                .expect_or_abort("structs without fields are not supported")
                .ident
                .is_none(),
            attrs: item.attrs,
            vis: item.vis,
            ident: item.ident,
            fields: item.fields.into_iter().map(Field::from).collect(),
        }
    }
}
