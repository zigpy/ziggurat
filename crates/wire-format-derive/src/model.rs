use proc_macro_error2::{OptionExt, abort};
use proc_macro2::{Span, TokenStream, TokenTree};
use syn::parse_quote_spanned;
use syn::spanned::Spanned;
use syn::{Attribute, Ident, ItemStruct, Type, Visibility, PathArguments, GenericArgument};

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

impl NormalField {
    fn from(field: syn::Field) -> Self {
        let mut bits = None;
        let mut out_ty = field.ty.clone();
        if let Ok(padding) = padding_from_type(&field.ty) {
            if padding != 8 && padding != 16 && padding != 32 && padding != 64 {
                out_ty = out_ty_from_padding(padding, field.ty.span());
                bits = Some(padding);
            }
        }

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
    Option{
        option_stripped: NormalField,
        option_present: NormalField,
    },
    ControlOption(Ident),
    PaddBits(u8),
}

impl Field {
    pub fn option_stripped(&self) -> Option<&NormalField> {
        match self {
            Field::Option{option_stripped: field, ..} => Some(field),
            _ => None,
        }
    }

    pub fn needed_in_struct_def(&self) -> Option<&NormalField> {
        match self {
            Field::Normal(field) | Field::Option{option_present: field, ..} => Some(field),
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
        match &field.ident {
            Some(ident) if ident.to_string() == "reserved" => {
                if let Some(option_ident) = controls_option(&field) {
                    Self::ControlOption(option_ident)
                } else {
                    let padding = padding_from_type(&field.ty)
                        .unwrap_or_else(|(msg, span)| abort!(span, msg));
                    Self::PaddBits(padding)
                }
            }
            Some(_) => if let Some(option_stripped) = strip_option(field.clone()) {
                Self::Option{option_stripped: NormalField::from(option_stripped), option_present: NormalField::from(field)}
            } else {
                Self::Normal(NormalField::from(field))
            }
            None => Self::Unit(field),
        }
    }
}

fn strip_option(field: syn::Field) -> Option<syn::Field> {
    let Type::Path(path) = &field.ty else {
        return None;
    };

    let ty = &path.path.segments.first()?;
    if ty.ident.to_string() != "Option" {
        return None;
    }
    
    let PathArguments::AngleBracketed(generics) = &ty.arguments else {
        return None;
    };

    let Some(GenericArgument::Type(inner_type)) = generics.args.first() else {
        return None;
    };

    let mut new_field = field.clone();
    new_field.ty = inner_type.clone();
    Some(new_field)
}

fn controls_option(field: &syn::Field) -> Option<Ident> {
    fn parse(attr: &Attribute) -> Result<Ident, ()> {
        let Ok(list) = attr.meta.require_list() else {
            return Err(());
        };
        let mut tokens = list.tokens.clone().into_iter();
        match tokens.next() {
            Some(TokenTree::Ident(ident)) if ident.to_string() == "controls" => (),
            _ => return Err(()),
        }
        match tokens.next() {
            Some(TokenTree::Punct(punct)) if punct.as_char() == '=' => (),
            _ => return Err(()),
        }
        let Some(TokenTree::Ident(target_field)) = tokens.next() else {
            return Err(());
        };
        Ok(target_field)
    }

    let attr = field
        .attrs
        .iter()
        .find(|a| a.path().is_ident("wire_format"))?;

    match parse(attr) {
        Ok(ident) => Some(ident),
        Err(_) => abort!(attr.span(), "invalid wire_format attribute"; 
            help = "The syntax is: #[wire_format(controls = <ident>)] with ident \
            a later option type field"),
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

        let is_unit = item
            .fields
            .iter()
            .next()
            .expect_or_abort("structs without fields are not supported")
            .ident
            .is_none();
        let fields: Vec<_> = item.fields.into_iter().map(Field::from).collect();
        check_controlled_fields(&fields);

        Self {
            is_unit,
            attrs: item.attrs,
            vis: item.vis,
            ident: item.ident,
            fields,
        }
    }
}

fn check_controlled_fields(fields: &[Field]) {
    for field in fields {
        if let Field::ControlOption(controlled) = field {
            if !fields
                .iter()
                .filter_map(Field::option_stripped)
                .any(|f| f.ident == *controlled)
            {
                abort!(controlled.span(), "No field {} to be controlled by this annotated \
                    field", controlled; note = "The field being controlled must follow \
                    the boolean (bitfield) controlling it.")
            }
        }
    }
}
