use proc_macro_error2::{OptionExt, abort};
use proc_macro2::{Span, TokenStream, TokenTree};
use syn::parse_quote_spanned;
use syn::spanned::Spanned;
use syn::{Attribute, GenericArgument, Ident, PathArguments, Visibility};

pub struct Model {
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub ident: Ident,
    pub ty: Type,
}

pub struct EmptyVariant {
    pub ident: Ident,
    pub discriminant: usize,
}

pub enum Type {
    NormalStruct(Vec<Field>),
    UnitStruct(syn::Field),
    Enum {
        bits: usize,
        variants: Vec<EmptyVariant>,
        // Extracted as Ident from parsed AST, no reason to change that
        repr_type: Ident,
    },
}

#[derive(Debug)]
pub struct NormalField {
    pub vis: Visibility,
    pub ident: Ident,
    pub out_ty: syn::Type,
    pub bits: Option<u8>,
}

fn out_ty_from_padding(padding: u8, span: Span) -> syn::Type {
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
    Normal(NormalField),
    Option {
        full_type: NormalField,
        inner_type: NormalField,
    },
    List {
        full_type: NormalField,
        inner_type: NormalField,
    },
    ControlList {
        controlled: Ident,
        bits: usize,
    },
    ControlOption(Ident),
    PaddBits(u8),
}

impl Field {
    pub fn option_stripped(&self) -> Option<&NormalField> {
        match self {
            Field::Option {
                inner_type: field, ..
            } => Some(field),
            _ => None,
        }
    }

    pub fn needed_in_struct_def(&self) -> Option<&NormalField> {
        match self {
            Field::Normal(field)
            | Field::Option { full_type: field, .. }
            | Field::List { full_type: field, .. } => Some(field),
            _ => None,
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

impl Field {
    fn from(field: syn::Field) -> Self {
        match &field.ident {
            Some(ident) if *ident == "reserved" => {
                if let Some(option_ident) = controls_option(&field) {
                    Self::ControlOption(option_ident)
                } else if let Some(list_ident) = controls_list(&field) {
                    let bits = padding_from_type(&field.ty)
                        .unwrap_or_else(|(msg, span)| abort!(span, msg));
                    Self::ControlList {
                        controlled: list_ident,
                        bits: bits as usize,
                    }
                } else {
                    let padding = padding_from_type(&field.ty)
                        .unwrap_or_else(|(msg, span)| abort!(span, msg));
                    Self::PaddBits(padding)
                }
            }
            Some(_) => {
                if let Some(option_stripped) = strip_option(field.clone()) {
                    Self::Option {
                        inner_type: NormalField::from(option_stripped),
                        full_type: NormalField::from(field),
                    }
                } else if let Some(vec_stripped) = strip_vec(field.clone()) {
                    Self::List {
                        inner_type: NormalField::from(vec_stripped),
                        full_type: NormalField::from(field),
                    }
                } else {
                    Self::Normal(NormalField::from(field))
                }
            }
            None => unreachable!("unit structs are not tranformed into model::Field"),
        }
    }
}

fn strip_vec(field: syn::Field) -> Option<syn::Field> {
    strip_generic(field, "Vec")
}

fn strip_option(field: syn::Field) -> Option<syn::Field> {
    strip_generic(field, "Option")
}

fn strip_generic(field: syn::Field, outer_ident: &str) -> Option<syn::Field> {
    let syn::Type::Path(path) = &field.ty else {
        return None;
    };

    let ty = &path.path.segments.first()?;
    if ty.ident != outer_ident {
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
    fn parse(attr: &Attribute) -> Option<Result<Ident, ()>> {
        let Ok(list) = attr.meta.require_list() else {
            return Some(Err(()));
        };
        let mut tokens = list.tokens.clone().into_iter();
        match tokens.next() {
            Some(TokenTree::Ident(ident)) if ident == "controls" => (),
            _ => return None,
        }
        match tokens.next() {
            Some(TokenTree::Punct(punct)) if punct.as_char() == '=' => (),
            _ => return Some(Err(())),
        }
        let Some(TokenTree::Ident(target_field)) = tokens.next() else {
            return Some(Err(()));
        };
        Some(Ok(target_field))
    }

    let attr = field
        .attrs
        .iter()
        .find(|a| a.path().is_ident("wire_format"))?;

    match parse(attr)? {
        Ok(ident) => Some(ident),
        Err(_) => abort!(attr.span(), "invalid wire_format attribute"; 
            help = "The syntax is: #[wire_format(controls = <ident>)] with ident \
            a later option type field"),
    }
}

fn controls_list(field: &syn::Field) -> Option<Ident> {
    fn parse(attr: &Attribute) -> Result<Ident, ()> {
        let Ok(list) = attr.meta.require_list() else {
            return Err(());
        };
        let mut tokens = list.tokens.clone().into_iter();
        match tokens.next() {
            Some(TokenTree::Ident(ident)) if ident == "length_of" => (),
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
            help = "The syntax is: #[wire_format(length_of = <ident>)] with ident \
            a later option type field"),
    }
}

impl Model {
    fn reject_item_generics(generics: &syn::Generics) {
        assert!(generics.lifetimes().count() == 0, "lifetimes not supported");
        assert!(
            generics.const_params().count() == 0,
            "const params not supported"
        );
        assert!(
            generics.type_params().count() == 0,
            "generic types not supported"
        );
    }

    pub(crate) fn from_enum(item: syn::ItemEnum, attr: TokenStream) -> Self {
        let Ok(bits) = get_num_bits(attr) else {
            abort!(item.span(), "Every enum must be attributed with its serialized size \
                in bits."; note = "Example: #[wire_format::zigbee_bytes(bits=2)]");
        };
        Self::reject_item_generics(&item.generics);

        let repr = require_repr_attr(&item.attrs, item.span());
        let variants: Vec<_> = item
            .variants
            .clone()
            .into_iter()
            .map(|v| EmptyVariant {
                ident: v.ident,
                discriminant: require_usize(
                    v.discriminant
                        .clone()
                        .unwrap_or_else(|| {
                            abort!(item.span(), "Every enum variant must have an explicit \
                    discriminant value"; 
                    note = "Assign a discriminant with = <number>")
                        })
                        .1,
                ),
            })
            .collect();
        verify_all_discriminants_fit(&variants, bits);

        let ty = Type::Enum {
            bits,
            variants,
            repr_type: repr,
        };

        Self {
            attrs: item.attrs,
            vis: item.vis,
            ident: item.ident,
            ty,
        }
    }
    pub(crate) fn from_struct(item: syn::ItemStruct, _attr: TokenStream) -> Self {
        Self::reject_item_generics(&item.generics);

        let is_unit = item
            .fields
            .iter()
            .next()
            .expect_or_abort("structs without fields are not supported")
            .ident
            .is_none();
        let ty = if is_unit {
            let field = item
                .fields
                .clone()
                .into_iter()
                .next()
                .unwrap_or_else(|| abort!(item.span(), "Zero sized struct not supported"));
            Type::UnitStruct(field)
        } else {
            let fields: Vec<_> = item.fields.into_iter().map(Field::from).collect();
            check_controlled_fields(&fields);
            Type::NormalStruct(fields)
        };

        Self {
            attrs: item.attrs,
            vis: item.vis,
            ident: item.ident,
            ty,
        }
    }
}

fn verify_all_discriminants_fit(variants: &[EmptyVariant], bits: usize) {
    let biggest = variants
        .iter()
        .max_by_key(|var| var.discriminant)
        .expect("zero size enums are not supported");
    if biggest.discriminant >= 2usize.pow(bits as u32) {
        abort!(
            biggest.ident.span(),
            "The discriminant for {} does not fit into {} bits",
            biggest.ident,
            bits
        );
    }
}

fn get_num_bits(attr: TokenStream) -> Result<usize, ()> {
    let mut tokens = attr.into_iter();
    match tokens.next() {
        Some(TokenTree::Ident(item)) if item == "bits" => (),
        _ => return Err(()),
    }

    match tokens.next() {
        Some(TokenTree::Punct(punct)) if punct.as_char() == '=' => (),
        _ => return Err(()),
    }

    let Some(TokenTree::Literal(num)) = tokens.next() else {
        return Err(());
    };

    num.to_string().parse().map_err(|_| ())
}

fn require_repr_attr(attrs: &[Attribute], span: Span) -> Ident {
    let attr = attrs
        .iter()
        .find(|a| a.path().is_ident("repr"))
        .unwrap_or_else(|| abort!(span, "enum must have repr attribute"));

    let list = attr
        .meta
        .require_list()
        .expect("we just found an attribute therefore its non empty");

    let Some(TokenTree::Ident(repr_type)) = list.tokens.clone().into_iter().next() else {
        abort!(span, "repr attribute on enum should contain repr type");
    };

    repr_type
}

fn require_usize(expr: syn::Expr) -> usize {
    if let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(d),
        ..
    }) = expr
    {
        d.base10_parse()
            .expect("only valid numbers can be enum discriminant")
    } else {
        unreachable!("only digits form a valid enum discriminant expression")
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
