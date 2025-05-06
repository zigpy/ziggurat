use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::Ident;
use syn::spanned::Spanned;

use crate::model::NormalField;

use super::{is_primitive, list_len_ident};

pub fn padding_field_code(n_bits: u8) -> TokenStream {
    let n_bits = proc_macro2::Literal::usize_suffixed(n_bits as usize);
    quote! { writer.skip(#n_bits); }
}

pub fn normal_field_code(
    NormalField {
        ident,
        out_ty,
        bits,
        ..
    }: &NormalField,
) -> TokenStream {
    if let Some(bits) = *bits {
        let utype: syn::Type =
            syn::parse_str(&format!("::wire_format::u{bits}")).expect("should be valid type path");
        quote_spanned! {out_ty.span()=>
            let #ident = #utype::new(self.#ident);
            #ident.write_zigbee_bytes(writer)?;
        }
    } else {
        quote_spanned! {out_ty.span()=>
            self.#ident.write_zigbee_bytes(writer)?;
        }
    }
}

pub fn option_field_code(field: &NormalField) -> TokenStream {
    let field_ident = &field.ident;
    let write_code = if let Some(bits) = field.bits {
        let utype: syn::Type =
            syn::parse_str(&format!("::wire_format::u{bits}")).expect("should be valid type path");
        quote_spanned! {field.out_ty.span()=>
            let #field_ident = #utype::new(#field_ident);
            #field_ident.write_zigbee_bytes(writer)?;
        }
    } else {
        quote_spanned! {field.out_ty.span()=>
            #field_ident.write_zigbee_bytes(writer)?;
        }
    };

    quote_spanned!(field_ident.span()=>
        if let Some(ref #field_ident) = self.#field_ident {
            #write_code
        }
    )
}

pub fn control_option_code(controlled: &Ident) -> TokenStream {
    quote_spanned! {controlled.span()=>
        if self.#controlled.is_some() {
            true.write_zigbee_bytes(writer)?;
        } else {
            false.write_zigbee_bytes(writer)?;
        }
    }
}

pub fn control_list_code(controlled: &Ident, bits: usize) -> TokenStream {
    let len_ident = list_len_ident(controlled);
    if let Some(ty) = is_primitive(bits) {
        quote_spanned! {controlled.span()=>
            let #len_ident: #ty = self.#controlled.len().try_into()
                .map_err(|_| ::wire_format::ToBytesError::ListTooLong {
                    max: #ty::MAX as usize,
                    got: self.#controlled.len(),
            })?;
            ::wire_format::ZigbeeBytes::write_zigbee_bytes(&#len_ident, writer)?;
        }
    } else {
        let utype: syn::Type =
            syn::parse_str(&format!("::wire_format::u{bits}")).expect("valid type path");
        quote_spanned! {controlled.span()=>
            let #len_ident = #utype::new(self.#controlled.len().try_into()
                .map_err(|_| ::wire_format::ToBytesError::ListTooLong {
                    max: 2usize.pow(#utype::BITS as u32) - 1,
                    got: self.#controlled.len(),
                })?);
            ::wire_format::ZigbeeBytes::write_zigbee_bytes(&#len_ident, writer)?;
        }
    }
}

pub(crate) fn enum_code(repr: Ident, bits: usize) -> TokenStream {
    if is_primitive(bits).is_some() {
        quote_spanned! {repr.span()=>
            ::wire_format::ZigbeeBytes::write_zigbee_bytes(&(*self as #repr), writer)
        }
    } else {
        let utype: syn::Type =
            syn::parse_str(&format!("::wire_format::u{bits}")).expect("valid type path");
        quote_spanned! {repr.span()=>
            let discriminant = #utype::new(*self as #repr);
            ::wire_format::ZigbeeBytes::write_zigbee_bytes(&discriminant, writer)
        }
    }
}

pub(crate) fn list_field_code(inner_type: &NormalField) -> TokenStream {
    let field_ident = &inner_type.ident;
    quote_spanned! {field_ident.span()=>
        for element in &self.#field_ident {
            ::wire_format::ZigbeeBytes::write_zigbee_bytes(element, writer)?;
        }
    }
}
