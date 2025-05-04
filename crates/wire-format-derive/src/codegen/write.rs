use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::Ident;
use syn::spanned::Spanned;

use crate::model::NormalField;

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

pub fn control_field_code(controlled: &Ident) -> TokenStream {
    quote_spanned! {controlled.span()=>
        if self.#controlled.is_some() {
            true.write_zigbee_bytes(writer)?;
        } else {
            false.write_zigbee_bytes(writer)?;
        }
    }
}
