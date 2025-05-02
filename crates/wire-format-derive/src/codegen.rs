use proc_macro_error2::OptionExt;
use proc_macro2::{Punct, Spacing, TokenStream};
use quote::{ToTokens, TokenStreamExt, quote, quote_spanned};
use syn::spanned::Spanned;

use crate::model::{Field, Model, NormalField};

pub fn codegen(model: Model) -> TokenStream {
    if model.is_unit {
        unit_struct(model)
    } else {
        normal_struct(model)
    }
}

fn unit_struct(
    Model {
        vis,
        ident,
        fields,
        attrs,
        ..
    }: Model,
) -> TokenStream {
    let field = fields
        .iter()
        .map(Field::unwrap_unit)
        .next()
        .expect_or_abort("Unit structs can only have one field");
    let field_ty = &field.ty;
    quote! {
        #(#attrs)*
        #vis struct #ident(#field);

        #[automatically_derived]
        impl ::wire_format::ZigbeeBytes for #ident {
            fn needed_bits(&self) -> usize {
                self.0.needed_bits()
            }
            fn write_zigbee_bytes(&self, writer: &mut ::wire_format::BitWriter)
            -> Result<(), ::wire_format::ToBytesError> {
                self.0.write_zigbee_bytes(writer)
            }
            fn read_zigbee_bytes(reader: &mut ::wire_format::BitReader)
            -> Result<Self, ::wire_format::FromBytesError>
            where
                Self: Sized
            {
                Ok(Self(#field_ty::read_zigbee_bytes(reader)?))
            }
        }
    }
}

fn normal_struct(
    Model {
        vis,
        ident,
        fields,
        attrs,
        ..
    }: Model,
) -> TokenStream {
    let struct_fields: Vec<_> = fields.iter().filter_map(Field::normal).collect();
    let write_code: Vec<_> = fields
        .iter()
        .map(|field| match field {
            Field::Unit(_) => unreachable!("unit fields not possible in normal struct"),
            Field::Normal(normal_field) => normal_field_write_code(normal_field),
            Field::PaddBits(in_type) => padding_field_write_code(*in_type),
        })
        .collect();
    let read_code: Vec<_> = fields
        .iter()
        .map(|field| match field {
            Field::Unit(_) => unreachable!("unit fields not possible in normal struct"),
            Field::Normal(normal_field) => normal_field_read_code(normal_field),
            Field::PaddBits(n_bits) => padding_field_read_code(*n_bits),
        })
        .collect();
    let out_struct_idents: Vec<_> = fields
        .iter()
        .filter_map(Field::normal)
        .map(|f| &f.ident)
        .collect();

    quote! {
        #(#attrs)*
        #vis struct #ident {
            #(#struct_fields),*
        }

        #[automatically_derived]
        impl ::wire_format::ZigbeeBytes for #ident {
            fn needed_bits(&self) -> usize {
                todo!()
            }
            fn write_zigbee_bytes(&self, writer: &mut ::wire_format::BitWriter)
            -> Result<(), ::wire_format::ToBytesError> {
                #(#write_code)*
                Ok(())
            }
            fn read_zigbee_bytes(reader: &mut ::wire_format::BitReader)
            -> Result<Self, ::wire_format::FromBytesError>
            where
                Self: Sized
            {
                #(#read_code)*
                Ok(Self {
                    #(#out_struct_idents),*
                })
            }
        }
    }
}

fn padding_field_write_code(n_bits: u8) -> TokenStream {
    let n_bits = proc_macro2::Literal::usize_suffixed(n_bits as usize);
    quote! { writer.skip(#n_bits); }
}

//

fn normal_field_write_code(
    NormalField {
        ident,
        out_ty,
        bits,
        ..
    }: &NormalField,
) -> TokenStream {
    if let Some(bits) = bits {
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

fn padding_field_read_code(n_bits: u8) -> TokenStream {
    let n_bits = proc_macro2::Literal::usize_suffixed(n_bits as usize);
    quote! { reader.skip(#n_bits); }
}

fn normal_field_read_code(
    NormalField {
        ident,
        out_ty,
        bits,
        ..
    }: &NormalField,
) -> TokenStream {
    if let Some(bits) = bits {
        let utype: syn::Type =
            syn::parse_str(&format!("::wire_format::u{bits}")).expect("should be valid type path");
        quote_spanned! {out_ty.span()=>
            let #ident = #utype::read_zigbee_bytes(reader)?;
            let #ident = #ident.value();
        }
    } else {
        let out_ty = generics_to_fully_qualified(out_ty.clone());
        quote_spanned! {out_ty.span()=>
            let #ident = #out_ty::read_zigbee_bytes(reader)?;
        }
    }
}

/// Turns `Type<T>` into `Type::<T>` which is needed for 
/// `Type::<T>::read_zigbee_bytes(reader)`
fn generics_to_fully_qualified(mut ty: syn::Type) -> syn::Type {
    if let syn::Type::Path(typath) = &mut ty {
        let syn::Path { segments, .. } = &mut typath.path;
        let first_seg = segments.first_mut().expect("type path always has at least one segment");
        let syn::PathArguments::AngleBracketed(args) = &mut first_seg.arguments else {
            return ty;
        };

        args.colon2_token = Some(syn::Token![::](args.span()));
    }
    ty
}

impl ToTokens for super::model::NormalField {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.vis.to_tokens(tokens);

        self.ident.to_tokens(tokens);
        tokens.append(Punct::new(':', Spacing::Joint));

        self.out_ty.to_tokens(tokens);
    }
}
