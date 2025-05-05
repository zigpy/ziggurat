use proc_macro2::{Punct, Spacing, TokenStream};
use quote::{ToTokens, TokenStreamExt, quote};
use syn::{Attribute, Ident, Visibility};

use crate::model::{EmptyVariant, Field, Model};

mod read;
mod write;

pub fn codegen(model: Model) -> TokenStream {
    match model.ty {
        crate::model::Type::NormalStruct(fields) => {
            normal_struct(model.vis, model.ident, model.attrs, fields)
        }
        crate::model::Type::UnitStruct(field) => {
            unit_struct(model.vis, model.ident, model.attrs, field)
        }
        crate::model::Type::Enum {
            variants,
            repr_type: repr,
        } => normal_enum(model.vis, model.ident, model.attrs, variants, repr),
    }
}

fn normal_enum(
    vis: Visibility,
    ident: Ident,
    attrs: Vec<Attribute>,
    variants: Vec<EmptyVariant>,
    repr: Ident,
) -> TokenStream {
    let variants_discriminants = variants
        .iter()
        .map(|v| v.discriminant)
        .map(proc_macro2::Literal::usize_unsuffixed);
    let variant_idents = variants.iter().map(|v| &v.ident);

    let res = quote! {
        #(#attrs)*
        #vis enum #ident {
            #(#variants),*
        }

        #[automatically_derived]
        impl ::wire_format::ZigbeeBytes for #ident {
            fn needed_bits(&self) -> usize {
                todo!()
            }
            fn write_zigbee_bytes(&self, writer: &mut ::wire_format::BitWriter)
            -> Result<(), ::wire_format::ToBytesError> {
                ::wire_format::ZigbeeBytes::write_zigbee_bytes(&(*self as #repr), writer)
            }
            fn read_zigbee_bytes(reader: &mut ::wire_format::BitReader)
            -> Result<Self, ::wire_format::FromBytesError>
            where
                Self: Sized
            {
                let discriminant = #repr::read_zigbee_bytes(reader)?;
                match discriminant {
                    #(#variants_discriminants => Ok(#ident::#variant_idents)),*,
                    invalid => Err(::wire_format::FromBytesError::InvalidDiscriminant {
                        ty: std::any::type_name::<Self>(),
                        got: discriminant as usize,
                    }),
                }
            }
        }
    };
    eprintln!("{}", res);
    res
}

fn unit_struct(
    vis: Visibility,
    ident: Ident,
    attrs: Vec<Attribute>,
    field: syn::Field,
) -> TokenStream {
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
    vis: Visibility,
    ident: Ident,
    attrs: Vec<Attribute>,
    fields: Vec<Field>,
) -> TokenStream {
    let struct_fields: Vec<_> = fields
        .iter()
        .filter_map(Field::needed_in_struct_def)
        .collect();
    let write_code: Vec<_> = fields
        .iter()
        .map(|field| match field {
            Field::Normal(normal_field) => write::normal_field_code(normal_field),
            Field::PaddBits(in_type) => write::padding_field_code(*in_type),
            Field::ControlOption(controlled) => write::control_field_code(controlled),
            Field::Option {
                option_stripped, ..
            } => write::option_field_code(option_stripped),
        })
        .collect();
    let read_code: Vec<_> = fields
        .iter()
        .map(|field| match field {
            Field::Normal(normal_field) => read::normal_field_code(normal_field),
            Field::PaddBits(n_bits) => read::padding_field_code(*n_bits),
            Field::ControlOption(ident) => read::control_field_code(ident),
            Field::Option {
                option_stripped, ..
            } => read::option_field_code(option_stripped),
        })
        .collect();
    let out_struct_idents: Vec<_> = fields
        .iter()
        .filter_map(Field::needed_in_struct_def)
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

impl ToTokens for super::model::NormalField {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.vis.to_tokens(tokens);

        self.ident.to_tokens(tokens);
        tokens.append(Punct::new(':', Spacing::Joint));

        self.out_ty.to_tokens(tokens);
    }
}

impl ToTokens for super::model::EmptyVariant {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.ident.to_tokens(tokens);
        tokens.append(Punct::new('=', Spacing::Joint));

        proc_macro2::Literal::usize_unsuffixed(self.discriminant).to_tokens(tokens)
    }
}
