use proc_macro_error2::OptionExt;
use proc_macro2::{Punct, Spacing, TokenStream};
use quote::{ToTokens, TokenStreamExt, quote};

use crate::model::{Field, Model};

mod read;
mod write;

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
    let struct_fields: Vec<_> = fields.iter().filter_map(Field::needed_in_struct_def).collect();
    let write_code: Vec<_> = fields
        .iter()
        .map(|field| match field {
            Field::Unit(_) => unreachable!("unit fields not possible in normal struct"),
            Field::Normal(normal_field) => write::normal_field_code(normal_field),
            Field::PaddBits(in_type) => write::padding_field_code(*in_type),
            Field::ControlOption(controlled) => write::control_field_code(controlled),
            Field::Option{option_stripped, ..} => write::option_field_code(option_stripped),
        })
        .collect();
    let read_code: Vec<_> = fields
        .iter()
        .map(|field| match field {
            Field::Unit(_) => unreachable!("unit fields not possible in normal struct"),
            Field::Normal(normal_field) => read::normal_field_code(normal_field),
            Field::PaddBits(n_bits) => read::padding_field_code(*n_bits),
            Field::ControlOption(ident) => read::control_field_code(ident),
            Field::Option{option_stripped, ..} => read::option_field_code(option_stripped),
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
