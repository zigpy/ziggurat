use proc_macro_error2::{proc_macro_error};

mod model;
use model::Model;
mod codegen;
use codegen::codegen;
mod errors;

/// # Warning
/// When applied to an enum (which does not contain values) 
/// that enum must be Copy.
#[proc_macro_attribute]
#[proc_macro_error]
pub fn zigbee_bytes(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let model = if let Ok(item) = syn::parse::<syn::ItemStruct>(item.clone()) {
        Model::from_struct(item, attr.into())
    } else if let Ok(item) = syn::parse::<syn::ItemEnum>(item) {
        Model::from_enum(item, attr.into())
    } else {
        panic!("only enum and (unit)struct are supported")
    };

    let code = codegen(model);
    code.into()
}
