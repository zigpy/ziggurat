use proc_macro_error2::proc_macro_error;
use syn::parse_macro_input;

mod model;
use model::Model;
mod codegen;
use codegen::codegen;
mod errors;

#[proc_macro_attribute]
#[proc_macro_error]
pub fn zigbee_bytes(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let item = parse_macro_input!(item as syn::ItemStruct);

    let model = Model::try_from(item, attr.into());

    let code = codegen(model);
    code.into()
}
