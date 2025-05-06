use proc_macro_error2::proc_macro_error;

mod model;
use model::Model;
mod codegen;
use codegen::codegen;
mod errors;

/// # Warning
/// - When applied to an enum (which does not contain values) 
/// that enum must be Copy.
/// - Any derives should be applied after the this proc macro
///
/// # Example:
///
/// ```
/// #[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
/// #[zigbee_bytes(bits=2)]
/// #[repr(u8)]
/// pub enum NwkRouteRequestManyToOne {
///     NotManyToOne = 0,
///     ManyToOneSenderSupportsRouteRecordTable = 1,
///     ManyToOneSenderDoesntSupportRouteRecordTable = 2,
///     Reserved = 3,
/// }
///
/// #[zigbee_bytes]
/// #[derive(Debug, Clone, PartialEq)]
/// pub struct NwkRouteRequestCommand {
///     reserved: u3,
///     pub many_to_one: NwkRouteRequestManyToOne,
///     #[wire_format(controls = destination_eui64)]
///     reserved: bool,
///     reserved: u2,
///     pub route_request_identifier: u8,
///     pub destination_address: Nwk,
///     pub path_cost: u8,
///     pub destination_eui64: Option<Eui64>,
///     pub tlvs: Vec<u8>,
/// }
/// ```
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
