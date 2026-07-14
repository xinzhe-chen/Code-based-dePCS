pub(crate) fn panic_message(error: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = error.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = error.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}
