use custom_error::custom_error;

custom_error! {pub Error
    r#None { descr: String } = "{}",
    YAML { source: serde_yaml::Error } = "{}",
    IO { source: std::io::Error } = "{}",
}

pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! none {
    ( $msg: expr ) => {
        {
            Error::None {
                descr: format!("Missing {}", $msg)
            }
        }
    }
}
