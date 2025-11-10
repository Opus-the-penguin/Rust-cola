use std::env;

pub fn test_parse() {
    let s = env::var("PORT").unwrap_or_default();
    let num: u16 = s.parse().unwrap_or(8080);
    println!("{}", num);
}

pub fn test_chars_all() {
    let s = env::var("USER").unwrap_or_default();
    if s.chars().all(|c| c.is_alphanumeric()) {
        println!("{}", s);
    }
}
