use digest::dev::{digest_test, one_million_a};
use digest::new_test;
use hex_literal::hex;
use sm3::Sm3;

new_test!(sm3_main, "sm3", Sm3, digest_test);

#[test]
#[rustfmt::skip]
fn sm3_1million_a() {
    let expected = hex!("
        c8aaf89429554029e231941a2acc0ad6
        1ff2a5acd8fadd25847a3a732b3b02c3
    ");
    one_million_a::<sm3::Sm3>(&expected);
}
