use digest::new_mac_test;

new_mac_test!(blake2b_mac, "blake2b/mac", blake2::Blake2bMac512);
new_mac_test!(blake2s_mac, "blake2s/mac", blake2::Blake2sMac256);
