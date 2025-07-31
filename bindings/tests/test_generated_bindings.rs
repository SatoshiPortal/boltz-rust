use serial_test::serial;

fn run_test(script: &str) {
    uniffi::python_test::run_test(
        std::env!("CARGO_TARGET_TMPDIR"),
        std::env!("CARGO_PKG_NAME"),
        script,
    )
    .unwrap();
}

#[test]
#[serial]
fn reverse() {
    run_test("tests/bindings/reverse.py");
}

#[test]
#[serial]
fn chain() {
    run_test("tests/bindings/chain.py");
}

#[test]
#[serial]
fn submarine() {
    run_test("tests/bindings/submarine.py");
}
