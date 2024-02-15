rm -rf boltz-rust
rm boltz-rust.tar.gz
mkdir -p boltz-rust/android/app/src/main/jniLibs/arm64-v8a/ boltz-rust/android/app/src/main/jniLibs/armeabi-v7a/ boltz-rust/android/app/src/main/jniLibs/x86/ boltz-rust/android/app/src/main/jniLibs/x86_64/ boltz-rust/ios

cp target/aarch64-linux-android/release/libboltz-rust.so boltz-rust/android/app/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/libboltz-rust.so boltz-rust/android/app/src/main/jniLibs/armeabi-v7a/
cp target/i686-linux-android/release/libboltz-rust.so boltz-rust/android/app/src/main/jniLibs/x86/
cp target/x86_64-linux-android/release/libboltz-rust.so boltz-rust/android/app/src/main/jniLibs/x86_64/
cp target/bindings.h boltz-rust/
cp target/universal/release/libboltz-rust.a boltz-rust/ios
tar -cvzf boltz-rust.tar.gz boltz-rust

mv boltz-rust.tar.gz boltz-rust-0.0.2.tar.gz

#echo "upload to S3" // INSTEAD OF HERE, RELEASE TO boltz-rust REPO
