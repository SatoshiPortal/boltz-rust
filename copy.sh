rm -rf rust-elements-wrapper
rm rust-elements-wrapper.tar.gz
mkdir -p rust-elements-wrapper/android/app/src/main/jniLibs/arm64-v8a/ rust-elements-wrapper/android/app/src/main/jniLibs/armeabi-v7a/ rust-elements-wrapper/android/app/src/main/jniLibs/x86/ rust-elements-wrapper/android/app/src/main/jniLibs/x86_64/ rust-elements-wrapper/ios

cp target/aarch64-linux-android/release/librust_elements_wrapper.so rust-elements-wrapper/android/app/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/librust_elements_wrapper.so rust-elements-wrapper/android/app/src/main/jniLibs/armeabi-v7a/
cp target/i686-linux-android/release/librust_elements_wrapper.so rust-elements-wrapper/android/app/src/main/jniLibs/x86/
cp target/x86_64-linux-android/release/librust_elements_wrapper.so rust-elements-wrapper/android/app/src/main/jniLibs/x86_64/
cp target/bindings.h rust-elements-wrapper/
cp target/universal/release/librust_elements_wrapper.a rust-elements-wrapper/ios
tar -cvzf rust-elements-wrapper.tar.gz rust-elements-wrapper

mv rust-elements-wrapper.tar.gz rust-elements-wrapper-0.0.2.tar.gz

#echo "upload to S3" // INSTEAD OF HERE, RELEASE TO rust-elements-wrapper REPO
