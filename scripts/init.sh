#!/bin/bash
# sudo locale-gen en_US en_US.UTF-8
# sudo dpkg-reconfigure locales 
# source /etc/default/locale 
# sudo update-locale LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8
# source /etc/default/locale

sudo apt-get update --allow-releaseinfo-change
sudo apt-get install -y build-essential cmake apt-transport-https ca-certificates curl gnupg2 software-properties-common dirmngr unzip openssl libssl-dev git expect jq lsb-release tree default-jdk pkg-config autoconf pkgconf libtool
curl https://sh.rustup.rs -sSf | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"
source $HOME/.cargo/env
echo "[*] Installed basic tools"

mkdir ~/android
cd ~/android
wget https://dl.google.com/android/repository/commandlinetools-linux-8092744_latest.zip
unzip ~/android/commandlinetools-linux-8092744_latest.zip 
rm ~/android/commandlinetools-linux-8092744_latest.zip
cd cmdline-tools
mkdir tools
mv -i * tools 2> /dev/null
cd ..
echo "[*] Installed Android Cli Tools"

export ANDROID_HOME=~/android
export PATH=$ANDROID_HOME/cmdline-tools/tools/bin/:$PATH
export PATH=$ANDROID_HOME/platform-tools/:$PATH
sdkmanager 
sdkmanager --install "platform-tools" "platforms;android-32" "build-tools;32.0.0" "ndk;21.4.7075529"
sdkmanager --licenses
ls ~/android/ndk/21.4.7075529/toolchains/llvm/prebuilt/linux-x86_64/bin
echo "[*] Installed Android SDK+NDK Tools"

export ANDROID_SDK_HOME=~/android
export sdkmanager --install "platform-tools"
export PATH=$PATH:~/android/sdk/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin
# for now we have to make hacky copies of llvm-ar for each build
# cp $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-ar
# also do this for other 3 android arch
cd 
git clone https://github.com/StackmateNetwork/stackmate-core.git
cd stackmate-core
echo "[*] Pulled stackmate-core"

rustup target add x86_64-apple-darwin aarch64-linux-android x86_64-linux-android i686-linux-android armv7-linux-androideabi
echo "[*] Added targets to cargo."
echo "[!] Next Steps: "
echo "[!] CONFIGURE ~/.cargo/config"
echo "[!] ./build.sh"