FROM amd64/rust:slim-bullseye
USER root
RUN mkdir $HOME/stackmate-core

RUN apt-get update --allow-releaseinfo-change && \
    apt-get install -y build-essential \
    cmake apt-transport-https ca-certificates curl \
    wget gnupg2 software-properties-common dirmngr unzip \
    openssl libssl-dev git expect jq lsb-release tree \
    default-jdk pkg-config pkgconf autoconf libtool neovim

RUN rustup target add x86_64-apple-darwin aarch64-linux-android x86_64-linux-android i686-linux-android armv7-linux-androideabi
# RUN curl https://sh.rustup.rs -sSf | \
#     sh -s -- --default-toolchain stable -y && \
#     $HOME/.cargo/bin/rustup update beta && \
#     $HOME/.cargo/bin/rustup update nightly
# RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc

RUN mkdir /.cargo
COPY config /.cargo/config

ENV CARGO_HOME=/.cargo
ENV ANDROID_HOME=/android
RUN mkdir ${ANDROID_HOME} && cd ${ANDROID_HOME} && \
    wget https://dl.google.com/android/repository/commandlinetools-linux-8092744_latest.zip

RUN cd ${ANDROID_HOME} &&  unzip commandlinetools-linux-8092744_latest.zip && \
    rm -rf commandlinetools-linux-8092744_latest.zip && \
    cd cmdline-tools && mkdir ../tools  && mv * ../tools && mv ../tools .

ENV ANDROID_NDK_HOME=$ANDROID_HOME/ndk/23.0.7599858
ENV PATH=/bin:/usr/bin:/usr/local/bin:$ANDROID_HOME/cmdline-tools/tools/bin:$ANDROID_HOME/platform-tools:$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_HOME/sysroot:$PATH
RUN yes | sdkmanager --install "platform-tools" "platforms;android-32" "build-tools;32.0.0" "ndk;23.0.7599858"
RUN yes | sdkmanager --licenses

RUN ln -s $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-ar
RUN ln -s $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android-ar
RUN ln -s $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7-linux-androideabi-ar
RUN ln -s $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android-ar

VOLUME ["$HOME/stackmate-core"]
COPY docker-entrypoint.sh /usr/bin
COPY config /.cargo/config
# ENTRYPOINT ["docker-entrypoint.sh"]
# CMD ["make", "android"]
CMD ["tail", "-f", "/dev/null"]

# docker build --platform linux/x86_64 -t smbuilder . 

# in the project root directory run:
# docker run --platform linux/x86_64 --name test-builder -v $PWD:/stackmate-core -d smbuilder 