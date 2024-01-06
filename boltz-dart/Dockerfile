FROM amd64/rust:slim-bullseye
ARG USER_ID

RUN if getent passwd $USER_ID >/dev/null; then \
        existing_user=$(getent passwd $USER_ID | cut -d: -f1) && \
        usermod -l debian $existing_user; \
    else \
        useradd -u $USER_ID -m debian; \
    fi

RUN mkdir /boltz-dart
RUN chown -R debian /boltz-dart

RUN apt-get update --allow-releaseinfo-change && \
    apt-get install -y build-essential \
    cmake apt-transport-https ca-certificates curl \
    wget gnupg2 software-properties-common dirmngr unzip \
    openssl libssl-dev git expect jq lsb-release tree \
    default-jdk pkg-config autoconf libtool neovim

RUN rustup target add x86_64-apple-darwin aarch64-linux-android x86_64-linux-android i686-linux-android armv7-linux-androideabi

RUN mkdir /.cargo
COPY config /.cargo/config
RUN chown -R debian /.cargo

ENV CARGO_HOME=/.cargo
ENV ANDROID_HOME=/android
ENV NDK_VERSION=23.0.7599858
ENV ANDROID_VERSION=32

RUN mkdir ${ANDROID_HOME} && cd ${ANDROID_HOME} && \
    wget https://dl.google.com/android/repository/commandlinetools-linux-8092744_latest.zip

RUN cd ${ANDROID_HOME} &&  unzip commandlinetools-linux-8092744_latest.zip && \
    rm -rf commandlinetools-linux-8092744_latest.zip && \
    cd cmdline-tools && mkdir ../tools  && mv * ../tools && mv ../tools .

ENV ANDROID_NDK_HOME=$ANDROID_HOME/ndk/$NDK_VERSION
ENV PATH=/bin:/usr/bin:/usr/local/bin:$ANDROID_HOME/cmdline-tools/tools/bin:$ANDROID_HOME/platform-tools:$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_HOME/sysroot:$PATH
RUN yes | sdkmanager --install "platform-tools" "platforms;android-$ANDROID_VERSION" "build-tools;$ANDROID_VERSION.0.0" "ndk;$NDK_VERSION"
RUN yes | sdkmanager --licenses

RUN ln -s $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-ar
RUN ln -s $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android-ar
RUN ln -s $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7-linux-androideabi-ar
RUN ln -s $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android-ar
RUN ln -s $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ar

VOLUME ["/boltz-dart"]

COPY docker-entrypoint.sh /usr/bin
USER debian

ENTRYPOINT ["docker-entrypoint.sh"]
# CMD ["make", "android"]
# CMD ["tail", "-f", "/dev/null"]

# docker build --platform linux/x86_64 --build-arg USER_ID=$(id -u) -t bwcbuilder . 
# in the project root directory run:
# docker run --platform linux/x86_64 --name bwcbuilder01 -v $PWD:/boltz-dart bwcbuilder && docker stop bwcbuilder01 && docker rm bwcbuilder01