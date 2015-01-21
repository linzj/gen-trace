THISPATH=`dirname ${0%/*}`
cd $THISPATH
TARGET_ARCH=x86

NDK_ROOT=`dirname $(which ndk-build)`
export ANDROID_NDK_ROOT=$NDK_ROOT
export NDK_PATH=$NDK_ROOT

# If not defined ANDROID_TOOLCHAIN, it search the ndk directory and find the gcc-4.4.3 to compile v8.
if [ -z "$ANDROID_TOOLCHAIN" ]; then
    if [ "$TARGET_ARCH" = "x86" ]; then
        TOOLCHAIN_PATH=`dirname $(find $NDK_ROOT/toolchains $NDK_ROOT/build  -name 'i686*' -name '*-g++' | sort -r| head -n 1)`
    elif [ "$TARGET_ARCH" = "armeabi" ]; then
        TOOLCHAIN_PATH=`dirname $(find $NDK_ROOT/toolchains $NDK_ROOT/build  -name 'arm*' -name '*-g++' | sort -r| head -n 1)`
        EXTRA_OPTION="armv7=false vfp2=off vfp3=off"
    elif [ "$TARGET_ARCH" = "armeabi-v7a" ]; then
        TOOLCHAIN_PATH=`dirname $(find $NDK_ROOT/toolchains $NDK_ROOT/build  -name 'arm*' -name '*-g++' | sort -r| head -n 1)`
        EXTRA_OPTION="armv7=true vfp2=on vfp3=on"
    else
        echo "unsupported platform " "$TARGET_ARCH" 1>&2
        exit 1
    fi
    export ANDROID_TOOLCHAIN=${TOOLCHAIN_PATH%/bin}
fi

export PATH=$TOOLCHAIN_PATH:$PATH
export GCC_VER=`i686-linux-android-g++ --version | head -n 1 | awk '{print $3}'`
