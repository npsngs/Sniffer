D:\StudioStudio-SDK\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\bin\arm-linux-androideabi-gcc-4.9.exe --sysroot=D:\StudioStudio-SDK\ndk-bundle\platforms\android-21\arch-arm pcap.c main.c -o sniffer -static
pause
adb push E:\YxdSDK\Sniffer\app\src\main\cpp\sniffer /data/local/
adb shell su -c chmod 777 /data/local/sniffer
::pause
adb shell su -c /data/local/sniffer
pause