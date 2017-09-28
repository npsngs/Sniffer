#include <jni.h>
#include "pcap.h"

extern "C"
JNIEXPORT jstring JNICALL
Java_com_forthe_sniffer_MainActivity13_startSniffer(JNIEnv *env, jobject instance, jstring path_) {
    const char *path = env->GetStringUTFChars(path_, 0);

    // TODO
    start_rec(path);
    env->ReleaseStringUTFChars(path_, path);
}
