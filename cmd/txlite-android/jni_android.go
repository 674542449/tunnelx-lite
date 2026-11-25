//go:build android && cgo

package main

/*
#include <jni.h>
#include <stdlib.h>

static inline char* txl_jbytes_copy(JNIEnv* env, jbyteArray arr, jsize* outLen) {
    if (arr == NULL) {
        *outLen = 0;
        return NULL;
    }
    jsize n = (*env)->GetArrayLength(env, arr);
    *outLen = n;
    if (n <= 0) {
        return NULL;
    }
    char* buf = (char*)malloc((size_t)n);
    if (buf == NULL) {
        *outLen = 0;
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, arr, 0, n, (jbyte*)buf);
    return buf;
}

static inline jbyteArray txl_bytes_to_jbytes(JNIEnv* env, const char* data, jsize len) {
    jbyteArray arr = (*env)->NewByteArray(env, len);
    if (arr != NULL && len > 0) {
        (*env)->SetByteArrayRegion(env, arr, 0, len, (const jbyte*)data);
    }
    return arr;
}
*/
import "C"
import (
	"encoding/json"
	"unsafe"

	"github.com/674542449/tunnelx-lite/internal/mobile"
)

func goBytesFromJByteArray(env *C.JNIEnv, arr C.jbyteArray) []byte {
	var n C.jsize
	ptr := C.txl_jbytes_copy(env, arr, &n)
	if ptr == nil || n <= 0 {
		return nil
	}
	defer C.free(unsafe.Pointer(ptr))
	return C.GoBytes(unsafe.Pointer(ptr), C.int(n))
}

func jByteArrayFromGoBytes(env *C.JNIEnv, b []byte) C.jbyteArray {
	if len(b) == 0 {
		return C.txl_bytes_to_jbytes(env, nil, 0)
	}
	return C.txl_bytes_to_jbytes(env, (*C.char)(unsafe.Pointer(&b[0])), C.jsize(len(b)))
}

//export Java_com_txlite_android_core_CoreBridge_nativeInit
func Java_com_txlite_android_core_CoreBridge_nativeInit(env *C.JNIEnv, _ C.jclass, dataDir, socksAddr, httpAddr C.jbyteArray) C.jbyteArray {
	err := mobile.Init(
		string(goBytesFromJByteArray(env, dataDir)),
		string(goBytesFromJByteArray(env, socksAddr)),
		string(goBytesFromJByteArray(env, httpAddr)),
	)
	if err != nil {
		b, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
		return jByteArrayFromGoBytes(env, b)
	}
	return jByteArrayFromGoBytes(env, []byte(`{"ok":true}`))
}

//export Java_com_txlite_android_core_CoreBridge_nativeCall
func Java_com_txlite_android_core_CoreBridge_nativeCall(env *C.JNIEnv, _ C.jclass, action, payload C.jbyteArray) C.jbyteArray {
	act := string(goBytesFromJByteArray(env, action))
	req := goBytesFromJByteArray(env, payload)
	resp := mobile.Call(act, req)
	return jByteArrayFromGoBytes(env, resp)
}
