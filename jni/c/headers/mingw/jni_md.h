/*
 * @(#)jni_md.h	1.14 03/12/19
 *
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * SUN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

#ifndef _JAVASOFT_JNI_MD_H_
#define _JAVASOFT_JNI_MD_H_

#define JNIEXPORT __declspec(dllexport)
#define JNIIMPORT __declspec(dllimport)
#define JNICALL __stdcall

#include <stdint.h>

typedef long jint;
typedef int64_t jlong;
typedef signed char jbyte;

#endif /* !_JAVASOFT_JNI_MD_H_ */
