/*
 * Copyright 2020 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.secp256k1

import java.util.*


private fun tryLoad(platform: String): Secp256k1? {
    try {
        val cls = Class.forName("fr.acinq.secp256k1.jni.NativeSecp256k1${platform.capitalize(Locale.ROOT)}Loader")
        val load = cls.getMethod("load")
        return load.invoke(null) as Secp256k1
    } catch (ex: ClassNotFoundException) {
        return null
    }
}

internal actual fun getSecpk256k1(): Secp256k1 =
    tryLoad("android")
        ?: tryLoad("jvm")
        ?: error("Could not load native Secp256k1 JNI library. Have you added the JNI dependency?")
