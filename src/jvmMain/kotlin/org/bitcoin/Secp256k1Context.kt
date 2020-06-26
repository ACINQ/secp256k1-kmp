/*
 * Copyright 2014-2016 the libsecp256k1 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoin

import fr.acinq.secp256k1.Secp256k1Loader.initialize

/**
 * This class holds the context reference used in native methods
 * to handle ECDSA operations.
 */
public object Secp256k1Context {
    @JvmStatic
    public val isEnabled: Boolean //true if the library is loaded
    private val context: Long //ref to pointer to context obj

    @JvmStatic
    public fun getContext(): Long {
        return if (!isEnabled) -1 else context //sanity check
    }

    @JvmStatic private external fun secp256k1_init_context(): Long

    init { //static initializer
        var isEnabled = true
        var contextRef: Long = -1
        try {
            if ("The Android Project" == System.getProperty("java.vm.vendor")) {
                System.loadLibrary("secp256k1")
            } else {
                initialize()
            }
            contextRef = secp256k1_init_context()
        } catch (e: UnsatisfiedLinkError) {
            println("Cannot load secp256k1 native library: $e")
            isEnabled = false
        } catch (e: Exception) {
            println("Cannot load secp256k1 native library: $e")
            isEnabled = false
        }
        this.isEnabled = isEnabled
        this.context = contextRef
    }
}