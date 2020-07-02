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
package fr.acinq.secp256k1

import java.lang.Exception

internal object NativeSecp256k1Util {
    @Throws(AssertFailException::class)
    fun assertEquals(val1: Int, val2: Int, message: String) {
        if (val1 != val2) throw AssertFailException("FAIL: $message")
    }

    class AssertFailException(message: String?) : Exception(message)
}