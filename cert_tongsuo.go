// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tongsuogo

// #include "shim.h"
import "C"

func getDigestFunction(digest EVP_MD) (md *C.EVP_MD) {
	switch digest {
	// please don't use these digest functions
	case EVP_NULL:
		md = C.X_EVP_md_null()
	case EVP_MD5:
		md = C.X_EVP_md5()
	case EVP_SHA:
		md = C.X_EVP_sha()
	case EVP_SHA1:
		md = C.X_EVP_sha1()
	case EVP_DSS:
		md = C.X_EVP_dss()
	case EVP_DSS1:
		md = C.X_EVP_dss1()
	case EVP_SHA224:
		md = C.X_EVP_sha224()
	// you actually want one of these
	case EVP_SHA256:
		md = C.X_EVP_sha256()
	case EVP_SHA384:
		md = C.X_EVP_sha384()
	case EVP_SHA512:
		md = C.X_EVP_sha512()
	}
	return md
}
