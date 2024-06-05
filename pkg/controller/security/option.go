/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package security

import (
	"time"

	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/security"
)

const (
	ADD = iota
	DELETE
	RETRY
	Rotate

	maxConcurrentCSR = 128 // max concurrent CSR
)

func NewSecurityOptions() *security.Options {
	return &security.Options{
		WorkloadRSAKeySize: workloadRSAKeySizeEnv,
		Pkcs8Keys:          pkcs8KeysEnv,
		ECCSigAlg:          eccSigAlgEnv,
		ECCCurve:           eccCurvEnv,
		SecretTTL:          secretTTLEnv,
	}
}

var (
	caAddress    = env.Register("CA_ADDRESS", "istiod.istio-system.svc:15012", "").Get()
	secretTTLEnv = env.Register("SECRET_TTL", 24*time.Hour,
		"The cert lifetime requested by kmesh CA agent").Get()

	workloadRSAKeySizeEnv = env.Register("WORKLOAD_RSA_KEY_SIZE", 2048,
		"Specify the RSA key size to use for workload certificates.").Get()
	pkcs8KeysEnv = env.Register("PKCS8_KEY", false,
		"Whether to generate PKCS#8 private keys").Get()
	eccSigAlgEnv = env.Register("ECC_SIGNATURE_ALGORITHM", "", "The type of ECC signature algorithm to use when generating private keys").Get()
	eccCurvEnv   = env.Register("ECC_CURVE", "P256", "The elliptic curve to use when ECC_SIGNATURE_ALGORITHM is set to ECDSA").Get()
)
