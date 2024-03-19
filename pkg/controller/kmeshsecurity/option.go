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

package kmeshsecurity

import (
	"time"

	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/security"
)

var 	(
	CACertFilePath = ""
	PilotCertProvider = env.Register("PILOT_CERT_PROVIDER", "istiod",
	"The provider of Pilot DNS certificate.").Get()
	CSRSignAddress = env.Register("MESH_CONTROLLER", "istiod.istio-system.svc:15012", "").Get()
)
func NewSecurityOptions() (*security.Options) {
	secOpts := &security.Options{
		CAEndpoint:                     caEndpointEnv,
		CAProviderName:                 caProviderEnv,
		PilotCertProvider:              PilotCertProvider,
		OutputKeyCertToDir:             outputKeyCertToDir,
		ProvCert:                       provCert,
		ClusterID:                      clusterIDVar.Get(),
		FileMountedCerts:               fileMountedCertsEnv,
		WorkloadNamespace:              PodNamespaceVar.Get(),
		ServiceAccount:                 serviceAccountVar.Get(),
		XdsAuthProvider:                xdsAuthProvider.Get(),
		TrustDomain:                    trustDomainEnv,
		WorkloadRSAKeySize:             workloadRSAKeySizeEnv,
		Pkcs8Keys:                      pkcs8KeysEnv,
		ECCSigAlg:                      eccSigAlgEnv,
		ECCCurve:                       eccCurvEnv,
		SecretTTL:                      secretTTLEnv,
		FileDebounceDuration:           fileDebounceDuration,
		SecretRotationGracePeriodRatio: secretRotationGracePeriodRatioEnv,
		STSPort:                        0,
		CertSigner:                     certSigner.Get(),
		CARootPath:                     CACertFilePath,
		CertChainFilePath:              security.DefaultCertChainFilePath,
		KeyFilePath:                    security.DefaultKeyFilePath,
		RootCertFilePath:               security.DefaultRootCertFilePath,
	}

	secOpts = SetupSecurityOptions(secOpts)

	return secOpts
}

// TODO :Set options based on user requirements.
func SetupSecurityOptions(secOpts *security.Options) (*security.Options){
	
	return secOpts
}

var (
	InstanceIPVar        = env.Register("INSTANCE_IP", "", "")
	PodNameVar           = env.Register("POD_NAME", "", "")
	PodNamespaceVar      = env.Register("POD_NAMESPACE", "", "")
	ProxyConfigEnv       = env.Register(
		"PROXY_CONFIG",
		"",
		"The proxy configuration. This will be set by the injection - gateways will use file mounts.",
	).Get()

	serviceAccountVar = env.Register("SERVICE_ACCOUNT", "", "Name of service account")
	clusterIDVar      = env.Register("ISTIO_META_CLUSTER_ID", "", "")
	// Provider for XDS auth, e.g., gcp. By default, it is empty, meaning no auth provider.
	xdsAuthProvider = env.Register("XDS_AUTH_PROVIDER", "", "Provider for XDS auth")

	// ProvCert is the environment controlling the use of pre-provisioned certs, for VMs.
	// May also be used in K8S to use a Secret to bootstrap (as a 'refresh key'), but use short-lived tokens
	// with extra SAN (labels, etc) in data path.
	provCert = env.Register("PROV_CERT", "",
		"Set to a directory containing provisioned certs, for VMs").Get()

	outputKeyCertToDir = env.Register("OUTPUT_CERTS", "",
		"The output directory for the key and certificate. If empty, key and certificate will not be saved. "+
			"Must be set for VMs using provisioning certificates.").Get()

	caProviderEnv = env.Register("CA_PROVIDER", "Citadel", "name of authentication provider").Get()
	caEndpointEnv = env.Register("CA_ADDR", "", "Address of the spiffe certificate provider. Defaults to discoveryAddress").Get()

	trustDomainEnv = env.Register("TRUST_DOMAIN", "cluster.local",
		"The trust domain for spiffe certificates").Get()

	secretTTLEnv = env.Register("SECRET_TTL", 24*time.Hour,
		"The cert lifetime requested by istio agent").Get()

	fileDebounceDuration = env.Register("FILE_DEBOUNCE_DURATION", 100*time.Millisecond,
		"The duration for which the file read operation is delayed once file update is detected").Get()

	secretRotationGracePeriodRatioEnv = env.Register("SECRET_GRACE_PERIOD_RATIO", 0.5,
		"The grace period ratio for the cert rotation, by default 0.5.").Get()
	workloadRSAKeySizeEnv = env.Register("WORKLOAD_RSA_KEY_SIZE", 2048,
		"Specify the RSA key size to use for workload certificates.").Get()
	pkcs8KeysEnv = env.Register("PKCS8_KEY", false,
		"Whether to generate PKCS#8 private keys").Get()
	eccSigAlgEnv        = env.Register("ECC_SIGNATURE_ALGORITHM", "", "The type of ECC signature algorithm to use when generating private keys").Get()
	eccCurvEnv          = env.Register("ECC_CURVE", "P256", "The elliptic curve to use when ECC_SIGNATURE_ALGORITHM is set to ECDSA").Get()
	fileMountedCertsEnv = env.Register("FILE_MOUNTED_CERTS", false, "").Get()

	// DNSCaptureByAgent is a copy of the env var in the init code.
	DNSCaptureByAgent = env.Register("ISTIO_META_DNS_CAPTURE", false,
		"If set to true, enable the capture of outgoing DNS packets on port 53, redirecting to istio-agent on :15053")

	// DNSCaptureAddr is the address to listen.
	DNSCaptureAddr = env.Register("DNS_PROXY_ADDR", "localhost:15053",
		"Custom address for the DNS proxy. If it ends with :53 and running as root allows running without iptable DNS capture")

	DNSForwardParallel = env.Register("DNS_FORWARD_PARALLEL", false,
		"If set to true, agent will send parallel DNS queries to all upstream nameservers")

	// certSigner is cert signer for workload cert
	certSigner = env.Register("ISTIO_META_CERT_SIGNER", "",
		"The cert signer info for workload cert")

)
