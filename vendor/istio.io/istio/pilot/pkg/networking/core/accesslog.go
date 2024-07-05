// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package core

import (
	"sync"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	cel "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	grpcaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pkg/wellknown"
)

const (
	// EnvoyServerName for istio's envoy
	EnvoyServerName = "istio-envoy"

	celFilter                          = "envoy.access_loggers.extension_filters.cel"
	listenerEnvoyAccessLogFriendlyName = "listener_envoy_accesslog"

	// EnvoyAccessLogCluster is the cluster name that has details for server implementing Envoy ALS.
	// This cluster is created in bootstrap.
	EnvoyAccessLogCluster = "envoy_accesslog_service"
)

var (
	// State logged by the metadata exchange filter about the upstream and downstream service instances
	// We need to propagate these as part of access log service stream
	// Logging them by default on the console may be an issue as the base64 encoded string is bound to be a big one.
	// But end users can certainly configure it on their own via the meshConfig using the %FILTER_STATE% macro.
	envoyWasmStateToLog = []string{"wasm.upstream_peer", "wasm.upstream_peer_id", "wasm.downstream_peer", "wasm.downstream_peer_id"}

	// accessLogBuilder is used to set accessLog to filters
	accessLogBuilder = newAccessLogBuilder()
)

type AccessLogBuilder struct {
	// tcpGrpcAccessLog is used when access log service is enabled in mesh config.
	tcpGrpcAccessLog *accesslog.AccessLog
	// httpGrpcAccessLog is used when access log service is enabled in mesh config.
	httpGrpcAccessLog *accesslog.AccessLog
	// tcpGrpcListenerAccessLog is used when access log service is enabled in mesh config.
	tcpGrpcListenerAccessLog *accesslog.AccessLog

	// file accessLog which is cached and reset on MeshConfig change.
	mutex                 sync.RWMutex
	fileAccesslog         *accesslog.AccessLog
	listenerFileAccessLog *accesslog.AccessLog
}

func newAccessLogBuilder() *AccessLogBuilder {
	return &AccessLogBuilder{
		tcpGrpcAccessLog:         tcpGrpcAccessLog(false),
		httpGrpcAccessLog:        httpGrpcAccessLog(),
		tcpGrpcListenerAccessLog: tcpGrpcAccessLog(true),
	}
}

func (b *AccessLogBuilder) setTCPAccessLog(push *model.PushContext, proxy *model.Proxy, tcp *tcp.TcpProxy, class networking.ListenerClass, svc *model.Service) {
	mesh := push.Mesh
	cfgs := push.Telemetry.AccessLogging(push, proxy, class, svc)

	if len(cfgs) == 0 {
		// No Telemetry API configured, fall back to legacy mesh config setting
		if mesh.AccessLogFile != "" {
			tcp.AccessLog = append(tcp.AccessLog, b.buildFileAccessLog(mesh))
		}

		if mesh.EnableEnvoyAccessLogService {
			// Setting it to TCP as the low level one.
			tcp.AccessLog = append(tcp.AccessLog, b.tcpGrpcAccessLog)
		}
		return
	}

	if al := buildAccessLogFromTelemetry(cfgs, false); len(al) != 0 {
		tcp.AccessLog = append(tcp.AccessLog, al...)
	}
}

func buildAccessLogFromTelemetry(cfgs []model.LoggingConfig, forListener bool) []*accesslog.AccessLog {
	als := make([]*accesslog.AccessLog, 0, len(cfgs))
	for _, c := range cfgs {
		if c.Disabled {
			continue
		}
		filters := make([]*accesslog.AccessLogFilter, 0, 2)
		if forListener {
			filters = append(filters, addAccessLogFilter())
		}

		if telFilter := buildAccessLogFilterFromTelemetry(c); telFilter != nil {
			filters = append(filters, telFilter)
		}

		al := &accesslog.AccessLog{
			Name:       c.AccessLog.Name,
			ConfigType: c.AccessLog.ConfigType,
			Filter:     buildAccessLogFilter(filters...),
		}

		als = append(als, al)
	}
	return als
}

func buildAccessLogFilterFromTelemetry(spec model.LoggingConfig) *accesslog.AccessLogFilter {
	if spec.Filter == nil {
		return nil
	}

	fl := &cel.ExpressionFilter{
		Expression: spec.Filter.Expression,
	}

	return &accesslog.AccessLogFilter{
		FilterSpecifier: &accesslog.AccessLogFilter_ExtensionFilter{
			ExtensionFilter: &accesslog.ExtensionFilter{
				Name:       celFilter,
				ConfigType: &accesslog.ExtensionFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(fl)},
			},
		},
	}
}

func (b *AccessLogBuilder) setHTTPAccessLog(push *model.PushContext, proxy *model.Proxy,
	connectionManager *hcm.HttpConnectionManager, class networking.ListenerClass, svc *model.Service,
) {
	mesh := push.Mesh
	cfgs := push.Telemetry.AccessLogging(push, proxy, class, svc)
	if len(cfgs) == 0 {
		// No Telemetry API configured, fall back to legacy mesh config setting
		if mesh.AccessLogFile != "" {
			connectionManager.AccessLog = append(connectionManager.AccessLog, b.buildFileAccessLog(mesh))
		}

		if mesh.EnableEnvoyAccessLogService {
			connectionManager.AccessLog = append(connectionManager.AccessLog, b.httpGrpcAccessLog)
		}
		return
	}

	if al := buildAccessLogFromTelemetry(cfgs, false); len(al) != 0 {
		connectionManager.AccessLog = append(connectionManager.AccessLog, al...)
	}
}

func (b *AccessLogBuilder) setListenerAccessLog(push *model.PushContext, proxy *model.Proxy,
	listener *listener.Listener, class networking.ListenerClass,
) {
	mesh := push.Mesh
	if mesh.DisableEnvoyListenerLog {
		return
	}

	cfgs := push.Telemetry.AccessLogging(push, proxy, class, nil)

	if len(cfgs) == 0 {
		// No Telemetry API configured, fall back to legacy mesh config setting
		if mesh.AccessLogFile != "" {
			listener.AccessLog = append(listener.AccessLog, b.buildListenerFileAccessLog(mesh))
		}

		if mesh.EnableEnvoyAccessLogService {
			// Setting it to TCP as the low level one.
			listener.AccessLog = append(listener.AccessLog, b.tcpGrpcListenerAccessLog)
		}

		return
	}

	if al := buildAccessLogFromTelemetry(cfgs, true); len(al) != 0 {
		listener.AccessLog = append(listener.AccessLog, al...)
	}
}

func (b *AccessLogBuilder) buildFileAccessLog(mesh *meshconfig.MeshConfig) *accesslog.AccessLog {
	if cal := b.cachedFileAccessLog(); cal != nil {
		return cal
	}

	// We need to build access log. This is needed either on first access or when mesh config changes.
	al := model.FileAccessLogFromMeshConfig(mesh.AccessLogFile, mesh)

	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.fileAccesslog = al

	return al
}

func addAccessLogFilter() *accesslog.AccessLogFilter {
	return &accesslog.AccessLogFilter{
		FilterSpecifier: &accesslog.AccessLogFilter_ResponseFlagFilter{
			ResponseFlagFilter: &accesslog.ResponseFlagFilter{Flags: []string{"NR"}},
		},
	}
}

func buildAccessLogFilter(f ...*accesslog.AccessLogFilter) *accesslog.AccessLogFilter {
	if len(f) == 0 {
		return nil
	}

	if len(f) == 1 {
		return f[0]
	}

	return &accesslog.AccessLogFilter{
		FilterSpecifier: &accesslog.AccessLogFilter_AndFilter{
			AndFilter: &accesslog.AndFilter{
				Filters: f,
			},
		},
	}
}

func (b *AccessLogBuilder) buildListenerFileAccessLog(mesh *meshconfig.MeshConfig) *accesslog.AccessLog {
	if cal := b.cachedListenerFileAccessLog(); cal != nil {
		return cal
	}

	// We need to build access log. This is needed either on first access or when mesh config changes.
	lal := model.FileAccessLogFromMeshConfig(mesh.AccessLogFile, mesh)
	// We add ResponseFlagFilter here, as we want to get listener access logs only on scenarios where we might
	// not get filter Access Logs like in cases like NR to upstream.
	lal.Filter = addAccessLogFilter()

	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.listenerFileAccessLog = lal

	return lal
}

func (b *AccessLogBuilder) cachedFileAccessLog() *accesslog.AccessLog {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return b.fileAccesslog
}

func (b *AccessLogBuilder) cachedListenerFileAccessLog() *accesslog.AccessLog {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return b.listenerFileAccessLog
}

func tcpGrpcAccessLog(isListener bool) *accesslog.AccessLog {
	accessLogFriendlyName := model.TCPEnvoyAccessLogFriendlyName
	if isListener {
		accessLogFriendlyName = listenerEnvoyAccessLogFriendlyName
	}
	fl := &grpcaccesslog.TcpGrpcAccessLogConfig{
		CommonConfig: &grpcaccesslog.CommonGrpcAccessLogConfig{
			LogName: accessLogFriendlyName,
			GrpcService: &core.GrpcService{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
						ClusterName: EnvoyAccessLogCluster,
					},
				},
			},
			TransportApiVersion:     core.ApiVersion_V3,
			FilterStateObjectsToLog: envoyWasmStateToLog,
		},
	}

	var filter *accesslog.AccessLogFilter
	if isListener {
		filter = addAccessLogFilter()
	}
	return &accesslog.AccessLog{
		Name:       model.TCPEnvoyALSName,
		ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: protoconv.MessageToAny(fl)},
		Filter:     filter,
	}
}

func httpGrpcAccessLog() *accesslog.AccessLog {
	fl := &grpcaccesslog.HttpGrpcAccessLogConfig{
		CommonConfig: &grpcaccesslog.CommonGrpcAccessLogConfig{
			LogName: model.HTTPEnvoyAccessLogFriendlyName,
			GrpcService: &core.GrpcService{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
						ClusterName: EnvoyAccessLogCluster,
					},
				},
			},
			TransportApiVersion:     core.ApiVersion_V3,
			FilterStateObjectsToLog: envoyWasmStateToLog,
		},
	}

	return &accesslog.AccessLog{
		Name:       wellknown.HTTPGRPCAccessLog,
		ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: protoconv.MessageToAny(fl)},
	}
}

func (b *AccessLogBuilder) reset() {
	b.mutex.Lock()
	b.fileAccesslog = nil
	b.listenerFileAccessLog = nil
	b.mutex.Unlock()
}
