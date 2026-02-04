# Kmesh 2026 Road Map

This document outlines the planned features and improvements for Kmesh in 2026, following the successful release of v1.2.0.

## Overview

The 2026 roadmap focuses on enhancing observability, performance optimization, extending mesh capabilities, and improving load balancing strategies to make Kmesh more robust and feature-rich for production environments.

## Planned Features and Improvements

### 1. Kmesh Dashboard ([#1552](https://github.com/kmesh-net/kmesh/issues/1552))

**Priority:** High  
**Status:** Planned

Develop a comprehensive web-based dashboard for Kmesh that provides:
- Real-time visualization of service mesh topology
- Traffic flow monitoring and analysis
- Performance metrics and health status
- Configuration management interface
- Troubleshooting and debugging tools

**Benefits:**
- Improved observability and user experience
- Easier debugging and troubleshooting
- Better operational insights into the mesh

### 2. Optimize kmesh-daemon CPU Usage During Massive xDS Configuration Updates ([#1549](https://github.com/kmesh-net/kmesh/issues/1549))

**Priority:** High  
**Status:** Planned

Optimize the CPU consumption of kmesh-daemon when handling large-scale xDS configuration updates:
- Implement incremental configuration processing
- Optimize BPF map update operations
- Reduce unnecessary synchronization overhead
- Batch processing of configuration changes

**Benefits:**
- Lower resource consumption in large-scale deployments
- Improved stability during configuration updates
- Better scalability for large clusters

### 3. Use Orion to Replace Waypoint

**Priority:** Medium  
**Status:** Under Investigation

Evaluate and implement Orion as a replacement for the current waypoint architecture:
- Research Orion's capabilities and compatibility
- Design migration strategy
- Implement Orion integration
- Provide backward compatibility

**Benefits:**
- Potentially improved performance for L7 traffic processing
- Enhanced feature set
- Better alignment with emerging standards

### 4. Support Multi-Cluster

**Priority:** High  
**Status:** Planned

Enable Kmesh to work seamlessly across multiple Kubernetes clusters:
- Implement cross-cluster service discovery
- Support cross-cluster traffic routing
- Handle multi-cluster authentication and authorization
- Provide unified observability across clusters

**Benefits:**
- Enable true multi-cluster service mesh deployments
- Support for disaster recovery and geographic distribution
- Improved scalability for large organizations

### 5. Support More Load Balancing Algorithms

**Priority:** Medium  
**Status:** Planned

Extend the load balancing capabilities with additional algorithms:
- Weighted round-robin
- Least connections
- Least request
- Random with two choices
- Maglev consistent hashing
- Ring hash
- Peak EWMA (exponentially weighted moving average)

**Benefits:**
- Better flexibility for different application requirements
- Improved traffic distribution
- Enhanced performance for specific use cases

### 6. Support MCP (Mesh Configuration Protocol) in Layer 7

**Priority:** Medium  
**Status:** Planned

Implement MCP support for Layer 7 traffic governance:
- Enable MCP-based configuration synchronization
- Support advanced L7 routing rules via MCP
- Implement MCP source integration
- Provide fallback mechanisms

**Benefits:**
- Enhanced configuration flexibility
- Better integration with existing mesh control planes
- Support for hybrid mesh architectures

### 7. Optimize Long Connection Load Balancing

**Priority:** High  
**Status:** Planned

Improve load balancing behavior for long-lived connections:
- Implement connection draining mechanisms
- Support dynamic re-balancing of active connections
- Add connection affinity controls
- Optimize for streaming workloads

**Benefits:**
- Better resource utilization for long-running connections
- Improved fairness in load distribution
- Enhanced support for gRPC and WebSocket workloads

## Timeline

**Q1 2026 (January - March)**
- Begin work on Kmesh Dashboard prototype
- Start optimization work on kmesh-daemon CPU usage
- Research and evaluation phase for Orion integration

**Q2 2026 (April - June)**
- Complete kmesh-daemon CPU optimization
- Release beta version of Kmesh Dashboard
- Design and prototype multi-cluster support

**Q3 2026 (July - September)**
- Implement additional load balancing algorithms
- Beta release of multi-cluster support
- Begin MCP Layer 7 implementation

**Q4 2026 (October - December)**
- Complete long connection load balancing optimization
- Finalize Orion integration (if approved)
- General availability of Kmesh Dashboard and multi-cluster support

## Contributing

We welcome community contributions to help achieve these roadmap goals! If you're interested in contributing to any of these features:

1. Check the linked issues for detailed discussions
2. Join our community meetings to coordinate work
3. Review our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
4. Reach out to the maintainers for guidance

## Feedback

This roadmap is a living document. If you have suggestions, feature requests, or want to propose changes, please:
- Comment on issue [#1555](https://github.com/kmesh-net/kmesh/issues/1555)
- Create a new issue with your proposal
- Join our community discussions

## Version History

- **v1.0** - February 2026: Initial 2026 roadmap publication

---

*Last Updated: February 4, 2026*
