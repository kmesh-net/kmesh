# Quickstart for Kmesh E2E Testing

This document is designed to help developers quickly get started with writing and running end-to-end (E2E) tests for the Kmesh project. It covers the prerequisites, the test environment setup, a simple test function template, and instructions for running tests. By following this guide, you will be able to write and execute E2E tests efficiently, ensuring the stability and correctness of Kmesh features.

## Prerequisites

Before getting started, ensure the following tools are installed in your environment:

- **Go**: For running the test framework.
- **Docker**: For containerizing applications.
- **kubectl**: For managing Kubernetes clusters.
- **Kind**: For creating Kubernetes clusters locally.
- **Helm**: For managing Kubernetes applications.

## E2E Test Environment

Kmesh E2E testing requires a two-node KinD cluster:

- **Control Node**: Manages the cluster.
- **Worker Node**: Runs the test services.

At the start of the test, two services will be deployed:

1. **service-with-waypoint-at-service-granularity**: A service with a Waypoint.
2. **enrolled-to-kmesh**: A service without a Waypoint.

Both services use Echo Pods, which are used to test different scenarios.

## Writing E2E Tests

Here is a simple E2E test function template with step-by-step explanations:

```go
func TestEchoCall(t *testing.T) {
    // Create a new test suite for the current test
    framework.NewTest(t).Run(func(t framework.TestContext) {
        // Define a subtest for the Echo Call functionality
        t.NewSubTest("Echo Call Test").Run(func(t framework.TestContext) {
            // Retrieve the source service (with Waypoint) and destination service (without Waypoint)
            src := apps.ServiceWithWaypointAtServiceGranularity[0]
            dst := apps.EnrolledToKmesh

            // Define test cases with a name and a checker to validate the response
            cases := []struct {
                name string
                checker echo.Checker
            }{
                {
                    name: "basic call", // Name of the test case
                    checker: echo.And(
                        echo.ExpectOK(),                      // Expect the HTTP call to succeed
                        echo.ExpectBodyContains("Hello"),    // Expect the response body to contain "Hello"
                    ),
                },
            }

            // Iterate over each test case and execute it
            for _, c := range cases {
                t.NewSubTest(c.name).Run(func(t framework.TestContext) {
                    // Perform the HTTP call from the source to the destination
                    src.CallOrFail(t, echo.CallOptions{
                        Target:   dst[0],       // Target service
                        PortName: "http",      // Port name to use for the call
                        Checker:  c.checker,    // Checker to validate the response
                    })
                })
            }
        })
    })
}
```

### Explanation of Steps

1. **`framework.NewTest(t).Run`**: Initializes a new test suite for the current test.
2. **`t.NewSubTest("Echo Call Test").Run`**: Creates a subtest for the Echo Call functionality.
3. **Retrieve Services**: The `src` variable represents the source service (with Waypoint), and the `dst` variable represents the destination service (without Waypoint).
4. **Define Test Cases**: Each test case includes a name and a `checker` to validate the HTTP response. For example, `echo.ExpectOK()` ensures the HTTP call succeeds, and `echo.ExpectBodyContains("Hello")` checks the response body.
5. **Iterate and Execute**: For each test case, the `src.CallOrFail` method performs the HTTP call from the source to the destination and validates the response using the specified `checker`.
6. **`echo.CallOptions`**: Specifies the target service, port name, and checker for the HTTP call.

### Resource Cleanup

Use the `t.Cleanup` method to ensure test resources are cleaned up after the test completes. For example:

```go
t.Cleanup(func() {
    // Clean up resources
})
```

### Deploying Policies

Use the `t.ConfigIstio` method to deploy policies required for the test. For example:

```go
t.ConfigIstio().YAML("test-namespace", `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-all
spec:
  rules:
  - {}
`).ApplyOrFail(t)
```

### Using echo.Checker

`echo.Checker` is used to verify whether a test case passes. For example:

```go
// Example: Using echo.Checker to validate HTTP response
src.CallOrFail(t, echo.CallOptions{
    Target:   dst[0],
    PortName: "http",
    Checker: echo.And(
        echo.ExpectOK(),                      // Expect the HTTP call to succeed
        echo.ExpectBodyContains("Hello"),    // Expect the response body to contain "Hello"
        echo.ExpectHeaders(map[string]string{
            "Content-Type": "text/plain",    // Expect the Content-Type header to be "text/plain"
        }),
    ),
})
```

## Running Tests

For detailed instructions on running tests, refer to the [E2E Test Guide](https://kmesh.net/docs/developer-guide/Tests/e2e-test).
