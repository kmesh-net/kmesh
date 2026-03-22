---
sidebar_position: 6
title: Try Fault Injection
---

## Preparation

1. Make default namespace managed by Kmesh

2. Deploy bookinfo as sample application and sleep as curl client

3. Install service granularity waypoint for reviews service

   _The above steps could refer to [Install Waypoint | Kmesh](/docs/application-layer/install_waypoint.md#preparation)_

4. And install waypoint for ratings service

   ```bash
   istioctl x waypoint apply -n default --name ratings-svc-waypoint
   kubectl label service ratings istio.io/use-waypoint=ratings-svc-waypoint
   kubectl annotate gateway ratings-svc-waypoint sidecar.istio.io/proxyImage=ghcr.io/kmesh-net/waypoint:latest
   ```

5. Apply application version routing by running the following commands:

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/networking/virtual-service-all-v1.yaml

   kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/networking/virtual-service-reviews-test-v2.yaml
   ```

- With the above configuration, this is how requests flow:
  - `productpage` → `reviews:v2` → `ratings` (only for user `jason`)
  - `productpage` → `reviews:v1` (for everyone else)

## Injecting an HTTP delay fault

To test the Bookinfo application microservices for resiliency, inject a 7s delay between the `reviews:v2` and `ratings` microservices for user `jason`. This test will uncover a bug that was intentionally introduced into the Bookinfo app.

Note that the `reviews:v2` service has a 10s hard-coded connection timeout for calls to the `ratings` service. Even with the 7s delay that you introduced, you still expect the end-to-end flow to continue without any errors.

1. Create a fault injection rule to delay traffic coming from the test user `jason`.

   ```bash
   kubectl apply -f - <<EOF
   apiVersion: networking.istio.io/v1alpha3
   kind: VirtualService
   metadata:
     name: ratings
   spec:
     hosts:
     - ratings
     http:
     - match:
       - headers:
           end-user:
             exact: jason
       fault:
         delay:
           percentage:
             value: 100.0
           fixedDelay: 7s
       route:
       - destination:
           host: ratings
           subset: v1
     - route:
       - destination:
           host: ratings
           subset: v1
   EOF
   ```

Allow several seconds for the new rule to propagate to all pods.

## Testing the delay configuration

1. Open the Bookinfo web application in your browser.

2. On the `/productpage` web page, log in as user `jason`.

   You expect the Bookinfo home page to load without errors in approximately 7 seconds. However, there is a problem: the Reviews section displays an error message:

   `Sorry, product reviews are currently unavailable for this book.`

3. View the web page response time:

   ![Fault_Injection1](images/fault_injection1.png)

## Understanding what happened

As expected, the 7s delay you introduced doesn't affect the `reviews` service because the timeout between the `reviews` and `ratings` service is hard-coded at 10s. However, there is also a hard-coded timeout between the `productpage` and the `reviews` service, coded as 3s + 1 retry for 6s total. As a result, the `productpage` call to `reviews` times out prematurely and throws an error after 6s.

Bugs like this can occur in typical enterprise applications where different teams develop different microservices independently. Istio's fault injection rules help you identify such anomalies without impacting end users.

## Fixing the bug

You would normally fix the problem by:

1. Either increasing the `productpage` to `reviews` service timeout or decreasing the `reviews` to `ratings` timeout
2. Stopping and restarting the fixed microservice
3. Confirming that the `/productpage` web page returns its response without any errors.

However, you already have a fix running in v3 of the `reviews` service. The `reviews:v3` service reduces the `reviews` to `ratings` timeout from 10s to 2.5s so that it is compatible with (less than) the timeout of the downstream `productpage` requests.

If you migrate all traffic to `reviews:v3` as described in the [traffic shifting](https://kmesh.net/en/docs/userguide/try_traffic_shifting/) task, you can then try to change the delay rule to any amount less than 2.5s, for example 2s, and confirm that the end-to-end flow continues without any errors.

## Injecting an HTTP abort fault

Another way to test microservice resiliency is to introduce an HTTP abort fault. In this task, you will introduce an HTTP abort to the `ratings` microservices for the test user `jason`.

In this case, you expect the page to load immediately and display the `Ratings service is currently unavailable` message.

1. Create a fault injection rule to send an HTTP abort for user `jason`:

   ```bash
   kubectl apply -f - <<EOF
   apiVersion: networking.istio.io/v1alpha3
   kind: VirtualService
   metadata:
     name: ratings
   spec:
     hosts:
     - ratings
     http:
     - match:
       - headers:
           end-user:
             exact: jason
       fault:
         abort:
           percentage:
             value: 100.0
           httpStatus: 500
       route:
       - destination:
           host: ratings
           subset: v1
     - route:
       - destination:
           host: ratings
           subset: v1
   EOF
   ```

## Testing the abort configuration

1. Open the Bookinfo web application in your browser.

2. On the `/productpage`, log in as user `jason`.

   If the rule propagated successfully to all pods, the page loads immediately and the `Ratings service is currently unavailable` message appears.

   ![Fault_Injection2](images/fault_injection2.png)

3. If you log out from user `jason` or open the Bookinfo application in an anonymous window (or in another browser), you will see that `/productpage` still calls `reviews:v1` (which does not call `ratings` at all) for everybody but `jason`. Therefore you will not see any error message.

## Cleanup

1. Remove the application routing rules:

   ```bash
   kubectl delete virtualservice ratings
   ```

2. If you are not planning to explore any follow-on tasks, refer to the [Install Waypoint/Cleanup](/docs/application-layer/install_waypoint.md#cleanup) instructions to shutdown the application.

## Demo

<div className="video-responsive">
  <iframe
    src="https://www.youtube.com/embed/tWgRaU_Zw8I"
    frameborder="0"
    allowfullscreen
  ></iframe>
</div>
