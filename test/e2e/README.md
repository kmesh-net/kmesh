# Kmesh E2E test

Kmesh E2E test is used to validate the system as a whole, ensuring that all the individual components and integrations work together seamlessly.

It's integrated into CI to ensure that each merge of code will not break existing functions. You can also run it locally during development for self-testing. It plays an important role in maintaining the stability and availability of Kmesh.

NOTE: Kmesh E2E test framework and test cases is heavily inspired by istio integration framework (<https://github.com/istio/istio/tree/master/tests/integration>), both in architecture and code.
