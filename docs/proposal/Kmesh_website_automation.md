---
title: Proposal for Website automation and chinese docs optimization
authors:
  - "@yashisrani"
reviewers:
  - "@lizhencheng"
approvers:
  - "@lizhencheng"

creation-date: 2025-07-07
---

## Proposal for Website automation and chinese docs optimization

<!--
This is the title of your KEP. Keep it short, simple, and descriptive. A good
title can help communicate what the KEP is and should be considered as part of
any review.
-->

Upstream issue: <https://github.com/kmesh-net/kmesh/issues/1412>

### Summary

<!--
This section is incredibly important for producing high-quality, user-focused
documentation such as release notes or a development roadmap.

A good summary is probably at least a paragraph in length.
-->

- Currently, Kmesh project lacked good automation around website & documentation. We want to manually copy and paste documentation into a website. which often led to inconsistencies and duplicate effort across teams. When website was recently refactored, a new feature to archive old documents was added, but it still dependent on manual CLI steps during each release.

- The chinese documentation lacking any automated checks for typos or grammatical errors.

- The goal is to make docs updates effortless, ensure versioned archives and enhance Chinese content quality, all without manual steps.

### Motivation

<!--
This section is for explicitly listing the motivation, goals, and non-goals of
this KEP.  Describe why the change is important and the benefits to users.
-->

- Kmesh Previous workflows were manual & time consuming and new releases required repetitve manual step, wasting engineering time.

- Automating these tasks will free the team to focus on building new features rather than maintaining docs by hand.

#### Goals

<!--
List the specific goals of the KEP. What is it trying to achieve? How will we
know that this has succeeded?
-->

- Automate Synchronize of Kmeshctl documentation from main repository to the website.
- Automate Versioned documentation release process, including archiving old docs and publishing new versions.
- (if feasible) Implement automated typo and grammar checks for chinese documentation.

#### Non-Goals

<!--
What is out of scope for this KEP? Listing non-goals helps to focus discussion
and make progress.
-->

- English Docs Optimization.
- Selective File Syncing
- Pull Request Automation

### Proposal

<!--
This is where we get down to the specifics of what the proposal actually is.
This should have enough detail that reviewers can understand exactly what
you're proposing, but should not include things like API designs or
implementation. What is the desired outcome and how do we measure success?.
The "Design Details" section below is for the real
nitty-gritty.
-->

**1. Kmeshctl Syncing Tool:**

- **Solution - 1 Script (`website/scripts/sync-kmeshctl-docs.sh`):**

  - It clones `Kmesh-net/kmesh`, copies `docs/ctl/` to `website/docs/` , using Github action workflow.

- **Solution - 2**

  - We can keep all those docs in one place (Website repo or main repo) and we can create script to copy all needed docs. this technique used by prometheus-operator.
  - prometheus-operator having all documentation in main repository and it's website having shell script to copy all needed docs which they want to show on website.
  - **Prometheus-Operaror** website shell-script :
    `https://github.com/prometheus-operator/website/blob/main/synchronize.sh `

**2. Versioning Workflow:**

- The Version and Publish kmesh Docs workflow runs in the `kmesh-net/kmesh` repository when you push a tag (e.g., v1.0.0).
- It automatically archives old documentation from `kmesh-net/website/docs/` to a versioned folder (e.g., `versioned_docs/version-v1.0.0/`), updates Docusaurus files for version navigation, and copies new `kmesh/docs/` files to `kmesh/website/docs/`.

**3. Chinese Docs Workflow (BONUS):**

- **Solution - 1**

  - Checks `kmesh/website/docs/*-zh.md` and `*_CN.md` for typos/grammar using **LanguageTool**, Logs errors, and sends slack notifications for manual reviews.

- **Solution - 2**

  - We can create a new folder which will contain all chinese documentation, then we can perform same typos/grammar checks using **LanguageTool**. in this case, There is no need to add a condition like (_-zh.md, _\_CN.md).

#### User Stories (Optional)

<!--
Detail the things that people will be able to do if this KEP is implemented.
Include as much detail as possible so that people can understand the "how" of
the system. The goal here is to make this feel real for users without getting
bogged down.
-->

##### Story 1

- As a kmesh developer, I want `kmesh/docs/ctl/` changes to automatically update the website, so users always see the latest guides without manual effort.

##### Story 2

- As a website maintainer, I want old docs archived and new versions published when a tag is created, so users can access historical versions via Docusaurus.

#### Notes/Constraints/Caveats (Optional)

<!--
What are the caveats to the proposal?
What are some important details that didn't come across above?
Go in to as much detail as necessary here.
This might be a good place to talk about core concepts and how they relate.
-->

#### Risks and Mitigations

<!--
What are the risks of this proposal, and how do we mitigate?

How will security be reviewed, and by whom?

How will UX be reviewed, and by whom?

Consider including folks who also work outside the SIG or subproject.
-->

- **Risk**: versioning fails if Docusaurus is misconfigured.

  - **Mitigation**: Test Docusaurus setup locally before deployment.

- **Risk**: LanguageTool misses Chinese-specific errors.
  - **Mitigation**: Use Slack notifications for manual review; test LanguageTool locally.

### Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
-->

#### Test Plan

<!--
**Note:** *Not required until targeted at a release.*

Consider the following in developing a test plan for this enhancement:
- Will there be e2e and integration tests, in addition to unit tests?
- How will it be tested in isolation vs with other components?

No need to outline all test cases, just the general strategy. Anything
that would count as tricky in the implementation, and anything particularly
challenging to test, should be called out.

-->

- **kmeshctl Sync Script:** run `./scripts/sync-kmeshctl-docs.sh` to verify file copying.
- **Act Tool:** We can use `act` to test workflows locally.

```
act -w .github/workflows/kmeshctl-sync-docs.yml
act -W .github/workflows/trigger-netlify-build.yml
act -W .github/workflows/version-and-publish-docs.yml
act -W .github/workflows/check-chinese-docs.yml
```

Requires Docker and act installed, set `WEBSITE_REPO_TOKEN` in `.env`

### Alternatives

<!--
What other approaches did you consider, and why did you rule them out? These do
not need to be as detailed as the proposal, but should include enough
information to express the idea and why it was not acceptable.
-->

**1. Github Actions for Sync:**

- Instead of Netlify-triggered script, use a Github Action to sync `kmesh/docs/ctl/` to `kmesh/website/docs` and commit directly.
- **Pros**: Unified Automation in Github, No Netlify Dependency.
- **Cons**: Required managing commits.

**2. Manual Versioning:**

- Manually run Docusaurus versioning commands instead of a workflow.
- **Pros**: Simpler initial setup.
- **Cons**: Required managing commits.

**3. External Chinese NLP Tools:**

- Use APIs for advanced chinese typo/grammar checks.
- **Pros**: More accurate than LanguageTool for chinese.
- **Cons**: Paid, Complex setup, not open-source.

<!--
Note: This is a simplified version of kubernetes enhancement proposal template.
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->
