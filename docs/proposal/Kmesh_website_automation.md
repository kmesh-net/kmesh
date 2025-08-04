---
title: Proposal for Website automation and Chinese docs optimization
authors:
  - "@yashisrani"
reviewers:
  - "@lizhencheng"
approvers:
  - "@lizhencheng"

creation-date: 2025-07-07
---

## Proposal for Website automation and Chinese docs optimization

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

- Currently, the Kmesh project lacks effective automation for its website and documentation. Documentation is manually copied to the website, leading to inconsistencies and duplicated effort. A recent website refactor added a feature to archive old documents, but the process still relies on manual CLI steps during each release.

- The Chinese documentation lacks any automated checks for typos or grammatical errors.

- The goal is to make docs updates effortless, ensure versioned archives and enhance Chinese content quality, all without manual steps.

### Motivation

<!--
This section is for explicitly listing the motivation, goals, and non-goals of
this KEP.  Describe why the change is important and the benefits to users.
-->
- Manual documentation updates and versioning in the Kmesh project are time-consuming and error-prone. For instance, each release requires developers to manually copy files, archive old documentation, and update the website, which diverts engineering resources from core development tasks. Similarly, the lack of automated checks for Chinese documentation risks publishing error-ridden content, reducing its usability.

- Previous Kmesh workflows were manual and time-consuming, and new releases required repetitive manual steps, wasting engineering time.

- Automating these tasks will free the team to focus on building new features rather than maintaining docs by hand.

#### Goals

<!--
List the specific goals of the KEP. What is it trying to achieve? How will we
know that this has succeeded?
-->

- Automate the synchronization of Kmeshctl documentation from the main repository to the website.
- Automate Versioned documentation release process, including archiving old docs and publishing new versions.
- (if feasible) Implement automated typo and grammar checks for chinese documentation.

#### Non-Goals

<!--
What is out of scope for this KEP? Listing non-goals helps to focus discussion
and make progress.
-->

- Optimizing English documentation (out of scope for this proposal).
- Implementing selective file syncing for specific documentation subsets.

### Proposal

<!--
This is where we get down to the specifics of what the proposal actually is.
This should have enough detail that reviewers can understand exactly what
you're proposing, but should not include things like API designs or
implementation. What is the desired outcome and how do we measure success?.
The "Design Details" section below is for the real
nitty-gritty.
-->

#### 1. Kmeshctl Syncing Tool

- **Solution - 1:**

  - It clones `Kmesh-net/kmesh`, copies `docs/ctl/` to `website/docs/`, using Github action workflow.
  - **Implementation:**

    The Sync kmeshctl Docs workflow:

    - Triggers on pushes to the main branch of kmesh-net/kmesh with changes in `docs/ctl/**`.
    - Copies the `kmesh/docs/ctl/` folder to `website/docs/kmeshctl/`, creating the target folder if it doesn’t exist.
    - Commits and pushes changes to `kmesh-net/website`.

![design](/docs/pics/kmeshctl-sync-2.png)

<br/>

- **Workflow Explanation:**
  - **Start**: A push to the main branch of kmesh-net/kmesh with changes in the `docs/ctl/`folder triggers the workflow.
  - **Checkout Repositories**: The workflow downloads the `kmesh-net/kmesh` and `kmesh-net/website` repositories.
  - **Validate**: Checks that the `kmesh/docs/ctl/` folder exists and contains files.
  - **Create Folder**: Creates the `website/docs/kmeshctl/` folder if it doesn’t exist.
  - **Sync Files**: Copies the kmeshctl docs from `kmesh/docs/ctl/` to `website/docs/kmeshctl/` using rsync.
  - **Save Changes**: Commits and pushes the updated files to the `kmesh-net/website` repository.

<br/>

- **Pros:**
  - **Keeps Docs Up-to-Date**: Automatically updates `website/docs/kmeshctl/` with the latest kmeshctl docs whenever changes are made to `kmesh-net/kmesh/docs/ctl/`, ensuring the website reflects current documentation.
  - **Efficient Syncing**: Uses rsync to copy only changed files, making updates quick even for small changes.
  - **Reliable**: Includes checks to ensure the `kmesh/docs/ctl/` folder and files exist, preventing errors if something’s missing.

<br/>

- **Cons:**
  - **Limited to kmeshctl Docs**: Only syncs `kmesh/docs/ctl/` to `website/docs/kmeshctl/`. If you need to sync other folders (e.g., docs/guides/), the workflow would need modification (not an issue since you specified only kmeshctl).
  - **Checkout Overhead**: Downloads both `kmesh-net/kmesh` and `kmesh-net/website` repositories, which may take ~5-10 seconds each, even with shallow clones. This is minor for small repos but could slow down if repos grow large.

<br/>

- **Solution - 2:**

  - We can keep all those docs in one place (Website repo or main repo) and we can create script to copy all needed docs. this technique used by prometheus-operator.
  - prometheus-operator having all documentation in main repository and it's website having shell script to copy all needed docs which they want to show on website.
  - **Prometheus-Operaror** website shell-script :
    `https://github.com/prometheus-operator/website/blob/main/synchronize.sh`

![design](/docs/pics/kmeshctl-sync-1.png)

**Workflow Explanation:**

- A Netlify webhook is triggered by a commit merged to `kmesh-net/kmesh/main` with changes in `docs/`.
- The shell script runs on the Netlify server, cloning both `kmesh-net/kmesh` and `kmesh-net/website` repositories.
- It copies only the required folders (`application-layer`, `architecture`, `community`, `developer-guide`, `performance`, `setup`, `transport-layer`, `kmeshctl`) from `kmesh-net/kmesh/docs/` to `kmesh-net/website/docs/`.
- The script triggers the Netlify build process to generate and deploy the updated website, without committing or pushing changes to the `kmesh-net/website` repository.
  
<br/>

- **Pros:**
  - Simplifies deployment on Netlify without requiring repository commits.
  - Uses rsync (a fast tool inspired by Prometheus Operator) to copy only changed files, making updates quick even for small changes.
  - Includes checks to ensure the `kmesh/docs/ctl/` folder and files exist, preventing errors if something’s missing.
  
<br/>  

- **Cons:**
  - limitations in scaling if the website repo grows significantly.
  - Netlify-specific dependencies (e.g, Netlify CLI setup).

---

- **Advantages and Disadvantages of Each Solution:**

  - **Solution-1 ( Advantages ):**

    - Targets only the `docs/ctl/` directory, keeping updates isolated and reducing noise in the website repository.
    - Includes validation steps to check for folder and file existence, minimizing the risk of errors.
    - A straightforward and familiar approach using GitHub Actions.
    - Keeps the main kmesh repository and website repository independent while syncing only the necessary files.
  
  - **Solution-1 ( Disadvantages ):**

    - Limited to syncing only the `docs/ctl/` folder. Adding additional documentation would require workflow modifications.
    - Creates commits in the website repository for every doc change, which may add commit noise.
    - Tightly coupled to GitHub Actions, making it less portable if switching CI/CD platforms.
    - Workflow can grow more complex when scaling to multiple documentation sections.

  - **Solution-2 ( Advantages ):**

    - Documentation remains in a single source of truth (main repository), simplifying management.
    - Automatically triggered by Netlify webhook without the need to commit or push changes to the website repository.
    - A proven approach used by Prometheus Operator, which makes it a reliable reference design.
    - Uses rsync to efficiently copy only updated files.
    - Capable of copying multiple folders in a single process, making it easier to scale for future documentation needs.

  - **Solution-2 ( Disadvantages ):**

    - If the website repository grows significantly, the script may face scaling limitations.
    - Shell script complexity can increase as the documentation structure expands.
    - Cloning repositories and copying files happen during the Netlify build, which may slightly increase build time.
    - Tied to Netlify’s ecosystem and requires specific Netlify CLI setup.

---

#### 2. Versioning Workflow

- **Solution - 1:**
  - **Workflow Explanation:**
    - When a new release is planned, a maintainer updates the `VERSION` file in `kmesh-net/website` (e.g., from `v1.0.0` to `v1.1.0`) and pushes the change.
    - This triggers a CI pipeline in the `kmesh-net/website` repository.
    - The pipeline checks out the website repository, sets up Node.js and Docusaurus, validates the `docs/` directory, creates a versioned snapshot (e.g., `versioned_docs/version-1.1.0/`) using the `VERSION` file content, and commits the changes back to the `kmesh-net/website` repository.
    - This ensures historical docs are archived and accessible via Docusaurus’s version navigation.

![design](/docs/pics/website-versioning-archiving-1.png)

- **Pros:**
  - CI pipeline automates versioning based on `VERSION` file changes, reducing manual effort.
  - Reduces unnecessary CI runs.
  - Simple version management.

<br/>

- **Cons:**
  - Manual updates risk errors.
  - Potential risks, if the `VERSION` file format is incorrect.
  - No tag-based fallback.

<br/>

- **Solution - 2:**

  - This workflow saves a snapshot of the kmesh website’s documentation (stored in `kmesh-net/website/docs/`) whenever a new version of the kmesh project is released (e.g., `v1.0.0`, `v2.0.0`). It uses Docusaurus, a tool that organizes documentation, to create a versioned archive (like a backup) of the docs, so users can view older versions of the website’s documentation, including the kmeshctl docs (added by the separate sync workflow).
  - This ensures the website always shows the latest docs while keeping a history of past versions.
  - **When It Runs:** The workflow starts when a new version tag (e.g., `v1.0.0`) is pushed to the kmesh-net/kmesh repository.

![design](/docs/pics/website-versioning-archiving-2.png)

**Workflow Explanation:**

- **Clone Website Code:** Gets the `kmesh-net/website` repository, which contains the website’s documentation and Docusaurus setup.
- **Set Up Docusaurus:** Install Docusaurus, the tool used to manage and version the website’s docs.
- **Check Docs Folder:** Makes sure the `website/docs/` folder exists and has files to avoid errors.
- **Get Version Number:** Extracts the version tag (e.g., `v1.0.0`) to use for archiving.
- **Archive Docs:** Saves a snapshot of the `website/docs/` folder (including kmeshctl/) as a versioned copy (e.g., `v1.0.0`) using Docusaurus.
- **Save Changes:** Updates the website repository with the versioned snapshot and Docusaurus settings.

<br/>

- **Pros:**
  - **Saves Version History:** Archives all website docs (including kmeshctl/) for each release (e.g., v1.0.0), enabling users to access documentation for specific kmesh versions via Docusaurus’s version navigation.
  - **Fast Execution:** Completes in ~15-20 seconds using shallow clones and cached Docusaurus dependencies, efficient for infrequent tag pushes.
  - **Reliable:** Checks that website/docs/ exists and contains files, preventing failures due to missing or empty folders.

<br/>

- **Cons:**
  - **Cross-Repository Trigger:** Runs in kmesh-net/kmesh (triggered by tags) but modifies kmesh-net/website, which may confuse contributors expecting the workflow in the website repo.
  - **Token Dependency:** Requires `WEBSITE_REPO_TOKEN` with write access to kmesh-net/website, needing secure setup and documentation.
  - **Docusaurus Dependency:** Assumes kmesh-net/website is a properly configured Docusaurus project. Misconfiguration could cause failures, requiring testing to confirm setup.

---

#### 3. Chinese Docs Workflow (BONUS)

- **Solution - 1:**

  - Checks `kmesh/website/docs/` for typos/grammar using **LanguageTool (Open Source)** or **Tencent/Alibaba (Paid APIs)**, show Logs errors for manual reviews.
  
![design](/docs/pics/Chinese_doc_check.png)

```yaml
name: Chinese Grammar Check

on:
  push:
    branches: [main]
    paths:
      - 'docs/**'
      - 'docs/proposal/**'
  pull_request:
    branches: [main]
    paths:
      - 'docs/**'
      - 'docs/proposal/**'

jobs:
  grammar-check:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pycorrector

      - name: Run grammar check
        run: |
          python -c "
          import os
          import pycorrector
          from pathlib import Path

          def check_grammar_in_file(file_path):
              with open(file_path, 'r', encoding='utf-8') as file:
                  text = file.read()
              errors = pycorrector.detect(text)
              return errors

          directories = ['docs', 'docs/proposal']
          error_found = False
          error_messages = []

          for directory in directories:
              for file_path in Path(directory).rglob('*.md'):
                  if file_path.is_file():
                      print(f'Checking file: {file_path}')
                      errors = check_grammar_in_file(file_path)
                      if errors:
                          error_found = True
                          error_messages.append(f'Grammar errors in {file_path}:')
                          for error in errors:
                              error_messages.append(f' - {error}')
                      else:
                          print(f'No grammar errors found in {file_path}')

          if error_found:
              print('\nGrammar errors found:')
              for msg in error_messages:
                  print(msg)
              exit(1)
          else:
              print('\nNo grammar errors found in any files.')
              exit(0)
          "
```

---

#### Preferred Solution

- After evaluating both approaches for each identified problem, we recommend adopting Solution 1 for all three workflows (Kmeshctl Syncing Tool, Versioning Workflow, and Chinese Docs Workflow).
  - **For Kmeshctl syncing,** Solution 1 provides a lightweight and reliable GitHub Actions-based mechanism to automatically keep `website/docs/kmeshctl/` in sync with changes to `docs/ctl/` in the main repository. This approach minimizes manual intervention and ensures the website always reflects the latest kmeshctl documentation.
  - **For versioning,** Solution 1 simplifies version management by leveraging a `VERSION` file and a dedicated CI pipeline within the website repository. This design is straightforward to maintain, avoids cross-repository complexity, and provides a controlled mechanism for creating and archiving versioned documentation snapshots.
  - **For Chinese documentation checks,** Solution offers an automated grammar and typo validation using open-source tools. This solution seamlessly integrates into the CI pipeline, providing immediate feedback on errors without requiring paid external services or complex setups.
  
---

#### User Stories (Optional)

<!--
Detail the things that people will be able to do if this KEP is implemented.
Include as much detail as possible so that people can understand the "how" of
the system. The goal here is to make this feel real for users without getting
bogged down.
-->

##### Story 1

- As a Kmesh developer, I want `kmesh/docs/` changes to automatically trigger a Netlify build and deploy the updated website, so users see the latest docs without manual intervention.

##### Story 2

- As a website maintainer, I want versioning to happen automatically when the VERSION file is updated, archiving old docs and committing changes via CI.

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

`act -w .github/workflows/kmeshctl-sync-docs.yml`
`act -W .github/workflows/trigger-netlify-build.yml`
`act -W .github/workflows/version-and-publish-docs.yml`
`act -W .github/workflows/check-chinese-docs.yml`

Requires Docker and act installed, set `WEBSITE_REPO_TOKEN` in `.env`

- **Clone local repo:** We can clone the kmesh repo, push changes to that repo and test the workflow.

### Alternatives

<!--
What other approaches did you consider, and why did you rule them out? These do
not need to be as detailed as the proposal, but should include enough
information to express the idea and why it was not acceptable.
-->

<!--
Note: This is a simplified version of kubernetes enhancement proposal template.
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->
