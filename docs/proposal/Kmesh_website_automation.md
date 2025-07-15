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

- **Solution - 1**

  - We can keep all those docs in one place (Website repo or main repo) and we can create script to copy all needed docs. this technique used by prometheus-operator.
  - prometheus-operator having all documentation in main repository and it's website having shell script to copy all needed docs which they want to show on website.
  - **Prometheus-Operaror** website shell-script :
    `https://github.com/prometheus-operator/website/blob/main/synchronize.sh`

![design](/docs/pics/kmeshctl-sync-1.png)

**Workflow Explanation:**

- This shell script, modeled after the Prometheus Operator’s sync script, copies only the required folders (`application-layer`, `architecture`,`community`, `developer-guide`, `performance`, `setup`, `transport-layer`, `kmeshctl`) from `kmesh-net/kmesh/docs/` to `kmesh-net/website/docs/`
- when a Netlify webhook is triggered by a commit merged to `kmesh-net/kmesh/main` with changes in docs/.
- It commits and pushes the changes to `kmesh-net/website/main`, ensuring the website reflects only the specified doc folders.

```bash
#!/usr/bin/env bash

set -xe

# Clean up temporary repos directory
rm -rf repos/
mkdir -p repos/

# Clone kmesh and website repositories
git clone https://github.com/kmesh-net/kmesh --depth 1 repos/kmesh
git clone https://github.com/kmesh-net/website --depth 1 repos/website

# Log commit hashes for debugging
for repo in repos/kmesh repos/website; do
  echo "$repo -> $(cd $repo && git rev-parse HEAD)"
done

# Validate source directory and required folders
if [ ! -d "repos/kmesh/docs" ]; then
  echo "Error: Directory repos/kmesh/docs does not exist"
  exit 1
fi
required_folders=("application-layer" "architecture" "community" "developer-guide" "performance" "setup" "transport-layer" "kmeshctl")
for folder in "${required_folders[@]}"; do
  if [ ! -d "repos/kmesh/docs/$folder" ]; then
    echo "Error: Required folder repos/kmesh/docs/$folder does not exist"
    exit 1
  fi
done

# Create target docs directory if it doesn't exist
mkdir -p repos/website/docs

# Copy required folders from kmesh/docs/ to website/docs/
for folder in "${required_folders[@]}"; do
  cp -r "repos/kmesh/docs/$folder" repos/website/docs/ || { echo "Error: cp failed for $folder"; exit 1; }
done
echo "Synced required folders to repos/website/docs/"

# Commit and push changes to website repo
cd repos/website
git config user.name "Kmesh Sync Bot"
git config user.email "bot@kmesh.net"
git add docs/
if git diff --staged --quiet; then
  echo "No changes to commit"
  exit 0
fi
git commit -m "Sync required folders from kmesh-net/kmesh [$(date -u +%Y-%m-%d)]"
git push https://$GITHUB_TOKEN@github.com/kmesh-net/website
```

- **Solution - 2:**

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
  - **Efficient Syncing**: Uses rsync (a fast tool inspired by Prometheus Operator) to copy only changed files, making updates quick even for small changes.
  - **Reliable**: Includes checks to ensure the `kmesh/docs/ctl/` folder and files exist, preventing errors if something’s missing.

<br/>

- **Cons:**
  - **Limited to kmeshctl Docs**: Only syncs `kmesh/docs/ctl/` to `website/docs/kmeshctl/`. If you need to sync other folders (e.g., docs/guides/), the workflow would need modification (not an issue since you specified only kmeshctl).
  - **Checkout Overhead**: Downloads both `kmesh-net/kmesh` and `kmesh-net/website` repositories, which may take ~5-10 seconds each, even with shallow clones. This is minor for small repos but could slow down if repos grow large.

#### 2. Versioning Workflow

- **Solution - 1:**

  - The versioning process using the `VERSION` file begins when developers update documentation in `kmesh-net/kmesh/docs/` and push changes, triggering the `sync-kmesh-docs.sh` script via a Netlify webhook to sync required folders to `kmesh-net/website/docs/`. Next, a developer updates the `VERSION` file in `kmesh-net/website` (e.g., from `v1.0.0` to `v1.1.0`) and pushes the change, activating the **Version kmesh Website Docs** workflow.
  - The workflow then checks out the local repo, sets up Node.js and Docusaurus, validates the `docs/` directory, creates a versioned snapshot (e.g., `versioned_docs/version-1.1.0/`) using the `VERSION` content, and commits it back to the repository.
  - This process ensures historical docs are archived and accessible via Docusaurus.

![design](/docs/pics/website-versioning-archiving-1.png)

- **Pros:**
  - Controlled, intentional versioning.
  - Reduces unnecessary CI runs.
  - Simple version management.

<br/>

- **Cons:**
  - Manual updates risk errors.
  - Requires sync coordination.
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
  - **Token Dependency:** Requires WEBSITE_REPO_TOKEN with write access to kmesh-net/website, needing secure setup and documentation.
  - **Docusaurus Dependency:** Assumes kmesh-net/website is a properly configured Docusaurus project. Misconfiguration could cause failures, requiring testing to confirm setup.

```yaml
name: Version kmesh Website Docs
on:
  push:
    tags: ['v*']
jobs:
  version-docs:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: Checkout website repo
        uses: actions/checkout@v4
        with:
          repository: kmesh-net/website
          path: website
          token: ${{ secrets.WEBSITE_REPO_TOKEN }}
          fetch-depth: 1
      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'
          cache-dependency-path: website/package-lock.json
      - name: Install Docusaurus
        run: cd website && npm install
      - name: Validate docs directory
        run: |
          [ -d "website/docs" ] || { echo "Error: website/docs missing"; exit 1; }
          ls "website/docs/"* >/dev/null 2>&1 || { echo "Error: No files in website/docs"; exit 1; }
      - name: Extract tag version
        run: echo "VERSION=${GITHUB_REF#refs/tags/}" >> $GITHUB_ENV
      - name: Version website docs
        run: |
          cd website
          npx docusaurus docs:version ${{ env.VERSION }}
          echo "Versioned website docs for ${{ env.VERSION }}"
      - name: Commit changes
        run: |
          cd website
          git config user.name "Kmesh Version Bot"
          git config user.email "bot@kmesh.net"
          git add docs versioned_docs versioned_sidebars.json versions.json
          git diff --staged --quiet && { echo "No changes to commit"; exit 0; }
          git commit -m "Version website docs for ${{ env.VERSION }} [$(date -u +%Y-%m-%d)]"
          git push origin main
```

#### 3. Chinese Docs Workflow (BONUS)

- **Solution - 1**

  - Checks `kmesh/website/docs/*-zh.md` and `*_CN.md` for typos/grammar using **LanguageTool**, Logs errors, and sends slack notifications for manual reviews.

![design](/docs/pics/Chinese_doc_check.png)

```yaml
name: Check Chinese Documentation

on:
  push:
    branches:
      - main
    paths:
      - 'docs/*-zh.md'
      - 'docs/*_CN.md'

jobs:
  check-chinese-docs:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout kmesh repository
        uses: actions/checkout@v4
        with:
          repository: kmesh-net/kmesh
          fetch-depth: 1

      - name: Validate directory
        run: |
          if [ ! -d "docs" ]; then
            echo "Error: Directory docs/ does not exist"
            exit 1
          fi
          if ! ls docs/*-zh.md docs/*_CN.md 2>/dev/null; then
            echo "No Chinese files (*-zh.md or *_CN.md) found in docs/"
            exit 0
          fi

      - name: Run LanguageTool for Chinese
        uses: reviewdog/action-languagetool@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          reporter: github-pr-review # Logs to Actions output, no PRs created
          level: warning
          language: zh-CN
          patterns: 'docs/*-zh.md docs/*_CN.md'
```

- **Solution - 2**

  - We can create a new folder which will contain all chinese documentation, then we can perform same typos/grammar checks using **LanguageTool**. in this case, There is no need to add a condition to identify Chinese doc.

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

`act -w .github/workflows/kmeshctl-sync-docs.yml`
`act -W .github/workflows/trigger-netlify-build.yml`
`act -W .github/workflows/version-and-publish-docs.yml`
`act -W .github/workflows/check-chinese-docs.yml`

Requires Docker and act installed, set `WEBSITE_REPO_TOKEN` in `.env`

### Alternatives

<!--
What other approaches did you consider, and why did you rule them out? These do
not need to be as detailed as the proposal, but should include enough
information to express the idea and why it was not acceptable.
-->

**1. Github Actions for Sync:**

- Instead of Netlify-triggered script, use a Github Action to sync `kmesh/docs/ctl/` to `kmesh/website/docs` and commit directly.
- **Pros:** Unified Automation in Github, No Netlify Dependency.
- **Cons:** Required managing commits.

**2. Manual Versioning:**

- Manually run Docusaurus versioning commands instead of a workflow.
- **Pros:** Simpler initial setup.
- **Cons:** Required managing commits.

**3. External Chinese NLP Tools:**

- Use APIs for advanced chinese typo/grammar checks.
- **Pros:** More accurate than LanguageTool for chinese.
- **Cons:** Paid, Complex setup, not open-source.

<!--
Note: This is a simplified version of kubernetes enhancement proposal template.
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->
