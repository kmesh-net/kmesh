---
sidebar_position: 3
title: Automation Workflows
---

# Project Documentation: Automation Workflows

This document outlines the automated workflows for the Kmesh project, designed to enhance documentation quality and streamline versioning.

## 1. kmeshctl Sync Workflow

**Purpose:** Automatically sync the kmeshctl CLI documentation from the kmesh repository to the kmesh-website repository via a Pull Request (PR).

**Workflow Trigger:** A push to the main branch of the kmesh repository, specifically when changes are made to the `docs/ctl/` directory.

### Steps

1. **Checkout Repositories:** The workflow checks out both the kmesh-website and kmesh repositories.
2. **Sync with rsync:** Uses the rsync command to synchronize the `docs/ctl/` directory from kmesh into the docs/kmeshctl/ directory of kmesh-website. The --delete flag ensures that deleted files are also removed.
3. **Create Pull Request:** If changes are detected, the workflow commits them and uses the `peter-evans/create-pull-request` action to create a PR in the kmesh-website repository. The branch name includes a timestamp to ensure uniqueness and prevent conflicts.

### Maintenance Notes

- **Secrets:** The `WEBSITE_PAT` secret must have write access to both the `kmesh-net/kmesh` and kmesh-net/website repositories.
- **Path Changes:** If the source or target directory paths change, update the `KMESH_CTL_DIR` and `WEBSITE_KMESHCTL_DIR` variables in the workflow.

## 2. Docusaurus Versioning and i18n (Chinese) Handling

The Docusaurus versioning system is designed to create new versions based on the content of the source docs/ directory. When the docusaurus docs:version command is executed, it automatically generates a new versioned folder (e.g., `versioned_docs/version-X.Y.Z/`) containing all the English documentation.

### Chinese Documentation (i18n) Versioning

- The Docusaurus versioning command does not automatically create a corresponding versioned folder for the Chinese translations located in `i18n/zh/docusaurus-plugin-content-docs/.`
- As a result, when a new version is created, there is no `i18n/zh/docusaurus-plugin-content-docs/version-X.Y.Z/` folder.
- This causes a "Page Not Found" error for users who have selected the Chinese language and navigate to the new version.

### Solution: Custom 404 Page

- To provide a seamless user experience, a custom 404 page has been implemented.
- When a Chinese user encounters a missing page for a new version, they are presented with a helpful error page.
- This page includes a prominent button that allows the user to easily redirect to the English version of the requested documentation or return to the homepage.
- This approach ensures that users always have access to the information they need, even if the Chinese translation for the latest version is not yet available.

This solution balances the need for up-to-date documentation with the practicalities of a multilingual site, where translation efforts may lag behind the release of new English content.

### Maintenance Notes

- This workflow relies on the `GITHUB_TOKEN` for PR creation.
- Ensure the `npm install` command is used, as a `package-lock.json` file is not available.

## 3. Chinese Grammar Check Workflow

**Purpose:** Automatically check the grammar and spelling of Chinese documentation.

**Workflow Trigger:** A push or pull request to the main branch, specifically when changes are made to files in the `docs/cn/zh/` directory.

### Steps

- **Checkout and Setup:** The workflow checks out the code and sets up a Python environment.
- **Install Dependencies:** Installs the language-tool-python package.
- **Run Grammar Check:** Uses the LanguageTool library to scan only the .md files within the `docs/cn/zh/` directory and its subdirectories for Chinese (zh-CN) content.
- **Report Issues:** The script provides detailed, color-coded output for any issues found, including the file, line number, error type (spelling, grammar, style), context, and suggestions. It also creates GitHub warning annotations.

### Maintenance Notes

- The workflow is robust and includes retries for initializing the LanguageTool service.
- It handles encoding errors gracefully.
- The output is designed to be highly readable for developers, classifying errors and providing actionable feedback.
