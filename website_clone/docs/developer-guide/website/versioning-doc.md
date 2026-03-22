---
title: Version management
sidebar_position: 2
---

# Versioning Documentation in Docusaurus: A Comprehensive Guide

Docusaurus offers robust built-in support for versioning documentation, a critical feature for projects that evolve over time. Versioning allows you to maintain multiple versions of your documentation, ensuring users can access information relevant to the specific version of your software they are using. This comprehensive document will walk you through the process of setting up, managing, and optimizing versioned documentation in Docusaurus.

---

## 1. Understanding Versioning in Docusaurus

Docusaurus provides a straightforward system for versioning documentation:

- **Current Version**: This is the latest, actively maintained version of your documentation, stored in the `docs/` folder. It typically represents the "Next" version or the most recent unreleased changes.
- **Versioned Docs**: These are snapshots of your documentation at specific points in time, usually tied to software releases. They are stored in folders named `versioned_docs/version-<version>/`, such as `versioned_docs/version-1.0/` for version 1.0.

For example:

```text
// Project directory structure with versioning
my-docusaurus-project/
├── docs/                       # Current version documentation
├── versioned_docs/             # All versioned documentation
│   ├── version-1.0/            # Version 1.0 documentation
│   └── version-1.1/            # Version 1.1 documentation
├── versioned_sidebars/         # Sidebars for each version
│   ├── version-1.0-sidebars.json
│   └── version-1.1-sidebars.json
└── versions.json               # List of all available versions
```

Each versioned set of documentation is a complete copy of the `docs/` folder at the time the version was created.

---

## 2. Setting Up Versioning

To begin versioning your documentation in Docusaurus, follow these steps:

### Step 1: Create Your First Version

When you're ready to release a new version of your software, create a versioned snapshot of your current documentation:

- Run the following command in your terminal:

```bash
# File: terminal command
npm run docusaurus docs:version <version>
```

or

```bash
# File: terminal command
yarn docusaurus docs:version <version>
```

Replace `<version>` with your desired version number, e.g., `1.0`.

- **What Happens**:
  - Docusaurus duplicates the entire `docs/` folder into `versioned_docs/version-1.0/`.
  - It updates the `versions.json` file, which tracks all versioned documentation.

Example `versions.json` after creating version 1.0:

```json
// File: versions.json
[
  "1.0"
]
```

### Step 2: Customize Version Labels

By default, the version number (e.g., "1.0") appears in the sidebar and version selector. You can customize these labels in `docusaurus.config.js`:

```javascript
// File: docusaurus.config.js
module.exports = {
  // ... other configuration
  themeConfig: {
    // ... other theme configuration
    docs: {
      sidebar: {
        versionLabels: {
          '1.0': 'Version 1.0 (Legacy)',
          '1.1': 'Version 1.1',
          'current': 'Next (Unreleased)'
        },
      },
    },
  },
};
```

---

## 3. Managing Versioned Documentation

Once versioning is set up, you can manage your documentation as follows:

### Updating Documentation

- **Current Version**: Edit files in the `docs/` folder to reflect the latest changes and features.
- **Versioned Docs**: To update a specific version (e.g., for corrections or clarifications), modify files in `versioned_docs/version-<version>/`.

**Note**: Limit changes to versioned docs to minor fixes. Major updates should go into the current version (`docs/`).

### Adding New Versions

When releasing a new software version:

```bash
# File: terminal command
# 1. Update docs/ folder with latest content
# 2. Run the versioning command
npm run docusaurus docs:version 2.0
```

This creates a new snapshot in `versioned_docs/version-2.0/` and updates `versions.json`:

```json
// File: versions.json (after adding version 2.0)
[
  "2.0",
  "1.0"
]
```

### Removing Versions

To delete a version:

```bash
# File: terminal command
# 1. Remove the version folder
rm -rf versioned_docs/version-1.0
rm -rf versioned_sidebars/version-1.0-sidebars.json

# 2. Update versions.json manually
```

Edit `versions.json` to remove the version:

```json
// File: versions.json (after removing version 1.0)
[
  "2.0"
]
```

---

## 4. Configuring the Sidebar for Versioned Docs

Docusaurus handles sidebars for each version automatically, but you can customize them if needed.

### Automatic Sidebar Generation

When you create a version, Docusaurus automatically creates a sidebar configuration:

```json
// File: versioned_sidebars/version-1.0-sidebars.json (automatically generated)
{
  "version-1.0/docs": [
    {
      "type": "category",
      "label": "Getting Started",
      "items": [
        {
          "type": "doc",
          "id": "version-1.0/intro"
        },
        {
          "type": "doc",
          "id": "version-1.0/installation"
        }
      ]
    }
  ]
}
```

### Manual Sidebar Configuration

For more control, you can modify the versioned sidebar file directly:

```javascript
// File: versioned_sidebars/version-1.0-sidebars.json (customized)
{
  "version-1.0/docs": [
    {
      "type": "category",
      "label": "Getting Started",
      "items": [
        {
          "type": "doc",
          "id": "version-1.0/intro"
        },
        {
          "type": "doc",
          "id": "version-1.0/installation"
        }
      ]
    },
    {
      "type": "category",
      "label": "Advanced Topics",
      "items": [
        {
          "type": "doc",
          "id": "version-1.0/advanced/configuration"
        }
      ]
    }
  ]
}
```

---

## 5. Linking to Versioned Docs

### Version Dropdown Component

Docusaurus adds a version selector dropdown to your site navigation:

```jsx
// File: src/theme/Navbar.js (automatically handled by Docusaurus)
import React from 'react';
import VersionsDropdown from '@theme/VersionsDropdown';

function Navbar() {
  return (
    <nav>
      {/* ... other navbar items */}
      <VersionsDropdown />
    </nav>
  );
}
```

### Creating Custom Links to Specific Versions

In your documentation, you can link to specific versions:

```markdown
<!-- File: docs/my-doc.md -->

Check our [installation guide for v1.0](/docs/1.0/installation) or the [latest installation guide](/docs/installation).
```

---

## 6. Best Practices for Versioning

- **Version Naming**: Use semantic versioning (e.g., 1.0, 1.1, 2.0) for clarity.

  ```text
  // Recommended version naming
  1.0, 1.1, 2.0  // ✓ Semantic versioning
  
  // Not recommended
  stable, beta, old  // ✗ Ambiguous naming
  ```

- **Configuration Example** for managing version labels and visibility:

  ```javascript
  // File: docusaurus.config.js
  module.exports = {
    // ... other configuration
    presets: [
      [
        '@docusaurus/preset-classic',
        {
          docs: {
            // ... other docs configuration
            lastVersion: 'current',
            versions: {
              current: {
                label: 'Next',
                path: 'next',
              },
              '2.0': {
                label: '2.0',
                path: '2.0',
              },
              '1.0': {
                label: '1.0 (Legacy)',
                path: '1.0',
                banner: 'unmaintained', // Adds a banner indicating this version is no longer maintained
              },
            },
          },
        },
      ],
    ],
  };
  ```

---

## 7. Example Scenario

Let's walk through versioning for a software project with two releases: 1.0 and 2.0.

```bash
# File: terminal commands for versioning workflow
# Initial setup - create version 1.0
npm run docusaurus docs:version 1.0

# Result:
# - versioned_docs/version-1.0/ contains a snapshot of docs/
# - versioned_sidebars/version-1.0-sidebars.json is created
# - versions.json now includes "1.0"

# Later - update docs/ with changes for version 2.0 and create version 2.0
npm run docusaurus docs:version 2.0

# Result: 
# - versioned_docs/version-2.0/ is created
# - versioned_sidebars/version-2.0-sidebars.json is created
# - versions.json now includes "2.0" and "1.0"
# - docs/ becomes the "Next" version
```

Final project structure:

```text
# File: Project structure after versioning
my-docusaurus-project/
├── docs/                       # Current "Next" version
├── versioned_docs/
│   ├── version-2.0/            # Version 2.0 documentation
│   └── version-1.0/            # Version 1.0 documentation
├── versioned_sidebars/
│   ├── version-2.0-sidebars.json
│   └── version-1.0-sidebars.json
└── versions.json               # ["2.0", "1.0"]
```

The result is a site where users can easily navigate between versions through the dropdown menu:

- **Next**: Latest unreleased changes
- **2.0**: Documentation for version 2.0
- **1.0 (Legacy)**: Documentation for version 1.0

---

## 8. Additional Resources

For more in-depth information, refer to the official Docusaurus documentation:

- [https://docusaurus.io/docs/versioning](https://docusaurus.io/docs/versioning)

---

This guide provides everything you need to create and manage versioned documentation in Docusaurus. By following these steps, you can ensure your users have access to the right documentation for their software version. Happy documenting!
