---
title: Create a Document
sidebar_position: 1
---

## Creating a Document in Docusaurus: A Beginner's Guide

Docusaurus is a powerful tool for building documentation websites with ease. It uses Markdown files to generate static HTML pages, making it simple to create and maintain your project’s documentation. In this guide, we’ll cover everything you need to know to create a document in Docusaurus, from understanding the folder structure to configuring the sidebar navigation.

### 1. Understanding the Docusaurus Folder Structure

When you set up a Docusaurus project, it creates a specific folder structure to organize your site. The key folders and files related to documentation are:

- **`docs/`**: This is where all your documentation files are stored. Each file in this folder is a Markdown file (with a `.md` or `.mdx` extension) that will be converted into a page on your documentation site.

- **`docusaurus.config.js`**: This is the main configuration file for your Docusaurus site. It controls settings like the site title, navigation, and more.

- **`sidebars.js`** (optional): This file allows you to manually configure the sidebar navigation for your documentation.

- **`static/`**: This folder holds static assets like images, which can be referenced in your documentation.

For example, a typical Docusaurus project might look like this:

```text
my-docusaurus-site/
├── docs/
│   ├── intro.md
│   └── getting-started.md
├── src/
│   └── pages/
├── static/
│   └── img/
├── docusaurus.config.js
├── package.json
└── sidebars.js
```

In this structure, the `docs/` folder is the central location for all documentation files. This is where you’ll create and store your documents.

### 2. Parameters at the Start of the Docs (Front Matter)

In Docusaurus, each Markdown file can have an optional **front matter** section at the top. The front matter is written in YAML format and is enclosed between triple dashes (`---`). It provides metadata about the document, allowing you to customize its behavior and appearance. Common parameters (fields) in the front matter include:

- **`id`**: A unique identifier for the document. If not specified, it defaults to the file name without the extension (e.g., `my-doc` for `my-doc.md`).
- **`title`**: The title of the document, displayed in the sidebar and page header. If omitted, Docusaurus uses the first heading in the file.
- **`slug`**: A custom URL path for the document (e.g., `/my-custom-url`).
- **`tags`**: Keywords for categorizing the document.

Here’s an example of a front matter:

```yaml
---
id: my-doc
title: My Document
slug: /my-custom-url
tags:
  - example
  - documentation
---
```

This front matter tells Docusaurus:

- The document’s unique ID is `my-doc`.
- The title is “My Document”.
- The URL path is `/my-custom-url` instead of the default `/docs/my-doc`.
- It’s tagged with “example” and “documentation”.

Front matter is optional, but it’s highly recommended for better control over your documents.

### 3. How Folder Structure Affects Paths and Sidebar Navigation

The folder structure within the `docs/` directory determines both the URL paths of your documents and the sidebar navigation.

- **URL Paths**: By default, the folder structure becomes part of the document’s URL. For example:

  - `docs/intro.md` → `/docs/intro`
  - `docs/architecture/overview.md` → `/docs/architecture/overview`
    You can override this with the `slug` parameter in the front matter.

- **Sidebar Navigation**: Docusaurus can automatically generate a sidebar based on your folder structure. Each subfolder in `docs/` becomes a category in the sidebar, and the files within that folder become links under that category. For example:

  ```text
  docs/
  ├── intro.md
  └── architecture/
      ├── overview.md
      └── components.md
  ```

  This structure might produce a sidebar like:

  - Intro
  - Architecture
    - Overview
    - Components

  The folder name (e.g., `architecture`) doesn’t automatically become the category name unless configured. You can customize this behavior using sidebar configuration files.

#### The `_category_.json` File

Inside a subfolder, you can add a file named `_category_.json` to configure how that folder appears in the sidebar. This file defines properties for the category. Here’s an example from the query:

```json
{
  "label": "Architecture",
  "position": 3,
  "link": {
    "type": "generated-index"
  }
}
```

- **`label`**: The name displayed for the category in the sidebar (e.g., “Architecture”).
- **`position`**: The order of this category in the sidebar (e.g., 3 means it’s the third item).
- **`link`**: Defines what happens when the category is clicked. The value `"type": "generated-index"` tells Docusaurus to create an automatically generated index page for this category, listing all documents inside the folder (e.g., `overview.md` and `components.md`).

This file gives you fine-grained control over the sidebar for that specific folder.

### 4. Step-by-Step Process for Creating a Document (Beginner-Friendly)

If you’re new to Docusaurus, follow these steps to create your first document:

1. **Set Up Docusaurus**:

   - Install Docusaurus by running this command in your terminal:

     ```bash
     npx create-docusaurus@latest my-site classic
     ```

   - This creates a new Docusaurus site in the `my-site` folder using the classic template.
   - Navigate to your project folder:

     ```bash
     cd my-site
     ```

2. **Go to the Docs Folder**:

   - Open the `docs/` folder in your project directory (e.g., `my-site/docs/`).

3. **Create a Markdown File**:

   - Create a new file, e.g., `my-doc.md`, using a text editor.

4. **Add Front Matter (Optional)**:

   - At the top of the file, add metadata like this:

     ```yaml
     ---
     id: my-doc
     title: My Document
     ---
     ```

5. **Write Your Content**:

   - Below the front matter, write your documentation using Markdown. For example:

     ```markdown
     # My Document

     Welcome to my first Docusaurus document!

     ## Features

     - Easy to use
     - Highly customizable
     ```

6. **Organize with Folders (Optional)**:

   - To group related documents, create a subfolder (e.g., `docs/features/`) and move or create files inside it (e.g., `features/my-doc.md`).

7. **Configure the Sidebar (Optional)**:

   - For automatic sidebar generation, Docusaurus will use your folder structure.
   - To customize a category, add a `_category_.json` file in the subfolder. For example, in `docs/features/`:

     ```json
     {
       "label": "Features",
       "position": 2,
       "link": {
         "type": "generated-index"
       }
     }
     ```

   - Alternatively, edit `sidebars.js` in the root directory for manual sidebar configuration.

8. **Preview Your Site**:
   - Start the development server by running:

     ```bash
     npm start
     ```

     or

     ```bash
     yarn start
     ```

   - Open your browser and go to `http://localhost:3000` to see your site.
   - Check that your new document appears and the sidebar reflects your structure.

### 5. Example `.md` File

Here’s a complete example of a Markdown file you might create:

```markdown
---
id: architecture-overview
title: Architecture Overview
slug: /architecture
tags:
  - architecture
  - overview
---

# Architecture Overview

This document provides an overview of the system's architecture.

## Components

- **Frontend**: Built with React.
- **Backend**: Powered by Node.js.

## Design Principles

- Modularity
- Scalability
```

- The front matter sets the ID, title, custom URL, and tags.
- The content uses Markdown for structure and readability.

### 6. Additional Resources

For more details on creating and customizing documents in Docusaurus, visit the official documentation:

- [https://docusaurus.io/docs/create-doc](https://docusaurus.io/docs/create-doc)

This guide covers the essentials, but Docusaurus offers advanced features like versioning and multi-language support. As you grow comfortable, explore these to enhance your documentation site.
