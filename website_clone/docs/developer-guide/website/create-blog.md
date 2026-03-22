---
title: Create a Blog
sidebar_position: 3
---

## Creating a Blog in Docusaurus: A Comprehensive Guide

Docusaurus is a powerful static site generator that includes a built-in blog feature, making it easy to create and share blog posts. This guide will explain how to set up a blog, write posts, configure options, and maintain your content—all in a way that's approachable for beginners.

### 1. What Is the Blog Feature in Docusaurus?

The blog feature in Docusaurus allows you to:

- Write blog posts as Markdown files.
- Automatically generate a blog index page listing all your posts.
- Create individual pages for each blog post.
- Customize how your blog looks and behaves.

It’s perfect for sharing project updates, tutorials, or any time-based content, with minimal setup required.

### 2. Blog Folder Structure

In a Docusaurus project, blog posts are stored in the `blog/` directory. Each post is a separate Markdown file, and the file name typically includes the publication date and a slug (a URL-friendly title). Here’s an example structure:

```text
blog/
├── 2023-10-05-my-first-post.md
└── 2023-10-06-another-post.md
```

- **Date**: The `YYYY-MM-DD` part (e.g., `2023-10-05`) sets the post’s publication date and order.
- **Slug**: The part after the date (e.g., `my-first-post`) becomes part of the URL (e.g., `/blog/my-first-post`).

You can keep all posts in the `blog/` directory or use subfolders for organization (though a flat structure works fine for most cases).

### 3. Writing Blog Posts: Front Matter

Every blog post starts with a **front matter** section—a YAML block at the top of the file, enclosed in triple dashes (`---`). This section contains metadata about the post. Here’s an example:

```yaml
---
title: My First Blog Post
date: 2023-10-05
author: John Doe
tags: ["example", "blog"]
---
```

Key fields include:

- **`title`**: The post’s title, shown on the post page and blog index.
- **`date`**: The publication date (must match the file name’s date).
- **`author`**: The author’s name (optional).
- **`tags`**: A list of tags for categorization (optional).

The front matter is essential for Docusaurus to recognize and display your post correctly.

### 4. Writing Blog Post Content

After the front matter, write your post’s content using Markdown. Docusaurus supports standard Markdown syntax—headings, lists, links, images, and more. Here’s an example:

```markdown
# My First Blog Post

Welcome to my blog!

## Why I Started This Blog

I’m excited to share my experiences. Here’s why:

- To document my progress
- To connect with others
- To learn from feedback

## What’s Next?

Look out for posts on:

1. Project setup tips
2. Coding best practices
3. Fun experiments
```

Docusaurus also supports MDX, which lets you add React components to your posts for interactive elements (though this is optional for beginners).

### 5. Configuring Your Blog

You can customize your blog by editing the `docusaurus.config.js` file in your project’s root directory. The blog settings are typically defined in the `presets` section. Here’s an example:

```javascript
module.exports = {
  // ...
  presets: [
    [
      "@docusaurus/preset-classic",
      {
        blog: {
          path: "blog", // Directory for blog posts
          routeBasePath: "blog", // URL path for the blog
          blogTitle: "My Blog", // Blog page title
          blogDescription: "Thoughts and updates on my project", // Blog description
          postsPerPage: 10, // Posts per index page
          showReadingTime: true, // Show reading time for posts
        },
      },
    ],
  ],
};
```

Key options:

- **`path`**: Where your blog posts are stored (default: `blog`).
- **`routeBasePath`**: The URL path for your blog (e.g., `/blog`).
- **`blogTitle`**: The title shown on the blog index.
- **`blogDescription`**: A short description for SEO and feeds.
- **`postsPerPage`**: How many posts appear on each index page.
- **`showReadingTime`**: Displays estimated reading time per post.

Check the [Docusaurus blog documentation](https://docusaurus.io/docs/blog) for more options.

### 6. Adding the Blog to Your Site Navigation

To help users find your blog, add a link to it in the navigation bar or footer via `docusaurus.config.js`.

#### Navigation Bar Example

```javascript
module.exports = {
  // ...
  themeConfig: {
    navbar: {
      items: [
        {
          to: "/blog",
          label: "Blog",
          position: "left",
        },
      ],
    },
  },
};
```

#### Footer Example

```javascript
module.exports = {
  // ...
  themeConfig: {
    footer: {
      links: [
        {
          title: "Links",
          items: [
            {
              label: "Blog",
              to: "/blog",
            },
          ],
        },
      ],
    },
  },
};
```

This makes your blog accessible from anywhere on your site.

### 7. Previewing Your Blog Locally

To see your blog in action, run the development server:

```bash
npm start
```

or

```bash
yarn start
```

Open `http://localhost:3000/blog` in your browser to view the blog index. Click any post to see its individual page.

### 8. Best Practices for Managing Your Blog

As your blog grows, keep it organized with these tips:

- **File Naming**: Stick to a consistent format like `YYYY-MM-DD-title.md` for chronological ordering.
- **Tags**: Use tags in the front matter to group related posts. Docusaurus creates tag pages (e.g., `/blog/tags/example`) automatically.
- **Content Structure**: Keep posts focused and use headings for readability.
- **Updates**: Regularly check front matter (e.g., dates, tags) to ensure accuracy.

### 9. Example Blog Post

Here’s a full example of a blog post file:

```markdown
---
title: My First Blog Post
date: 2023-10-05
author: John Doe
tags: ["example", "blog"]
---

# My First Blog Post

Hi everyone!

## Why I’m Here

I started this blog to:

- Share my project journey
- Help others learn
- Get community input

## Coming Soon

Next, I’ll write about:

1. Setting up tools
2. Writing clean code
3. Cool ideas to try

Thanks for reading!
```

This file includes front matter and Markdown content, ready to be processed by Docusaurus.

### 10. Next Steps and Resources

You now have a working blog in Docusaurus! To take it further, explore:

- Adding an RSS feed for subscribers.
- Customizing the blog’s design with CSS.
- Using MDX for advanced features.

For more details, visit the [official Docusaurus blog documentation](https://docusaurus.io/docs/blog).
