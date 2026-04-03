// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking

import { themes as prismThemes } from "prism-react-renderer";

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "Kmesh",
  favicon: "img/favicons/favicon.ico",

  // Set the production url of your site here
  url: "https://kmesh.net",

  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: "/",

  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",

  i18n: {
    defaultLocale: "en",
    locales: ["en", "zh"],
    localeConfigs: {
      en: {
        htmlLang: "en-GB",
        label: "English",
      },
      zh: {
        label: "简体中文",
      },
    },
  },

  presets: [
    [
      "classic",
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: "./sidebars.js",
          editUrl: "https://github.com/kmesh-net/website/blob/main",
          showLastUpdateAuthor: true,
          showLastUpdateTime: true,
        },
        gtag: {
          trackingID: "G-854W8PEZ1Z",
          anonymizeIP: true,
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ["rss", "atom"],
            xslt: true,
          },
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: "https://github.com/kmesh-net/website/blob/main",
          // Useful options to enforce blogging best practices
          onInlineTags: "warn",
          onInlineAuthors: "warn",
          onUntruncatedBlogPosts: "warn",
        },
        theme: {
          customCss: "./src/css/custom.css",
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      docs: {
        sidebar: {
          hideable: true,
          autoCollapseCategories: true,
        },
      },
      navbar: {
        title: "Kmesh",
        logo: {
          alt: "Kmesh",
          src: "img/favicons/favicon.ico",
        },
        items: [
          {
            type: "docSidebar",
            sidebarId: "tutorialSidebar",
            position: "left",
            label: "Documentation",
          },
          { to: "/blog", label: "Blog", position: "left" },
          {
            href: "https://github.com/kmesh-net/kmesh/releases",
            label: "Downloads",
            position: "left",
          },
          {
            href: "https://github.com/kmesh-net/kmesh",
            position: "right",
            className: "header-github-link header-icon",
          },
          {
            href: "https://x.com/Kmesh_net",
            position: "right",
            className: "header-x-link header-icon",
          },
          {
            href: "https://www.youtube.com/@Kmesh-traffic",
            position: "right",
            className: "header-youtube-link header-icon",
          },
          {
            to: "https://app.slack.com/client/T08PSQ7BQ/C06BU2GB8NL",
            position: "right",
            className: "header-slack-link header-icon",
          },
          {
            type: "localeDropdown",
            position: "right",
          },
        ],
      },
      footer: {
        style: "dark",
        copyright: `Copyright © Kmesh a Series of LF Projects, LLC<br>For website terms of use, trademark policy and other project policies please see <a href="https://lfprojects.org/policies/">lfprojects.org/policies/</a>.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ["bash"],
      },

      zoom: {
        selector: ".markdown img",
        options: {
          margin: 24,
          background: "#BADA55",
          scrollOffset: 0,
          container: "#zoom-container",
          template: "#zoom-template",
        },
      },
    }),

  plugins: [
    [require.resolve("./src/plugins/blogGlobalData/index.js"), {}],
    "docusaurus-plugin-sass",
    "plugin-image-zoom",
    [
      "docusaurus-lunr-search",
      {
        languages: ["en",'zh'],
        indexDocs: true,
        indexBlog: true,
        indexPages: false,
      }
    ],
  ],
};

export default config;
