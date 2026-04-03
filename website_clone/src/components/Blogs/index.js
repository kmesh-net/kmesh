import React from "react";
import { usePluginData } from "@docusaurus/useGlobalData";
import SectionContainer from "../sectionContainer";
import { useHistory } from "@docusaurus/router";
import Translate from "@docusaurus/Translate";
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import "./styles.scss";

export default function Blogs() {

    const { i18n: { currentLocale } } = useDocusaurusContext();

    const {
        blogGlobalData: { blogPosts },
    } = usePluginData("blog-global-dataPlugin");

    const history = useHistory();

    return (
        <SectionContainer className="blogPostContainer">
            <div className="row">
                <div className="left">
                    <h1>
                        <Translate>Recent News</Translate>
                    </h1>
                    <a onClick={() => history.push("blog")}>
                        <Translate>View All</Translate>
                    </a>
                </div>
                <div className="right">
                    {blogPosts.slice(0, 3).map((item, index) => (
                        <div key={index} className="viewBlogContainer">
                            <h3
                                onClick={() =>
                                    history.push(item.metadata.permalink)
                                }
                            >
                                {item.metadata.title}
                            </h3>
                            {item.metadata?.frontMatter?.summary && (
                                <p>{item.metadata?.frontMatter.summary}</p>
                            )}
                            <div className="info">
                                <div className="author">
                                    {(item.metadata?.authors || []).map(
                                        (item) => (
                                            <a href={item.url} target="_blank">
                                                {item.name}
                                            </a>
                                        )
                                    )}
                                </div>
                                <div className="update-time">
                                    <Translate>Last updated on</Translate>{" "}
                                    {new Date(
                                        item.metadata.date
                                    ).toLocaleDateString(currentLocale, {
                                        year: "numeric",
                                        month: "long",
                                        day: "numeric",
                                    })}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </SectionContainer>
    );
}
