import React from "react";
import "./styles.scss";

export default function SectionContainer({ className = "", children }) {
  return (
    <section className={`${className} sectionContainer`}>
      <div className={"sectionContainerInner"}>{children}</div>
    </section>
  );
}
