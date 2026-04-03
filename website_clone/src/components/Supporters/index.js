import React from "react";
import SectionContainer from "../sectionContainer";
import Translate from "@docusaurus/Translate";
import Link from "@docusaurus/Link";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import "./index.scss";

const supportList = [
  {
    name: "HuaweiCloud",
    img_src: "img/supporters/huawei.png",
    external_link: "https://www.huaweicloud.com/",
  },

  {
    name: "OpenEuler",
    img_src: "img/supporters/openEuler.svg",
    external_link: "https://www.openeuler.org/",
  },
];

export default function Supporters() {
  const { i18n } = useDocusaurusContext();
  return (
    <SectionContainer className={"supporterContainer"}>
      <div className={"supporters"}>
        <h1>
            <span className={"joins"}>
              <Translate>Supporters </Translate>
            </span>         
        </h1>
      </div>
      <div className={"supporterBoxContainer"}>
        {supportList.map((item, index) => (
          <div key={index} className="supporterBox">
            <div className="imgContainer">
              <Link to={item.external_link}></Link>
              <Link to={item.external_link}>
                <img alt={item.name} src={item.img_src} />
              </Link>
            </div>
          </div>
        ))}
      </div>
    </SectionContainer>
  );
}
