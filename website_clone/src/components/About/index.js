import React from "react";
import SectionContainer from "../sectionContainer";
import Translate from "@docusaurus/Translate";
import "./styles.scss";

export default function About() {
  return (
    <SectionContainer className="aboutContainer">
      <div className={"row"}>
        <div className={"profile"}>
          <img className={"portrait"} src="img/Kmesh-icon.png"></img>
          <div className={"portraitTitle"}>
            <h3 className={"name"}>Kmesh</h3>
            <h3 className={"jobTitle"}>
              <Translate>
                Sidecarless Service Mesh Based on Programmable Kernel
              </Translate>
            </h3>
          </div>
        </div>
        <div className={"description"}>
          <p>
            <Translate>
              Kmesh is a high-performance service grid data plane software
              implemented based on the ebpf and programmable kernel. It adopts
              the sidecarless architecture and does not need to deploy proxy
              components on the data plane. It implements the service governance
              function and improves the forwarding performance of service
              access.
            </Translate>
          </p>
          <p>
            <Translate>
              At present, the latency and noise floor overhead of the data plane
              of the service grid has become a key problem in the development of
              the service grid technology, and the data plane technologies are
              diverse. We are committed to providing customers with a lighter
              and more efficient service governance capability to meet
              customers' requirements for security, agility, and efficiency.
            </Translate>
          </p>
        </div>
      </div>
    </SectionContainer>
  );
}
