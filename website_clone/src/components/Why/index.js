import React from "react";
import SectionContainer from "../sectionContainer";
import Translate from "@docusaurus/Translate";
import "./index.scss";

const reasons = [
  {
    title: <Translate>Smooth compatibility</Translate>,
    content: (
      <>
        <Translate>Application-transparent Traffic Management.</Translate>
        <br />
        <Translate>
          Automatic Integration with Istio and other software
        </Translate>
      </>
    ),
  },
  {
    title: <Translate>High performance</Translate>,
    content: (
      <>
        <Translate>Forwarding latency 60%↓</Translate>
        <br />
        <Translate>Service startup performance 40%↑</Translate>
      </>
    ),
  },
  {
    title: <Translate>Low overhead</Translate>,
    content: (
      <>
        <Translate>ServiceMesh data plane overhead 70%↓</Translate>
      </>
    ),
  },
  {
    title: <Translate>Security Isolation</Translate>,
    content: (
      <>
        <Translate>eBPF Secure Traffic Orchestration</Translate>
        <br />
        <Translate>Cgroup-level Orchestration Isolation</Translate>
      </>
    ),
  },
  {
    title: <Translate>Full Stack Visualization*</Translate>,
    content: (
      <>
        <Translate>E2E observation*</Translate>
        <br />
        <Translate>
          Integration with Mainstream Observability Platforms*
        </Translate>
      </>
    ),
  },
  {
    title: <Translate>Open Ecosystem</Translate>,
    content: <Translate>Support for XDS Protocol Standards</Translate>,
  },
];

export default function Why() {
  return (
    <SectionContainer className="whyContainer">
      <h1>
        <Translate>Why Kmesh</Translate>
      </h1>
      <div className="reasonBoxContainer">
        {reasons.map((item, index) => (
          <div key={index} className="reasonBox">
            <p className="reasonTitle">{item.title}</p>
            <div className="reasonContent">{item.content}</div>
          </div>
        ))}
      </div>
    </SectionContainer>
  );
}
