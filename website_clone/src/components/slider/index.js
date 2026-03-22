import React from "react";
import clsx from "clsx";
import Slider from "react-slick";
import Translate from "@docusaurus/Translate";
import { useHistory } from "@docusaurus/router";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import "./index.scss";

const sliderItems = [
  {
    title: <Translate>Quick start to Kmesh</Translate>,
    subTitle: <Translate>High-performance service mesh dataplane</Translate>,
    gitRepoUrl: "https://github.com/kmesh-net/kmesh.git",
    backgroundImage: "img/headers/star.png",
    opacity: 0.4,
    align: "center",
  },
  {
    title: (
      <Translate>
        The forwarding delay of the service mesh is reduced by 5x
      </Translate>
    ),
    subTitle: (
      <a
        href="https://kmesh.net/docs/welcome"
        style={{ color: 'inherit', textDecoration: 'underline' }}
      >
        <Translate>Click here for more Details</Translate>
      </a>
    ),
    backgroundImage: "img/headers/bubbles-wide.jpg",
    opacity: 0.5,
    align: "center",
  },
];

const SlideItem = (props) => {
  const {
    title,
    subTitle,
    button,
    backgroundImage,
    gitRepoUrl,
    align = "center",
    opacity = 0.5,
  } = props;

  const history = useHistory();

  return (
    <div
      className={clsx("slick-item", align)}
      style={{
        backgroundImage: `linear-gradient(rgba(0, 0, 0, ${opacity}), rgba(0, 0, 0, ${opacity})),url(${backgroundImage})`,
      }}
    >
      <div className={clsx("title")}>
        <div className={clsx("main-title")}>{title}</div>
        <div className={clsx("sub-title")}>{subTitle}</div>
      </div>
      {gitRepoUrl && (
        <span style={{ marginTop: 10 }}>
          <iframe
            src="https://ghbtns.com/github-btn.html?user=kmesh-net&amp;repo=kmesh&amp;type=star&amp;count=true&amp;size=large"
            width={160}
            height={30}
            title="GitHub Stars"
          />
        </span>
      )}
      {button && (
        <div className={clsx("button")}>
          <a onClick={() => history.push(button.url)}>{button.text}</a>
        </div>
      )}
    </div>
  );
};

export const HomeSlider = () => {
  const settings = {
    dots: true,
    infinite: true,
    speed: 500,
    slidesToShow: 1,
    slidesToScroll: 1,
  };

  return (
    <div className={"slider-container"}>
      <Slider {...settings}>
        {sliderItems.map((i, index) => (
          <SlideItem key={index} {...i} />
        ))}
      </Slider>
    </div>
  );
};
