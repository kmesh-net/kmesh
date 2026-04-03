import React from 'react';
import { useColorMode } from '@docusaurus/theme-common';
import styles from './styles.module.css';

export default function CNCFInfo() {
  const { colorMode } = useColorMode();

  return (
    <div className={styles.cncfContainer}>
      <div className={styles.cncfContent}>
      <p className={styles.cncfText}>
        Kmesh is a{' '}
        <a 
          href="https://cncf.io" 
          target="_blank" 
          rel="noopener noreferrer"
          className={styles.cncfLink}
        >
          CNCF (Cloud Native Computing Foundation)
        </a>{' '}
        Sandbox project.
        </p>
        <div className={styles.cncfLogo}>
          <img 
            src={colorMode === 'dark' ? "/img/cncf-dark.svg" : "/img/cncf-light.svg"} 
            alt="CNCF Logo" 
            className={styles.logoImage}
            key={colorMode}
          />
        </div>
      </div>
    </div>
  );
}