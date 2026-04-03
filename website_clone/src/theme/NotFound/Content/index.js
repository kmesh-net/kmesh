import React from "react";
import Link from "@docusaurus/Link";
import styles from "./styles.module.css"; // we will create this next

export default function NotFoundContent({ className }) {
  return (
    <main className={className}>
      <div className={styles.pageWrapper}>
        <div className={styles.notFoundContainer}>
          <div className={styles.content}>
            <h1 className={styles.title}>Page Not Found</h1>
            <p className={styles.subtitle}>
              The requested resource could not be located on this server.
            </p>

            <div className={styles.messageBox}>
              <div className={styles.infoIcon}>
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"
                    fill="currentColor"
                  />
                </svg>
              </div>
              <div>
                <p className={styles.message}>
                  Chinese documentation is currently unavailable.
                </p>
                <p className={styles.message}>
                  Please refer to our{" "}
                  <Link to="/docs/welcome" className={styles.link}>
                    English documentation
                  </Link>{" "}
                  for comprehensive project information.
                </p>
              </div>
            </div>

            <div className={styles.actions}>
              <Link to="/" className={styles.primaryButton}>
                <svg
                  width="20"
                  height="20"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"
                    fill="currentColor"
                  />
                </svg>
                Return Home
              </Link>
              <Link to="/docs/welcome" className={styles.secondaryButton}>
                <svg
                  width="20"
                  height="20"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"
                    fill="currentColor"
                  />
                </svg>
                View Documentation
              </Link>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
