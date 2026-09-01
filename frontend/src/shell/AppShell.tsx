import { useState, type PropsWithChildren } from "react";
import { Button, StatusBadge } from "../design-system";
import { SHELL_NAVIGATION_ITEMS } from "./navigation";

export interface AppShellProps extends PropsWithChildren {
  readonly authenticationLabel: string;
  readonly connectivityLabel: string;
}

function NavigationList() {
  return (
    <ul className="product-navigation__list">
      {SHELL_NAVIGATION_ITEMS.map((item) => (
        <li key={item.id}>
          {item.inPageTarget ? (
            <a aria-current="page" className="product-navigation__item is-current" href={item.inPageTarget}>
              <span>{item.label}</span>
              <span className="product-navigation__state">Current</span>
            </a>
          ) : (
            <div className="product-navigation__item" data-state={item.state}>
              <span>{item.label}</span>
              <span className="product-navigation__state">
                {item.state === "controlled" ? "Controlled" : "Planned"}
              </span>
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

export function AppShell({
  authenticationLabel,
  connectivityLabel,
  children,
}: AppShellProps) {
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <div className="product-shell">
        <header className="product-header">
          <a className="product-brand" href="#main-content" aria-label="Engineer4Me home">
            <span className="product-brand__mark" aria-hidden="true">E4M</span>
            <span>
              <strong>Engineer4Me</strong>
              <small>Evidence-led engineering workspace</small>
            </span>
          </a>
          <div className="product-header__status" aria-label="Application status">
            <StatusBadge tone="information">Connectivity: {connectivityLabel}</StatusBadge>
            <StatusBadge tone="warning">Authentication: {authenticationLabel}</StatusBadge>
          </div>
          <Button
            aria-controls="mobile-product-navigation"
            aria-expanded={mobileNavigationOpen}
            aria-label={mobileNavigationOpen ? "Close navigation" : "Open navigation"}
            className="mobile-navigation-toggle"
            onClick={() => setMobileNavigationOpen((open) => !open)}
            variant="quiet"
          >
            <span aria-hidden="true">{mobileNavigationOpen ? "Close" : "Menu"}</span>
          </Button>
        </header>

        <div className="product-shell__body">
          <aside className="desktop-navigation" aria-label="Product navigation">
            <NavigationList />
            <div className="context-card" aria-label="Workspace context">
              <span className="data-label">Organisation</span>
              <strong>Not connected</strong>
              <span className="data-label">Project</span>
              <strong>No project selected</strong>
              <p>Context selection remains unavailable until controlled API and access milestones pass.</p>
            </div>
          </aside>

          <nav
            aria-label="Mobile product navigation"
            className="mobile-navigation"
            hidden={!mobileNavigationOpen}
            id="mobile-product-navigation"
          >
            <NavigationList />
          </nav>

          <main className="product-main" id="main-content" tabIndex={-1}>
            {children}
          </main>
        </div>

        <footer className="product-footer">
          <span>Engineer4Me Phase 9 controlled product shell</span>
          <span>Voice remains deferred to Phase 10</span>
        </footer>
      </div>
    </>
  );
}
