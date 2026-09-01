import { useEffect, useState, type KeyboardEvent, type PropsWithChildren } from "react";
import { NavLink, useLocation } from "react-router";
import { Button, StatusBadge } from "../design-system";
import { RouteLifecycle } from "../routing";
import { SHELL_NAVIGATION_ITEMS } from "./navigation";

export interface AppShellProps extends PropsWithChildren {
  readonly authenticationLabel: string;
  readonly connectivityLabel: string;
}

interface NavigationRenderState {
  readonly isActive: boolean;
  readonly isPending: boolean;
}

interface NavigationListProps {
  readonly onNavigate?: () => void;
}

function NavigationList({ onNavigate }: NavigationListProps) {
  return (
    <ul className="product-navigation__list">
      {SHELL_NAVIGATION_ITEMS.map((item) => (
        <li key={item.id}>
          <NavLink
            className={({ isActive, isPending }: NavigationRenderState) => [
              "product-navigation__item",
              isActive ? "is-current" : "",
              isPending ? "is-pending" : "",
            ].filter(Boolean).join(" ")}
            end={item.path === "/"}
            onClick={onNavigate}
            to={item.path}
          >
            {({ isActive }: NavigationRenderState) => (
              <>
                <span>{item.label}</span>
                <span aria-hidden="true" className="product-navigation__state">
                  {isActive ? "Current" : item.stateLabel}
                </span>
              </>
            )}
          </NavLink>
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
  const location = useLocation();
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);

  useEffect(() => {
    setMobileNavigationOpen(false);
  }, [location.pathname]);

  function closeMobileNavigation({ restoreFocus = false } = {}) {
    setMobileNavigationOpen(false);
    if (restoreFocus) {
      document.getElementById("mobile-navigation-toggle")?.focus();
    }
  }

  return (
    <>
      <RouteLifecycle />
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <div className="product-shell">
        <header className="product-header">
          <NavLink className="product-brand" end to="/" aria-label="Engineer4Me home">
            <span className="product-brand__mark" aria-hidden="true">E4M</span>
            <span>
              <strong>Engineer4Me</strong>
              <small>Evidence-led engineering workspace</small>
            </span>
          </NavLink>
          <div className="product-header__status" aria-label="Application status">
            <StatusBadge tone="information">Connectivity: {connectivityLabel}</StatusBadge>
            <StatusBadge tone="warning">Authentication: {authenticationLabel}</StatusBadge>
          </div>
          <Button
            aria-controls="mobile-product-navigation"
            aria-expanded={mobileNavigationOpen}
            aria-label={mobileNavigationOpen ? "Close navigation" : "Open navigation"}
            className="mobile-navigation-toggle"
            id="mobile-navigation-toggle"
            onClick={() => setMobileNavigationOpen((open) => !open)}
            variant="quiet"
          >
            <span aria-hidden="true">{mobileNavigationOpen ? "Close" : "Menu"}</span>
          </Button>
        </header>

        <div className="product-shell__body">
          <aside className="desktop-navigation" aria-label="Product navigation and workspace context">
            <nav aria-label="Desktop product navigation">
              <NavigationList />
            </nav>
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
            tabIndex={-1}
            onKeyDown={(event: KeyboardEvent<HTMLElement>) => {
              if (event.key === "Escape") {
                closeMobileNavigation({ restoreFocus: true });
              }
            }}
          >
            <NavigationList onNavigate={() => closeMobileNavigation()} />
          </nav>

          <main className="product-main" id="main-content" tabIndex={-1}>
            {children}
          </main>
        </div>

        <footer className="product-footer">
          <span>Engineer4Me Phase 9 controlled browser product</span>
          <span>Voice remains deferred to Phase 10</span>
        </footer>
      </div>
    </>
  );
}
