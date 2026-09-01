import { useEffect, useRef } from "react";
import { useLocation } from "react-router";
import { routeDocumentTitle } from "./routes";

export function RouteLifecycle() {
  const location = useLocation();
  const previousPath = useRef(location.pathname);
  const title = routeDocumentTitle(location.pathname);

  useEffect(() => {
    document.title = title;

    if (previousPath.current !== location.pathname) {
      document.getElementById("main-content")?.focus();
      previousPath.current = location.pathname;
    }
  }, [location.pathname, title]);

  return (
    <span aria-atomic="true" aria-live="polite" className="visually-hidden">
      {title}
    </span>
  );
}
