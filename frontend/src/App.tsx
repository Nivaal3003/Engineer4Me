import { readAuthenticationConfiguration } from "./auth/config";

function App() {
  const authentication = readAuthenticationConfiguration();

  return (
    <main className="app-shell">
      <section className="status-card" aria-labelledby="engineer4me-heading">
        <p className="eyebrow">Engineer4Me</p>
        <h1 id="engineer4me-heading">Frontend security bootstrap</h1>
        <p>
          The frontend source is present, but interactive authentication remains
          deliberately inactive until its configuration and browser journey are
          reviewed in later controlled steps.
        </p>

        <dl className="status-grid">
          <div>
            <dt>Authentication activation</dt>
            <dd>Blocked</dd>
          </div>
          <div>
            <dt>Configuration readiness</dt>
            <dd>{authentication.ready ? "Ready for review" : "Incomplete"}</dd>
          </div>
        </dl>

        {!authentication.ready ? (
          <div className="notice" role="status">
            <strong>Missing public configuration</strong>
            <ul>
              {authentication.missing.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="notice" role="status">
            Public Entra configuration is present. No sign-in request is started
            by this bootstrap.
          </p>
        )}
      </section>
    </main>
  );
}

export default App;
