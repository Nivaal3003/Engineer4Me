/** Read-only browser permission capability detection. No permission API is invoked. */
export type BrowserEmbeddingContext =
  | "top_level"
  | "embedded_or_cross_origin"
  | "not_available"
  | "unknown";

export interface ReadOnlyPermissionCapabilitySnapshot {
  readonly detectionMode: "read_only_property_presence";
  readonly globalObjectPresent: boolean;
  readonly secureContext: boolean | null;
  readonly embeddingContext: BrowserEmbeddingContext;
  readonly navigatorPresent: boolean;
  readonly mediaDevicesObjectPresent: boolean;
  readonly getUserMediaFunctionPresent: boolean;
  readonly permissionsObjectPresent: boolean;
  readonly permissionsQueryFunctionPresent: boolean;
  readonly permissionsPolicyObjectPresent: boolean;
  readonly permissionsPolicyAllowsFeatureFunctionPresent: boolean;
  readonly capabilityDetectionCompleted: true;
  readonly browserPermissionApiCalled: false;
  readonly permissionStatusQueried: false;
  readonly permissionPromptShown: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly liveCaptureStarted: false;
}

type PropertyContainer = object | ((...arguments_: never[]) => unknown);

function asPropertyContainer(value: unknown): PropertyContainer | null {
  if ((typeof value === "object" && value !== null) || typeof value === "function") {
    return value as PropertyContainer;
  }
  return null;
}

function readProperty(container: PropertyContainer | null, key: PropertyKey): unknown {
  if (container === null) return undefined;
  try {
    return Reflect.get(container, key);
  } catch {
    return undefined;
  }
}

function functionPresent(container: PropertyContainer | null, key: PropertyKey): boolean {
  return typeof readProperty(container, key) === "function";
}

function detectEmbeddingContext(root: PropertyContainer | null): BrowserEmbeddingContext {
  if (root === null) return "not_available";
  const windowObject = asPropertyContainer(
    readProperty(root, "window") ?? readProperty(root, "self"),
  );
  if (windowObject === null) return "not_available";
  const topObject = readProperty(root, "top");
  if (topObject === undefined || topObject === null) return "unknown";
  return windowObject === topObject ? "top_level" : "embedded_or_cross_origin";
}

export function detectReadOnlyPermissionCapabilities(
  environment: unknown = globalThis,
): ReadOnlyPermissionCapabilitySnapshot {
  const root = asPropertyContainer(environment);
  const navigatorObject = asPropertyContainer(readProperty(root, "navigator"));
  const mediaDevices = asPropertyContainer(readProperty(navigatorObject, "mediaDevices"));
  const permissions = asPropertyContainer(readProperty(navigatorObject, "permissions"));
  const documentObject = asPropertyContainer(readProperty(root, "document"));
  const policyObject = asPropertyContainer(
    readProperty(documentObject, "permissionsPolicy")
      ?? readProperty(documentObject, "featurePolicy"),
  );
  const secureContextValue = readProperty(root, "isSecureContext");

  return Object.freeze({
    detectionMode: "read_only_property_presence",
    globalObjectPresent: root !== null,
    secureContext: typeof secureContextValue === "boolean" ? secureContextValue : null,
    embeddingContext: detectEmbeddingContext(root),
    navigatorPresent: navigatorObject !== null,
    mediaDevicesObjectPresent: mediaDevices !== null,
    getUserMediaFunctionPresent: functionPresent(mediaDevices, "getUserMedia"),
    permissionsObjectPresent: permissions !== null,
    permissionsQueryFunctionPresent: functionPresent(permissions, "query"),
    permissionsPolicyObjectPresent: policyObject !== null,
    permissionsPolicyAllowsFeatureFunctionPresent: functionPresent(
      policyObject,
      "allowsFeature",
    ),
    capabilityDetectionCompleted: true,
    browserPermissionApiCalled: false,
    permissionStatusQueried: false,
    permissionPromptShown: false,
    mediaDeviceEnumerationPerformed: false,
    liveCaptureStarted: false,
  });
}
