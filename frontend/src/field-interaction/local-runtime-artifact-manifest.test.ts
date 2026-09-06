import { describe, it, expect } from "vitest";
import { requireIssuedLocalArtifactManifest, assessmentDigest } from "./local-runtime-artifact-manifest";
import { createLocalArtifactManifest, LOCAL_ARTIFACT_ROLES } from "./local-runtime-artifact-manifest";
const D = "ab".repeat(32);
function manifestInput() { return {manifestRef:"assessment-1", engineCommit:"ab".repeat(20), modelRef:"base.en-candidate", platformRef:"cpu-reference-unqualified",
  artifacts: LOCAL_ARTIFACT_ROLES.map((role) => ({role, artifactRef:role+"-artifact", revision:"review-1", sha256:D, bytes:1024}))}; }
describe("local artifact declaration manifest",()=>{
 it("accepts six roles without verifying their bytes",()=>{const m=createLocalArtifactManifest(manifestInput());expect(m.artifacts).toHaveLength(6);expect(m.contentVerified).toBe(false);expect(m.executionAuthorized).toBe(false);});
 it("rejects missing roles",()=>{const i=manifestInput();i.artifacts.pop();expect(()=>createLocalArtifactManifest(i)).toThrow(/inventory/i);});
 it("rejects duplicate roles",()=>{const i=manifestInput();i.artifacts[1]={...i.artifacts[1]!,role:"engine_source"};expect(()=>createLocalArtifactManifest(i)).toThrow(/inventory/i);});
 it("rejects repeated artifact references",()=>{const i=manifestInput();i.artifacts[1]={...i.artifacts[1]!,artifactRef:i.artifacts[0]!.artifactRef};expect(()=>createLocalArtifactManifest(i)).toThrow(/duplicate/i);});
 it("rejects moving revision aliases",()=>{const i=manifestInput();i.artifacts[0]={...i.artifacts[0]!,revision:"latest"};expect(()=>createLocalArtifactManifest(i)).toThrow(/moving/i);});
 it("rejects path, URL and shell-like references",()=>{for(const manifestRef of ["../escape","https://x.invalid","a;b","C:\\model"]){expect(()=>createLocalArtifactManifest({...manifestInput(),manifestRef})).toThrow(/reference/i);}});
 it("requires full engine identity",()=>{expect(()=>createLocalArtifactManifest({...manifestInput(),engineCommit:"371b5a7"})).toThrow(/commit/i);});
 it("rejects non-digests and constant placeholders",()=>{for(const v of ["f".repeat(64),"bad",D.toUpperCase()])expect(()=>assessmentDigest(v)).toThrow(/digest/i);});
 it("rejects non-finite, zero and excessive byte counts",()=>{for(const bytes of [0,NaN,Infinity,4_294_967_297]){const i=manifestInput();i.artifacts[0]={...i.artifacts[0]!,bytes};expect(()=>createLocalArtifactManifest(i)).toThrow(/bound/i);}});
 it("takes a frozen defensive copy",()=>{const i=manifestInput();const m=createLocalArtifactManifest(i);i.artifacts[0]!.bytes=12;expect(m.artifacts[0]!.bytes).toBe(1024);expect(Object.isFrozen(m.artifacts[0])).toBe(true);});
 it("rejects fabricated copies of issued manifests",()=>{const m=createLocalArtifactManifest(manifestInput());expect(()=>requireIssuedLocalArtifactManifest({...m})).toThrow(/issued/i);expect(()=>requireIssuedLocalArtifactManifest(m)).not.toThrow();});
});
