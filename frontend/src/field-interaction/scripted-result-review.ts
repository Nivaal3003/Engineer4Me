import { beginTranscriptRevisionReview } from "./transcript-revision-review";
import type { TranscriptRevisionReview } from "./transcript-revision-review";
import { assertIssuedScriptedProcessingController } from "./scripted-processing-controller";
import type { ScriptedProcessingController, ScriptedResultTicket } from "./scripted-processing-controller";
/** Explicitly opens a fresh DRAFT. No prior preview approval is transferred to result text.
 * The result ticket is one-use; failure to open a new review does not resend a job.
 */
export function admitScriptedResultForFreshReview(controller: ScriptedProcessingController,
  result: ScriptedResultTicket, newTranscriptId: string, tick: number): TranscriptRevisionReview {
  assertIssuedScriptedProcessingController(controller);
  const envelope = controller.takeForFreshReview(result, newTranscriptId, tick);
  return beginTranscriptRevisionReview(envelope);
}
