export interface InertAudioSampleAcquisitionAdapter {
  readonly sampleAcquisitionOperationAvailable: false;
  readonly sampleAcquisitionStartCallCount: 0;
  readonly sampleReadCallCount: 0;
  readonly audioContextCreationCount: 0;
  readonly mediaRecorderCreationCount: 0;
  readonly audioWorkletCreationCount: 0;
  readonly playbackStartCount: 0;
  readonly recordingStartCount: 0;
  readonly persistenceWriteCount: 0;
  readonly mediaTransmissionCount: 0;
  readonly backendRequestCount: 0;
  readonly externalAiRequestCount: 0;
  readonly speechToTextRequestCount: 0;
  readonly voiceCommandInterpretationCount: 0;
}

export function createInertAudioSampleAcquisitionAdapter(): InertAudioSampleAcquisitionAdapter {
  return Object.freeze({
    sampleAcquisitionOperationAvailable: false,
    sampleAcquisitionStartCallCount: 0,
    sampleReadCallCount: 0,
    audioContextCreationCount: 0,
    mediaRecorderCreationCount: 0,
    audioWorkletCreationCount: 0,
    playbackStartCount: 0,
    recordingStartCount: 0,
    persistenceWriteCount: 0,
    mediaTransmissionCount: 0,
    backendRequestCount: 0,
    externalAiRequestCount: 0,
    speechToTextRequestCount: 0,
    voiceCommandInterpretationCount: 0,
  });
}
