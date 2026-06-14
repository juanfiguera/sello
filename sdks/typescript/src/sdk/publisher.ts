import { type TransparencyLogEntry } from "../log/types.ts";
import { type SdkSubmissionLog } from "./logs.ts";

export type SubmitMode = "background" | "await";

export type SelloSubmitOptions = {
  mode?: SubmitMode;
  maxPending?: number;
  concurrency?: number;
};

export type PublishJob = {
  envelope: Uint8Array;
  integratedTime: string;
};

export type PublishResult = {
  status: "submitted";
  entry: TransparencyLogEntry;
};

export type DropEvent = {
  envelope: Uint8Array;
  integratedTime: string;
  reason: "queue_full";
};

export type PublisherInput = {
  log: SdkSubmissionLog;
  submit?: SubmitMode | SelloSubmitOptions;
  onSubmitError?: (error: unknown) => void;
  onDrop?: (event: DropEvent) => void;
};

type QueuedJob = PublishJob & {
  resolve: (entry: TransparencyLogEntry | undefined) => void;
  reject: (error: unknown) => void;
};

export class BackgroundReceiptPublisher {
  readonly #log: SdkSubmissionLog;
  readonly #mode: SubmitMode;
  readonly #maxPending: number;
  readonly #concurrency: number;
  readonly #onSubmitError?: (error: unknown) => void;
  readonly #onDrop?: (event: DropEvent) => void;
  readonly #queue: QueuedJob[] = [];
  readonly #inFlight = new Set<Promise<void>>();

  constructor(input: PublisherInput) {
    this.#log = input.log;
    const options = normalizeSubmitOptions(input.submit);
    this.#mode = options.mode;
    this.#maxPending = options.maxPending;
    this.#concurrency = options.concurrency;
    this.#onSubmitError = input.onSubmitError;
    this.#onDrop = input.onDrop;
  }

  get mode(): SubmitMode {
    return this.#mode;
  }

  async publish(job: PublishJob): Promise<TransparencyLogEntry | undefined> {
    if (this.#mode === "await") {
      return await this.#log.append(job.envelope, job.integratedTime);
    }

    if (this.#queue.length + this.#inFlight.size >= this.#maxPending) {
      this.#onDrop?.({
        envelope: new Uint8Array(job.envelope),
        integratedTime: job.integratedTime,
        reason: "queue_full",
      });
      return undefined;
    }

    const promise = new Promise<TransparencyLogEntry | undefined>((resolve, reject) => {
      this.#queue.push({
        envelope: new Uint8Array(job.envelope),
        integratedTime: job.integratedTime,
        resolve,
        reject,
      });
    });
    this.#drain();
    return promise;
  }

  publishBackground(job: PublishJob): void {
    void this.publish(job).catch((error) => {
      this.#onSubmitError?.(error);
    });
  }

  async flush(): Promise<void> {
    while (this.#queue.length > 0 || this.#inFlight.size > 0) {
      await Promise.allSettled([...this.#inFlight]);
    }
  }

  #drain(): void {
    while (this.#inFlight.size < this.#concurrency && this.#queue.length > 0) {
      const job = this.#queue.shift() as QueuedJob;
      const task = this.#submit(job).finally(() => {
        this.#inFlight.delete(task);
        this.#drain();
      });
      this.#inFlight.add(task);
    }
  }

  async #submit(job: QueuedJob): Promise<void> {
    try {
      const entry = await this.#log.append(job.envelope, job.integratedTime);
      job.resolve(entry);
    } catch (error) {
      this.#onSubmitError?.(error);
      job.reject(error);
    }
  }
}

function normalizeSubmitOptions(
  submit: SubmitMode | SelloSubmitOptions | undefined,
): Required<SelloSubmitOptions> {
  const options =
    typeof submit === "string" || submit === undefined ? { mode: submit } : submit;
  const mode = options.mode ?? "background";
  if (mode !== "background" && mode !== "await") {
    throw new TypeError("submit.mode must be background or await");
  }

  const maxPending = options.maxPending ?? 1000;
  if (!Number.isSafeInteger(maxPending) || maxPending < 0) {
    throw new TypeError("submit.maxPending must be a non-negative safe integer");
  }

  const concurrency = options.concurrency ?? 4;
  if (!Number.isSafeInteger(concurrency) || concurrency < 1) {
    throw new TypeError("submit.concurrency must be a positive safe integer");
  }

  return { mode, maxPending, concurrency };
}
